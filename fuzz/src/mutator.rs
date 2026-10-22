//! Custom mutator for MLA archive fuzzing.
//!
//! Parses the input as a valid MLA archive, extracts entries into an
//! `ArchiveModel`, mutates the model, and re-serializes via `ArchiveWriter`
//! to guarantee structural validity. Optionally applies a small corruption
//! pass (byte flips in the body, preserving the header and footer magic).
//!
//! This avoids the problem where raw byte mutation almost always breaks the
//! `MLAFAAAA` magic header, making the fuzzer waste nearly all runs.

use std::collections::HashSet;
use std::io::{Cursor, Read};

use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::entry::EntryName;
use mla::{ArchiveReader, ArchiveWriter};

/// Deterministic PRNG for the mutator (xorshift64).
struct Rng(u64);

impl Rng {
    fn new(seed: u32) -> Self {
        Rng(u64::from(seed).max(1))
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn range(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            (self.next_u64() as usize) % max
        }
    }
}

/// In-memory representation of an MLA archive for mutation.
struct ArchiveModel {
    compress: Option<u32>,
    entries: Vec<EntryModel>,
}

struct EntryModel {
    name: Vec<u8>,
    content: Vec<u8>,
}

const MAX_ENTRIES: usize = 32;
const MAX_CONTENT_LEN: usize = 256;
const MAX_NAME_LEN: usize = 32;
const MAX_MODEL_SIZE: usize = 64 * 1024;
const ENTRY_READ_CAP: u64 = 64 * 1024;
/// Length of the MLA magic headers (MLAFAAAA / EMLAAAAA), in bytes.
const MAGIC_LEN: usize = 8;

/// Parse raw MLA archive bytes into an `ArchiveModel`.
fn parse_archive(data: &[u8]) -> Option<ArchiveModel> {
    let config = ArchiveReaderConfig::without_signature_verification().without_encryption();
    let mut reader = match ArchiveReader::from_config(Cursor::new(data), config) {
        Ok((reader, _)) => reader,
        Err(_) => return None,
    };

    // Collect entry names (clone to release the borrow on reader)
    let names: Vec<EntryName> = match reader.list_entries() {
        Ok(iter) => iter.cloned().collect(),
        Err(_) => return None,
    };

    let mut entries = Vec::new();
    for name in names {
        let name_bytes = name.as_arbitrary_bytes().to_vec();
        match reader.get_entry(name) {
            Ok(Some(entry)) => {
                let mut buf = Vec::new();
                let mut limited = entry.data.take(ENTRY_READ_CAP);
                if limited.read_to_end(&mut buf).is_err() {
                    return None;
                }
                entries.push(EntryModel {
                    name: name_bytes,
                    content: buf,
                });
            }
            Ok(None) => continue,
            Err(_) => return None,
        }
    }

    // Compression level is not preserved from the original archive.
    // toggle_compression can re-enable it with a random level.
    Some(ArchiveModel {
        compress: None,
        entries,
    })
}

/// Serialize an `ArchiveModel` into valid MLA archive bytes.
fn serialize_model(model: &ArchiveModel) -> Option<Vec<u8>> {
    let mut config = match ArchiveWriterConfig::without_encryption_without_signature() {
        Ok(cfg) => cfg,
        Err(_) => return None,
    };
    config = match model.compress {
        Some(level) => match config.with_compression_level(level) {
            Ok(cfg) => cfg,
            Err(_) => return None,
        },
        None => config.without_compression(),
    };

    let mut buf = Vec::new();
    let mut writer = match ArchiveWriter::from_config(&mut buf, config) {
        Ok(w) => w,
        Err(_) => return None,
    };

    let mut seen_names: HashSet<Vec<u8>> = HashSet::new();

    for entry in &model.entries {
        if entry.name.is_empty() {
            continue;
        }
        if !seen_names.insert(entry.name.clone()) {
            continue;
        }
        let entry_name = match EntryName::from_arbitrary_bytes(&entry.name) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let id = match writer.start_entry(entry_name) {
            Ok(id) => id,
            Err(_) => return None,
        };
        if !entry.content.is_empty() {
            let content_len = u64::try_from(entry.content.len()).ok()?;
            if writer
                .append_entry_content(id, content_len, &entry.content[..])
                .is_err()
            {
                return None;
            }
        }
        if writer.end_entry(id).is_err() {
            return None;
        }
    }

    match writer.finalize() {
        Ok(_) => Some(buf),
        Err(_) => None,
    }
}

/// Create a minimal default archive model.
fn default_model() -> ArchiveModel {
    ArchiveModel {
        compress: None,
        entries: vec![EntryModel {
            name: b"a".to_vec(),
            content: b"hi".to_vec(),
        }],
    }
}

/// Generate random bytes of the given length.
fn random_bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut remaining = len;
    while remaining > 0 {
        let v = rng.next_u64().to_le_bytes();
        let take = remaining.min(8);
        out.extend_from_slice(&v[..take]);
        remaining -= take;
    }
    out
}

/// Apply random mutations to the model.
fn mutate_model(model: &mut ArchiveModel, rng: &mut Rng) {
    let num_mutations = rng.range(3) + 1;
    for _ in 0..num_mutations {
        match rng.range(7) {
            0 => add_entry(model, rng),
            1 => remove_entry(model, rng),
            2 => rename_entry(model, rng),
            3 => append_content(model, rng),
            4 => truncate_content(model, rng),
            5 => flip_content_bytes(model, rng),
            6 => toggle_compression(model, rng),
            _ => {}
        }
    }
}

fn model_size(model: &ArchiveModel) -> usize {
    model
        .entries
        .iter()
        .map(|e| e.name.len() + e.content.len())
        .sum()
}

fn add_entry(model: &mut ArchiveModel, rng: &mut Rng) {
    if model.entries.len() >= MAX_ENTRIES || model_size(model) >= MAX_MODEL_SIZE {
        return;
    }
    let name_len = rng.range(MAX_NAME_LEN) + 1;
    let content_len = rng.range(MAX_CONTENT_LEN + 1);
    model.entries.push(EntryModel {
        name: random_bytes(rng, name_len),
        content: random_bytes(rng, content_len),
    });
}

fn remove_entry(model: &mut ArchiveModel, rng: &mut Rng) {
    if model.entries.len() > 1 {
        let idx = rng.range(model.entries.len());
        model.entries.remove(idx);
    }
}

fn rename_entry(model: &mut ArchiveModel, rng: &mut Rng) {
    if model.entries.is_empty() {
        return;
    }
    let idx = rng.range(model.entries.len());
    let name_len = rng.range(MAX_NAME_LEN) + 1;
    model.entries[idx].name = random_bytes(rng, name_len);
}

fn append_content(model: &mut ArchiveModel, rng: &mut Rng) {
    if model.entries.is_empty() {
        return;
    }
    let idx = rng.range(model.entries.len());
    let n = rng.range(64) + 1;
    let extra = random_bytes(rng, n);
    model.entries[idx].content.extend(extra);
}

fn truncate_content(model: &mut ArchiveModel, rng: &mut Rng) {
    if model.entries.is_empty() {
        return;
    }
    let idx = rng.range(model.entries.len());
    let content = &mut model.entries[idx].content;
    if content.is_empty() {
        return;
    }
    let max_remove = content.len().min(32);
    let remove = rng.range(max_remove) + 1;
    let new_len = content.len().saturating_sub(remove);
    content.truncate(new_len);
}

fn flip_content_bytes(model: &mut ArchiveModel, rng: &mut Rng) {
    if model.entries.is_empty() {
        return;
    }
    let idx = rng.range(model.entries.len());
    let content = &mut model.entries[idx].content;
    if content.is_empty() {
        return;
    }
    let num_flips = rng.range(4) + 1;
    for _ in 0..num_flips {
        let pos = rng.range(content.len());
        let bit = 1u8 << (rng.next_u64() % 8) as u8;
        content[pos] ^= bit;
    }
}

fn toggle_compression(model: &mut ArchiveModel, rng: &mut Rng) {
    model.compress = match model.compress {
        None => Some((rng.range(11) + 1) as u32),
        Some(_) => None,
    };
}

/// Public entry point: mutate an MLA archive.
///
/// Serialize `model`, falling back to a fresh default model on panic.
fn serialize_or_default(model: &ArchiveModel) -> Vec<u8> {
    std::panic::catch_unwind(|| serialize_model(model))
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            let m = default_model();
            serialize_model(&m).expect("default model must serialize")
        })
}

/// Parses the input, mutates the model, re-serializes, and optionally
/// applies a corruption pass. Returns valid or near-valid MLA bytes.
pub fn mutate_archive(data: &[u8], max_size: usize, seed: u32) -> Vec<u8> {
    let mut rng = Rng::new(seed);

    // Use catch_unwind to prevent panics in ArchiveReader/ArchiveWriter from
    // killing the fuzzer process. On any panic, fall back to a default model.
    let mut model = std::panic::catch_unwind(|| parse_archive(data))
        .ok()
        .flatten()
        .unwrap_or_else(default_model);
    mutate_model(&mut model, &mut rng);

    let mut out = serialize_or_default(&model);

    // Corruption pass: flip 1-3 bytes in the body, preserving the 8-byte
    // MLAFAAAA header and 8-byte EMLAAAAA footer. Full-byte XOR flips (unlike
    // the single-bit flips in flip_content_bytes) to exercise error paths.
    if out.len() > 16 && rng.range(10) == 0 {
        let start = MAGIC_LEN;
        let end = out.len() - MAGIC_LEN;
        let num_flips = rng.range(3) + 1;
        for _ in 0..num_flips {
            let pos = start + rng.range(end - start);
            out[pos] ^= 0xFF;
        }
    }

    if out.len() > max_size {
        out.truncate(max_size);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify that an archive starts with MLAFAAAA and ends with EMLAAAAA.
    fn has_valid_magic(data: &[u8]) -> bool {
        data.len() >= 16 && &data[..8] == b"MLAFAAAA" && &data[data.len() - 8..] == b"EMLAAAAA"
    }

    // Verify that ArchiveReader can parse the archive without error.
    fn is_parseable(data: &[u8]) -> bool {
        let config = ArchiveReaderConfig::without_signature_verification().without_encryption();
        ArchiveReader::from_config(Cursor::new(data), config).is_ok()
    }

    #[test]
    fn mutate_archive_always_has_valid_magic() {
        for seed in 0..200u32 {
            let out = mutate_archive(&[], 4096, seed);
            assert!(
                has_valid_magic(&out),
                "seed {seed}: bad magic, got {} bytes starting with {:?}",
                out.len(),
                &out[..8.min(out.len())]
            );
        }
    }

    #[test]
    fn mutate_archive_validity_above_80_percent() {
        let n = 500u32;
        let mut valid = 0usize;
        for seed in 0..n {
            let out = mutate_archive(&[], 4096, seed);
            if has_valid_magic(&out) && is_parseable(&out) {
                valid += 1;
            }
        }
        let rate = valid as f64 / n as f64;
        assert!(
            rate > 0.80,
            "validity rate {:.1}% is at or below 80% ({}/{})",
            rate * 100.0,
            valid,
            n
        );
    }

    #[test]
    fn mutate_archive_respects_max_size() {
        for seed in 0..100u32 {
            let out = mutate_archive(&[], 256, seed);
            assert!(
                out.len() <= 256,
                "seed {seed}: output {} bytes exceeds max 256",
                out.len()
            );
        }
    }

    #[test]
    fn mutate_archive_from_valid_archive_preserves_magic() {
        // Build a valid archive, then mutate it
        let original = mutate_archive(&[], 4096, 42);
        assert!(has_valid_magic(&original));
        for seed in 0..100u32 {
            let out = mutate_archive(&original, 4096, seed);
            assert!(
                has_valid_magic(&out),
                "seed {seed}: mutation of valid archive lost magic"
            );
        }
    }
}

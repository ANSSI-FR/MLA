use std::{
    error, fmt,
    fs::{self, File},
    path::PathBuf,
};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use mla::{
    config::ArchiveWriterConfig, crypto::mlakey::MLAPublicKey, entry::EntryName, errors::Error,
    helpers::mla_percent_escape,
};
use std::io::{self, BufReader, BufWriter};

// from http://cgit.git.savannah.gnu.org/cgit/coreutils.git/tree/src/ioblksize.h#n25
const DEFAULT_BUFFER_SIZE: usize = 256 * 1024;
const PATH_ESCAPED_STRING_ALLOWED_BYTES: &[u8; 65] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./\\";

// ----- Error ------

#[derive(Debug)]
enum MlarError {
    /// Wrap a MLA error
    Mla(Error),
    /// Wrap MLA v1 error (`mla_v1` crate)
    MlaV1(mla_v1::errors::Error),
    /// IO Error (not enough data, etc.)
    IO(io::Error),
    InvalidEntryNameToPath,
}

impl fmt::Display for MlarError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{self:?}")
    }
}

impl From<Error> for MlarError {
    fn from(error: Error) -> Self {
        MlarError::Mla(error)
    }
}

impl From<mla_v1::errors::Error> for MlarError {
    fn from(error: mla_v1::errors::Error) -> Self {
        MlarError::MlaV1(error)
    }
}

impl error::Error for MlarError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            MlarError::IO(err) => Some(err),
            MlarError::Mla(err) => Some(err),
            MlarError::MlaV1(err) => Some(err),
            MlarError::InvalidEntryNameToPath => None,
        }
    }
}

fn app() -> Command {
    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("input")
                .help("Input archive path. Any backslashes in entry names will be normalized to forward slashes during upgrade.")
                .long("input")
                .short('i')
                .num_args(1)
                .value_parser(value_parser!(PathBuf))
                .required(true),
        )
        .arg(
            Arg::new("private_keys")
                .long("private_keys")
                .short('k')
                .help("Candidates ED25519 private key paths (DER or PEM format)")
                .num_args(1)
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("output")
                .help("Output file path. Use - for stdout")
                .long("output")
                .short('o')
                .value_parser(value_parser!(PathBuf))
                .required(true),
        )
        .arg(
            Arg::new("public_keys")
                .help("MLA 2 public key paths")
                .long("pubkey")
                .short('p')
                .num_args(1)
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .action(ArgAction::SetTrue)
                .help("Increase verbosity with additional information"),
        )
}

fn writer_from_matches(
    matches: &ArgMatches,
) -> Result<mla::ArchiveWriter<'_, BufWriter<File>>, MlarError> {
    let config = if let Some(public_key_args) = matches.get_many::<PathBuf>("public_keys") {
        let (pub_encryption_keys, _) = public_key_args
            .map(|pub_key_path| {
                let mut key_file = File::open(pub_key_path).map_err(|e| {
                    eprintln!(
                        "[ERROR] Failed to open public key \"{}\": {e}",
                        pub_key_path.display()
                    );
                    MlarError::IO(e)
                })?;
                let key = MLAPublicKey::deserialize_public_key(&mut key_file).map_err(|e| {
                    eprintln!(
                        "[ERROR] Failed to parse public key \"{}\": {e}",
                        pub_key_path.display()
                    );
                    MlarError::Mla(e)
                })?;
                Ok(key.get_public_keys())
            })
            .collect::<Result<(Vec<_>, Vec<_>), MlarError>>()?;

        ArchiveWriterConfig::with_encryption_without_signature(&pub_encryption_keys).map_err(
            |e| {
                eprintln!("[ERROR] Invalid archive config: {e}");
                MlarError::Mla(e.into())
            },
        )?
    } else {
        ArchiveWriterConfig::without_encryption_without_signature().map_err(|e| {
            eprintln!("[ERROR] Invalid archive config: {e}");
            MlarError::Mla(e.into())
        })?
    };

    let out_file_path = matches.get_one::<PathBuf>("output").ok_or_else(|| {
        let msg = "Missing required output file argument";
        MlarError::IO(io::Error::other(format!("[ERROR] {msg}")))
    })?;

    let out_file = File::create(out_file_path).map_err(|e| {
        eprintln!(
            "[ERROR] Failed to create output file \"{}\": {e}",
            out_file_path.display()
        );
        MlarError::IO(e)
    })?;
    let buf_writer = BufWriter::with_capacity(DEFAULT_BUFFER_SIZE, out_file);

    mla::ArchiveWriter::from_config(buf_writer, config).map_err(|e| {
        eprintln!("[ERROR] Failed to create archive writer: {e}");
        MlarError::Mla(e)
    })
}

fn reader_from_matches(
    matches: &ArgMatches,
) -> Result<mla_v1::ArchiveReader<'_, BufReader<File>>, MlarError> {
    let mut config_v1 = mla_v1::config::ArchiveReaderConfig::new();

    if let Some(private_key_args) = matches.get_many::<PathBuf>("private_keys") {
        let mut private_keys = Vec::new();
        for private_key_arg in private_key_args {
            let key_bytes = fs::read(private_key_arg).map_err(|e| {
                eprintln!(
                    "[ERROR] Failed to read private key \"{}\": {e}",
                    private_key_arg.display()
                );
                MlarError::IO(e)
            })?;

            let key =
                curve25519_parser::parse_openssl_25519_privkey(&key_bytes).map_err(|err| {
                    eprintln!(
                        "[ERROR] Failed to parse private key \"{}\": {err}",
                        private_key_arg.display()
                    );
                    MlarError::Mla(Error::InvalidKeyFormat)
                })?;

            private_keys.push(key);
        }
        config_v1.layers_enabled.insert(mla_v1::Layers::ENCRYPT);
        config_v1.add_private_keys(&private_keys);
    }

    let in_file_path = matches.get_one::<PathBuf>("input").ok_or_else(|| {
        let msg = "Missing required input file argument";
        MlarError::IO(io::Error::other(format!("[ERROR] {msg}")))
    })?;

    let in_file = File::open(in_file_path).map_err(|e| {
        eprintln!(
            "[ERROR] Failed to open input file \"{}\": {e}",
            in_file_path.display()
        );
        MlarError::IO(e)
    })?;
    let buf_reader = BufReader::with_capacity(DEFAULT_BUFFER_SIZE, in_file);

    mla_v1::ArchiveReader::from_config(buf_reader, config_v1).map_err(|e| {
        eprintln!("[ERROR] Failed to create archive reader: {e}");
        MlarError::MlaV1(e)
    })
}

fn upgrade(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla_in = reader_from_matches(matches)?;
    let mut mla_out = writer_from_matches(matches)?;

    // Read the file list using metadata
    // v1 archive still uses files, not entries
    let entries: Vec<String> = mla_in
        .list_files()
        .inspect_err(|err| {
            eprintln!("[ERROR] Archive is malformed or unreadable. Try to recover the file. Details: {err}");
        })
        .map_err(Into::<MlarError>::into)?
        .cloned()
        .collect();

    for entry in entries {
        let escaped = mla_percent_escape(entry.as_bytes(), PATH_ESCAPED_STRING_ALLOWED_BYTES);
        // Safe to convert to UTF-8 string because all disallowed bytes are escaped
        let escaped_entry = String::from_utf8(escaped)
            .expect("[ERROR] mla_percent_escape should produce valid UTF-8");

        eprintln!(" adding: {escaped_entry}");

        let entry = match mla_in.get_file(entry.clone()) {
            Err(err) => {
                eprintln!("[ERROR] Failed to add {escaped_entry} ({err:?})");
                return Err(err.into());
            }
            Ok(None) => {
                let msg = format!("Unable to find {escaped_entry}");
                return Err(MlarError::MlaV1(mla_v1::errors::Error::IOError(
                    io::Error::new(io::ErrorKind::NotFound, format!("[ERROR] {msg}")),
                )));
            }
            Ok(Some(mla)) => mla,
        };

        // Normalize Windows paths by replacing backslashes with slashes
        let normalized_filename = entry.filename.replace('\\', "/");
        let Ok(new_entry_name) = EntryName::from_path(normalized_filename) else {
            eprintln!("[ERROR] Invalid or empty entry name");
            return Err(MlarError::InvalidEntryNameToPath);
        };

        if let Err(e) = mla_out.add_entry(new_entry_name, entry.size, entry.data) {
            let msg = format!("Failed to add entry {escaped_entry}: {e}");
            return Err(MlarError::Mla(Error::Other(format!("[ERROR] {msg}"))));
        }
    }

    mla_out.finalize().map_err(|e| {
        eprintln!("[ERROR] Failed to finalize archive: {e}");
        <mla::errors::Error as std::convert::Into<MlarError>>::into(e)
    })?;

    Ok(())
}

fn main() -> Result<(), MlarError> {
    let matches = app().get_matches();

    // User-friendly panic output
    let verbose = matches.get_flag("verbose");

    // Since Rust 2021, panic's payload is &'static str or String
    std::panic::set_hook(Box::new(move |panic_info| {
        let msg = match panic_info.payload().downcast_ref::<&str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                // if not &'static str
                Some(s) => s.as_str(),
                None => "Unknown panic",
            },
        };
        eprintln!("[ERROR] {msg}");

        if verbose && let Some(location) = panic_info.location() {
            let file = location.file();
            let line = location.line();
            eprintln!("(at {file}:{line})");
        }
    }));
    // error propagated
    upgrade(&matches)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use assert_cmd::Command;
    use std::{env, fs};

    #[test]
    fn test_upgrade_and_no_backslashes_in_output() {
        let base_temp = env::temp_dir();

        let files = [
            ("archive_v1.mla", "test-data"),
            ("archive_v1_windows.mla", "test-data"),
            ("test_x25519_archive_v1.pem", "test-data"),
            ("test_mlakey_archive_v2_receiver.mlapub", "../../samples"),
            ("test_mlakey_archive_v2_receiver.mlapriv", "../../samples"),
        ];

        // Copy test files into base_temp
        for (file, src_dir) in &files {
            fs::copy(format!("{src_dir}/{file}"), base_temp.join(file))
                .expect("[ERROR] Failed to copy test file");
        }

        // Change current dir to the temp test directory
        env::set_current_dir(&base_temp).expect("[ERROR] Failed to set current directory");

        // Helper function for running upgrade with arguments
        let run_upgrade = |input: &str, output: &str, private_key: &str, public_key: &str| {
            let matches = app().get_matches_from([
                "mlar-upgrader",
                "-k",
                private_key,
                "-i",
                input,
                "-o",
                output,
                "-p",
                public_key,
            ]);
            let _ = upgrade(&matches);
        };

        // 1. Run upgrade on archive_v1.mla (basic test)
        run_upgrade(
            "archive_v1.mla",
            "archive_v2_v1.mla",
            "test_x25519_archive_v1.pem",
            "test_mlakey_archive_v2_receiver.mlapub",
        );

        // 2.1 Run upgrade on archive_v1_windows.mla (check backslash removal)
        run_upgrade(
            "archive_v1_windows.mla",
            "archive_v2_windows.mla",
            "test_x25519_archive_v1.pem",
            "test_mlakey_archive_v2_receiver.mlapub",
        );

        // 2.2 Verify no backslashes in output from Windows archive upgrade
        let mut cmd = Command::cargo_bin("mlar").expect("[ERROR] Failed to find mlar binary");
        cmd.arg("list")
            .arg("-k")
            .arg("test_mlakey_archive_v2_receiver.mlapriv")
            .arg("-i")
            .arg("archive_v2_windows.mla")
            .arg("--skip-signature-verification");

        let output = cmd.assert().success().get_output().stdout.clone();
        let output_str = String::from_utf8(output).expect("[ERROR] Output not valid UTF-8");

        for line in output_str.lines() {
            assert!(
                !line.contains('\\'),
                "Entry name contains backslash: {line}"
            );
        }

        // Cleanup all copied and generated files
        for (file, _) in &files {
            fs::remove_file(base_temp.join(file)).unwrap();
        }
        fs::remove_file(base_temp.join("archive_v2_v1.mla")).unwrap();
        fs::remove_file(base_temp.join("archive_v2_windows.mla")).unwrap();
    }
}

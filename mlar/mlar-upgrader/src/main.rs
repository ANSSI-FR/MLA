use std::{
    fs::{self, File},
    path::PathBuf,
};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use mla::{config::ArchiveWriterConfig, crypto::mlakey::MLAPublicKey, entry::EntryName};

fn app() -> Command {
    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("input")
                .help("Archive path")
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
}

fn writer_from_matches(matches: &ArgMatches) -> mla::ArchiveWriter<'static, File> {
    let config = if let Some(public_key_args) = matches.get_many::<PathBuf>("public_keys") {
        let (pub_encryption_keys, _) = public_key_args
            .map(|pub_key_path| {
                let mut key_file = File::open(pub_key_path).unwrap_or_else(|e| {
                    eprintln!(
                        "Failed to open public key \"{}\": {e}",
                        pub_key_path.display()
                    );
                    std::process::exit(1);
                });
                MLAPublicKey::deserialize_public_key(&mut key_file)
                    .unwrap_or_else(|e| {
                        eprintln!(
                            "Failed to parse public key \"{}\": {e}",
                            pub_key_path.display()
                        );
                        std::process::exit(1);
                    })
                    .get_public_keys()
            })
            .collect::<(Vec<_>, Vec<_>)>();
        ArchiveWriterConfig::with_encryption_without_signature(&pub_encryption_keys)
    } else {
        ArchiveWriterConfig::without_encryption_without_signature()
    }
    .unwrap_or_else(|e| {
        eprintln!("Invalid archive config: {e}");
        std::process::exit(1);
    });

    let out_file_path = matches.get_one::<PathBuf>("output").unwrap_or_else(|| {
        eprintln!("Missing required output file argument");
        std::process::exit(1);
    });

    let out_file = File::create(out_file_path).unwrap_or_else(|e| {
        eprintln!(
            "Failed to create output file \"{}\": {e}",
            out_file_path.display()
        );
        std::process::exit(1);
    });

    mla::ArchiveWriter::from_config(out_file, config).unwrap_or_else(|e| {
        eprintln!("Failed to create archive writer: {e}");
        std::process::exit(1);
    })
}

fn reader_from_matches(matches: &ArgMatches) -> mla_v1::ArchiveReader<'static, File> {
    let mut config_v1 = mla_v1::config::ArchiveReaderConfig::new();

    if let Some(private_key_args) = matches.get_many::<PathBuf>("private_keys") {
        let mut private_keys = Vec::new();
        for private_key_arg in private_key_args {
            let key_bytes = fs::read(private_key_arg).unwrap_or_else(|e| {
                eprintln!(
                    "Failed to read private key \"{}\": {e}",
                    private_key_arg.display()
                );
                std::process::exit(1);
            });

            match curve25519_parser::parse_openssl_25519_privkey(&key_bytes) {
                Ok(key) => private_keys.push(key),
                Err(err) => {
                    eprintln!(
                        "Failed to parse private key \"{}\": {err}",
                        private_key_arg.display()
                    );
                    std::process::exit(1);
                }
            }
        }
        config_v1.layers_enabled.insert(mla_v1::Layers::ENCRYPT);
        config_v1.add_private_keys(&private_keys);
    }

    let in_file_path = matches.get_one::<PathBuf>("input").unwrap_or_else(|| {
        eprintln!("Missing required input file argument");
        std::process::exit(1);
    });

    let in_file = File::open(in_file_path).unwrap_or_else(|e| {
        eprintln!(
            "Failed to open input file \"{}\": {e}",
            in_file_path.display()
        );
        std::process::exit(1);
    });

    mla_v1::ArchiveReader::from_config(in_file, config_v1).unwrap_or_else(|e| {
        eprintln!("Failed to create archive reader: {e}");
        std::process::exit(1);
    })
}

fn upgrade(matches: &ArgMatches) {
    let mut mla_in = reader_from_matches(matches);

    // Read the file list using metadata
    // v1 archive still uses files, not entries
    let fnames: Vec<String> = mla_in.list_files().map_or_else(
        |_| {
            eprintln!("Archive is malformed or unreadable. Consider repairing the file.");
            std::process::exit(1);
        },
        |iter| iter.cloned().collect(),
    );

    let mut mla_out = writer_from_matches(matches);

    for fname in fnames {
        eprintln!("{fname}");

        let sub_file = match mla_in.get_file(fname.clone()) {
            Err(err) => {
                eprintln!("Error while adding {fname} ({err:?})");
                continue;
            }
            Ok(None) => {
                eprintln!("Unable to find {fname}");
                continue;
            }
            Ok(Some(mla)) => mla,
        };
        // If upgrading on Linux a MLA v1 archive for further Windows extraction
        // we need to replace the backslashes with slashes (`/`) before serialization like Windows
        // does in `EntryName::from_path`.
        let normalized_filename = sub_file.filename.replace('\\', "/");
        let Ok(new_entry_name) = EntryName::from_path(normalized_filename) else {
            eprintln!("Invalid or empty entry name");
            continue;
        };

        if let Err(e) = mla_out.add_entry(new_entry_name, sub_file.size, sub_file.data) {
            eprintln!("Failed to add entry {fname}: {e}");
        }
    }

    mla_out.finalize().unwrap_or_else(|e| {
        eprintln!("Failed to finalize archive: {e}");
        std::process::exit(1);
    });
}

fn main() {
    // User-friendly panic output
    std::panic::set_hook(Box::new(|panic_info| {
        let msg = match panic_info.payload().downcast_ref::<&str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => s.as_str(),
                None => "Unknown panic",
            },
        };
        eprintln!("Error: {msg}");
        if let Some(location) = panic_info.location() {
            let file = location.file();
            let line = location.line();
            eprintln!("(at {file}:{line})");
        }
        std::process::exit(1);
    }));

    let matches = app().get_matches();
    upgrade(&matches);
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
                .unwrap_or_else(|e| panic!("Failed to copy {file}: {e}"));
        }

        // Change current dir to the temp test directory
        env::set_current_dir(&base_temp).expect("Failed to set current directory");

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
            upgrade(&matches);
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
        let mut cmd = Command::cargo_bin("mlar").expect("Failed to find mlar binary");
        cmd.arg("list")
            .arg("-k")
            .arg("test_mlakey_archive_v2_receiver.mlapriv")
            .arg("-i")
            .arg("archive_v2_windows.mla")
            .arg("--skip-signature-verification");

        let output = cmd.assert().success().get_output().stdout.clone();
        let output_str = String::from_utf8(output).expect("Output not valid UTF-8");

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

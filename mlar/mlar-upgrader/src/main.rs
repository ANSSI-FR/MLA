use std::{
    fs::{self, File},
    io::Error,
    path::PathBuf,
};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};

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
                .help("MLA 2 public key paths (DER or PEM format)")
                .long("pubkey")
                .short('p')
                .num_args(1)
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf)),
        )
}

fn writer_from_matches(matches: &ArgMatches) -> mla::ArchiveWriter<'static, File> {
    let mut config = mla::config::ArchiveWriterConfig::new();
    config.enable_layer(mla::format::Layers::COMPRESS);
    if let Some(public_key_args) = matches.get_many::<PathBuf>("public_keys") {
        let mut public_keys = Vec::new();
        for public_key_arg in public_key_args {
            let key_bytes = fs::read(public_key_arg).expect("Failed to read public key");
            let public_key = mla::crypto::mlakey::parse_mlakey_pubkey_pem(&key_bytes)
                .map_err(|err| format!("Failed to parse public key as PEM: {err}"))
                .unwrap();

            public_keys.push(public_key);
        }
        config.enable_layer(mla::format::Layers::ENCRYPT);
        config.add_public_keys(&public_keys);
    }
    let out_file_path = matches.get_one::<PathBuf>("output").unwrap();
    let out_file = File::create(out_file_path).unwrap();
    mla::ArchiveWriter::from_config(out_file, config).unwrap()
}

fn reader_from_matches(matches: &ArgMatches) -> mla_v1::ArchiveReader<'static, File> {
    let mut config_v1 = mla_v1::config::ArchiveReaderConfig::new();
    if let Some(private_key_args) = matches.get_many::<PathBuf>("private_keys") {
        let mut private_keys = Vec::new();
        for private_key_arg in private_key_args {
            let key_bytes = fs::read(private_key_arg).expect("Failed to read private key");
            match curve25519_parser::parse_openssl_25519_privkey(&key_bytes) {
                Ok(key) => private_keys.push(key),
                Err(err) => panic!("Failed to parse private key: {err}"),
            }
        }
        config_v1.layers_enabled.insert(mla_v1::Layers::ENCRYPT);
        config_v1.add_private_keys(&private_keys);
    }
    let in_file_path = matches.get_one::<PathBuf>("input").unwrap();
    let in_file = File::open(in_file_path).unwrap();
    mla_v1::ArchiveReader::from_config(in_file, config_v1).unwrap()
}

fn upgrade(matches: &ArgMatches) -> Result<(), Error> {
    let mut mla_in = reader_from_matches(matches);

    // Read the file list using metadata
    let fnames: Vec<String> = mla_in.list_files().map_or_else(
        |_| {
            panic!("Files is malformed. Please consider repairing the file");
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
        mla_out
            .add_entry(&sub_file.filename, sub_file.size, sub_file.data)
            .unwrap();
    }
    mla_out.finalize().expect("Finalization error");

    Ok(())
}

fn main() {
    let matches = app().get_matches();
    upgrade(&matches).expect("Failed to upgrade");
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_upgrade() {
        // temporary directory for output as we don't know if we can write in current one
        let temp_dir = env::temp_dir();

        // mlar-upgrade args
        let input = "archive_v1.mla";
        let output = temp_dir.join("archive_v2.mla");
        let private_keys = "test_x25519_archive_v1.pem";
        let public_keys = "test_mlakey_archive_v2_pub.pem";

        // temporary locations
        let temp_input = temp_dir.join(input);
        let temp_private_keys = temp_dir.join(private_keys);
        let temp_public_keys = temp_dir.join(public_keys);

        // copy input, private_keys, public_keys to temp_dir
        fs::copy(format!("../../samples/{input}"), &temp_input).unwrap();
        fs::copy(format!("../../samples/{private_keys}"), &temp_private_keys).unwrap();
        fs::copy(format!("../../samples/{public_keys}"), &temp_public_keys).unwrap();

        env::set_current_dir(&temp_dir).unwrap();

        let matches = app().get_matches_from([
            "mlar-upgrader",
            "-k",
            private_keys,
            "-i",
            input,
            "-o",
            output.to_str().unwrap(),
            "-p",
            public_keys,
        ]);

        assert!(upgrade(&matches).is_ok());

        // Clean up
        fs::remove_file(temp_input).unwrap();
        fs::remove_file(temp_private_keys).unwrap();
        fs::remove_file(temp_public_keys).unwrap();
    }
}

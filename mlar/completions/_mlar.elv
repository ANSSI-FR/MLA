
use builtin;
use str;

set edit:completion:arg-completer[mlar] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'mlar'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
        &'mlar'= {
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
            cand -V 'Print version'
            cand --version 'Print version'
            cand create 'Create a new MLA Archive'
            cand list 'List entries inside a MLA Archive'
            cand extract 'Extract entries from a MLA Archive to files'
            cand cat 'Display entries from a MLA Archive, like ''cat'''
            cand to-tar 'Convert a MLA Archive to a TAR Archive'
            cand clean-truncated 'Recover readable data from a truncated archive by creating a new archive. This process discards damaged metadata and skips signature verification.'
            cand convert 'Convert a MLA Archive to a fresh new one, with potentially different options'
            cand keygen 'Generate a public/private MLA keypair'
            cand keyderive 'Advanced use case: Derive a new public/private keypair from an existing one and a public path, see `doc/KEY_DERIVATION.md`'
            cand info 'Get info on a MLA Archive'
            cand shared-secret 'Advanced use case: See Rust documentation of `mla::helpers::shared_secret`.'
            cand completions 'Generate shell completion scripts'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'mlar;create'= {
            cand -o 'Output file path. Use - for stdout'
            cand --output 'Output file path. Use - for stdout'
            cand -q 'Compression level (0-11); ; bigger values cause denser, but slower compression'
            cand --compression_level 'Compression level (0-11); ; bigger values cause denser, but slower compression'
            cand -k 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --private-key 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand -p 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --public-key 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --stdin-data-entry-names 'Comma-separated list of entry names to create with regards to content provided on stdin. Default: "default-entry".'
            cand --stdin-data-separator 'Delimiter string used to separate multiple archive entries from stdin. Required if --stdin-data includes multiple entries. Default: no separator (stdin will thus be treated as a single entry).'
            cand --uncompressed 'Disable compression.'
            cand --unencrypted 'Disable encryption.'
            cand --unsigned 'Disable signature.'
            cand --stdin-filepath-list 'Add filepaths specified on stdin (one UTF-8 path per line) rather than from positional arguments.'
            cand --stdin-data 'Pipe archive entries content from stdin. Can be customized with --stdin-data-entry-names and --stdin-data-separator.'
            cand --skip-not-found 'Skip files that are not found instead of failing.'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;list'= {
            cand -i 'Archive path'
            cand --input 'Archive path'
            cand -k 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --private-key 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand -p 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --public-key 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --shared-secret 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.'
            cand --accept-unencrypted 'Accept to operate on unencrypted archives'
            cand --only-one-key-with-valid-signature-is-ok 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
            cand --skip-signature-verification 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
            cand --raw-escaped-names 'Do not try to interpret entry names as paths and encode everything not alphanumeric, dash, underscore or dot'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;extract'= {
            cand -i 'Archive path'
            cand --input 'Archive path'
            cand -k 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --private-key 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand -p 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --public-key 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --shared-secret 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.'
            cand -o 'Output directory where files are extracted'
            cand --output 'Output directory where files are extracted'
            cand --accept-unencrypted 'Accept to operate on unencrypted archives'
            cand --only-one-key-with-valid-signature-is-ok 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
            cand --skip-signature-verification 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
            cand -g 'Treat specified files as glob patterns'
            cand --glob 'Treat specified files as glob patterns'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;cat'= {
            cand -i 'Archive path'
            cand --input 'Archive path'
            cand -k 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --private-key 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand -p 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --public-key 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --shared-secret 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.'
            cand -o 'Output file'
            cand --output 'Output file'
            cand --accept-unencrypted 'Accept to operate on unencrypted archives'
            cand --only-one-key-with-valid-signature-is-ok 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
            cand --skip-signature-verification 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
            cand -g 'Treat given entries names as glob patterns'
            cand --glob 'Treat given entries names as glob patterns'
            cand --raw-escaped-names 'With this option, entries names given as positional arguments should be specified as displayed by mlar list with this same option. This lets you see entries that cannot be interpreted as valid path.'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;to-tar'= {
            cand -i 'Archive path'
            cand --input 'Archive path'
            cand -k 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --private-key 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand -p 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --public-key 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --shared-secret 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.'
            cand -o 'Tar Archive path'
            cand --output 'Tar Archive path'
            cand --accept-unencrypted 'Accept to operate on unencrypted archives'
            cand --only-one-key-with-valid-signature-is-ok 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
            cand --skip-signature-verification 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;clean-truncated'= {
            cand -i 'Archive path'
            cand --input 'Archive path'
            cand -o 'Output file path. Use - for stdout'
            cand --output 'Output file path. Use - for stdout'
            cand -q 'Compression level (0-11); ; bigger values cause denser, but slower compression'
            cand --compression_level 'Compression level (0-11); ; bigger values cause denser, but slower compression'
            cand -k 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --private-key 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand -p 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --public-key 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --shared-secret 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.'
            cand --out-pub 'MLA public key file for output archive encryption'
            cand --out-priv 'MLA private key file for output archive signing'
            cand --accept-unencrypted 'Accept to operate on unencrypted archives'
            cand --only-one-key-with-valid-signature-is-ok 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
            cand --skip-signature-verification 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
            cand --uncompressed 'Disable compression.'
            cand --unencrypted 'Disable encryption.'
            cand --unsigned 'Disable signature.'
            cand --allow-unauthenticated-data 'Allow extraction of unauthenticated data from the archive. USE THIS OPTION ONLY IF NECESSARY'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;convert'= {
            cand -i 'Archive path'
            cand --input 'Archive path'
            cand -o 'Output file path. Use - for stdout'
            cand --output 'Output file path. Use - for stdout'
            cand -q 'Compression level (0-11); ; bigger values cause denser, but slower compression'
            cand --compression_level 'Compression level (0-11); ; bigger values cause denser, but slower compression'
            cand -k 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --private-key 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand -p 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --public-key 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --shared-secret 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.'
            cand --out-pub 'MLA public key file for output archive encryption'
            cand --out-priv 'MLA private key file for output archive signing'
            cand --accept-unencrypted 'Accept to operate on unencrypted archives'
            cand --only-one-key-with-valid-signature-is-ok 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
            cand --skip-signature-verification 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
            cand --uncompressed 'Disable compression.'
            cand --unencrypted 'Disable encryption.'
            cand --unsigned 'Disable signature.'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;keygen'= {
            cand -s 'Initial seed for deterministic key generation. THE SEED IS AS SECRET AS THE RESULTING PRIVATE KEY. USE THIS OPTION ONLY IF NECESSARY'
            cand --seed 'Initial seed for deterministic key generation. THE SEED IS AS SECRET AS THE RESULTING PRIVATE KEY. USE THIS OPTION ONLY IF NECESSARY'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
            cand public-from-private 'Generate public key from private key'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'mlar;keygen;public-from-private'= {
            cand -o 'Output public key file (.mlapub). If omitted, the path is derived from the input filename'
            cand --output 'Output public key file (.mlapub). If omitted, the path is derived from the input filename'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;keygen;help'= {
            cand public-from-private 'Generate public key from private key'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'mlar;keygen;help;public-from-private'= {
        }
        &'mlar;keygen;help;help'= {
        }
        &'mlar;keyderive'= {
            cand -p 'Public derivation path, can be specified multiple times'
            cand --path-component 'Public derivation path, can be specified multiple times'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;info'= {
            cand -i 'Archive path'
            cand --input 'Archive path'
            cand --accept-unencrypted 'Accept to operate on unencrypted archives'
            cand --only-one-key-with-valid-signature-is-ok 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
            cand --skip-signature-verification 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;shared-secret'= {
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
            cand get-decryption-metadata 'Get decryption metadata'
            cand decapsulate 'Decapsulate metadata to obtain shared secret.'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'mlar;shared-secret;get-decryption-metadata'= {
            cand -i 'Archive path'
            cand --input 'Archive path'
            cand -o 'Output file path. Use - for stdout'
            cand --output 'Output file path. Use - for stdout'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;shared-secret;decapsulate'= {
            cand -m 'Decryption metadata file path'
            cand --decryption-metadata 'Decryption metadata file path'
            cand -k 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand --private-key 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.'
            cand -o 'Output file path. Use - for stdout'
            cand --output 'Output file path. Use - for stdout'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;shared-secret;help'= {
            cand get-decryption-metadata 'Get decryption metadata'
            cand decapsulate 'Decapsulate metadata to obtain shared secret.'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'mlar;shared-secret;help;get-decryption-metadata'= {
        }
        &'mlar;shared-secret;help;decapsulate'= {
        }
        &'mlar;shared-secret;help;help'= {
        }
        &'mlar;completions'= {
            cand -s 'Shell to generate completions for'
            cand --shell 'Shell to generate completions for'
            cand -v 'Increase verbosity level'
            cand --verbose 'Increase verbosity level'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'mlar;help'= {
            cand create 'Create a new MLA Archive'
            cand list 'List entries inside a MLA Archive'
            cand extract 'Extract entries from a MLA Archive to files'
            cand cat 'Display entries from a MLA Archive, like ''cat'''
            cand to-tar 'Convert a MLA Archive to a TAR Archive'
            cand clean-truncated 'Recover readable data from a truncated archive by creating a new archive. This process discards damaged metadata and skips signature verification.'
            cand convert 'Convert a MLA Archive to a fresh new one, with potentially different options'
            cand keygen 'Generate a public/private MLA keypair'
            cand keyderive 'Advanced use case: Derive a new public/private keypair from an existing one and a public path, see `doc/KEY_DERIVATION.md`'
            cand info 'Get info on a MLA Archive'
            cand shared-secret 'Advanced use case: See Rust documentation of `mla::helpers::shared_secret`.'
            cand completions 'Generate shell completion scripts'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'mlar;help;create'= {
        }
        &'mlar;help;list'= {
        }
        &'mlar;help;extract'= {
        }
        &'mlar;help;cat'= {
        }
        &'mlar;help;to-tar'= {
        }
        &'mlar;help;clean-truncated'= {
        }
        &'mlar;help;convert'= {
        }
        &'mlar;help;keygen'= {
            cand public-from-private 'Generate public key from private key'
        }
        &'mlar;help;keygen;public-from-private'= {
        }
        &'mlar;help;keyderive'= {
        }
        &'mlar;help;info'= {
        }
        &'mlar;help;shared-secret'= {
            cand get-decryption-metadata 'Get decryption metadata'
            cand decapsulate 'Decapsulate metadata to obtain shared secret.'
        }
        &'mlar;help;shared-secret;get-decryption-metadata'= {
        }
        &'mlar;help;shared-secret;decapsulate'= {
        }
        &'mlar;help;completions'= {
        }
        &'mlar;help;help'= {
        }
    ]
    $completions[$command]
}

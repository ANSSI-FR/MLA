# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_mlar_global_optspecs
    string join \n v/verbose h/help V/version
end

function __fish_mlar_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_mlar_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_mlar_using_subcommand
    set -l cmd (__fish_mlar_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c mlar -n "__fish_mlar_needs_command" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_needs_command" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_needs_command" -s V -l version -d 'Print version'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "create" -d 'Create a new MLA Archive'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "list" -d 'List entries inside a MLA Archive'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "extract" -d 'Extract entries from a MLA Archive to files'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "cat" -d 'Display entries from a MLA Archive, like \'cat\''
complete -c mlar -n "__fish_mlar_needs_command" -f -a "to-tar" -d 'Convert a MLA Archive to a TAR Archive'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "clean-truncated" -d 'Recover readable data from a truncated archive by creating a new archive. This process discards damaged metadata and skips signature verification.'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "convert" -d 'Convert a MLA Archive to a fresh new one, with potentially different options'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "keygen" -d 'Generate a public/private MLA keypair'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "keyderive" -d 'Advanced use case: Derive a new public/private keypair from an existing one and a public path, see `doc/KEY_DERIVATION.md`'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "info" -d 'Get info on a MLA Archive'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "shared-secret" -d 'Advanced use case: See Rust documentation of `mla::helpers::shared_secret`.'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "completions" -d 'Generate shell completion scripts'
complete -c mlar -n "__fish_mlar_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c mlar -n "__fish_mlar_using_subcommand create" -s o -l output -d 'Output file path. Use - for stdout' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand create" -s q -l compression_level -d 'Compression level (0-11); ; bigger values cause denser, but slower compression' -r
complete -c mlar -n "__fish_mlar_using_subcommand create" -s k -l private-key -d 'MLA private key file. If A creates an archive for B, A uses A\'s private key for signing. For reading, B uses B\'s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand create" -s p -l public-key -d 'MLA public key file. If A creates an archive for B, A uses B\'s public key for encryption. For reading, B uses A\'s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand create" -l stdin-data-entry-names -d 'Comma-separated list of entry names to create with regards to content provided on stdin. Default: "default-entry".' -r
complete -c mlar -n "__fish_mlar_using_subcommand create" -l stdin-data-separator -d 'Delimiter string used to separate multiple archive entries from stdin. Required if --stdin-data includes multiple entries. Default: no separator (stdin will thus be treated as a single entry).' -r
complete -c mlar -n "__fish_mlar_using_subcommand create" -l uncompressed -d 'Disable compression.'
complete -c mlar -n "__fish_mlar_using_subcommand create" -l unencrypted -d 'Disable encryption.'
complete -c mlar -n "__fish_mlar_using_subcommand create" -l unsigned -d 'Disable signature.'
complete -c mlar -n "__fish_mlar_using_subcommand create" -l stdin-filepath-list -d 'Add filepaths specified on stdin (one UTF-8 path per line) rather than from positional arguments.'
complete -c mlar -n "__fish_mlar_using_subcommand create" -l stdin-data -d 'Pipe archive entries content from stdin. Can be customized with --stdin-data-entry-names and --stdin-data-separator.'
complete -c mlar -n "__fish_mlar_using_subcommand create" -l skip-not-found -d 'Skip files that are not found instead of failing.'
complete -c mlar -n "__fish_mlar_using_subcommand create" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand create" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand list" -s i -l input -d 'Archive path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand list" -s k -l private-key -d 'MLA private key file. If A creates an archive for B, A uses A\'s private key for signing. For reading, B uses B\'s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand list" -s p -l public-key -d 'MLA public key file. If A creates an archive for B, A uses B\'s public key for encryption. For reading, B uses A\'s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand list" -l shared-secret -d 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand list" -l accept-unencrypted -d 'Accept to operate on unencrypted archives'
complete -c mlar -n "__fish_mlar_using_subcommand list" -l only-one-key-with-valid-signature-is-ok -d 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
complete -c mlar -n "__fish_mlar_using_subcommand list" -l skip-signature-verification -d 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
complete -c mlar -n "__fish_mlar_using_subcommand list" -l raw-escaped-names -d 'Do not try to interpret entry names as paths and encode everything not alphanumeric, dash, underscore or dot'
complete -c mlar -n "__fish_mlar_using_subcommand list" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand list" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand extract" -s i -l input -d 'Archive path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand extract" -s k -l private-key -d 'MLA private key file. If A creates an archive for B, A uses A\'s private key for signing. For reading, B uses B\'s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand extract" -s p -l public-key -d 'MLA public key file. If A creates an archive for B, A uses B\'s public key for encryption. For reading, B uses A\'s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand extract" -l shared-secret -d 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand extract" -s o -l output -d 'Output directory where files are extracted' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand extract" -l accept-unencrypted -d 'Accept to operate on unencrypted archives'
complete -c mlar -n "__fish_mlar_using_subcommand extract" -l only-one-key-with-valid-signature-is-ok -d 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
complete -c mlar -n "__fish_mlar_using_subcommand extract" -l skip-signature-verification -d 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
complete -c mlar -n "__fish_mlar_using_subcommand extract" -s g -l glob -d 'Treat specified files as glob patterns'
complete -c mlar -n "__fish_mlar_using_subcommand extract" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand extract" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand cat" -s i -l input -d 'Archive path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand cat" -s k -l private-key -d 'MLA private key file. If A creates an archive for B, A uses A\'s private key for signing. For reading, B uses B\'s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand cat" -s p -l public-key -d 'MLA public key file. If A creates an archive for B, A uses B\'s public key for encryption. For reading, B uses A\'s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand cat" -l shared-secret -d 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand cat" -s o -l output -d 'Output file' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand cat" -l accept-unencrypted -d 'Accept to operate on unencrypted archives'
complete -c mlar -n "__fish_mlar_using_subcommand cat" -l only-one-key-with-valid-signature-is-ok -d 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
complete -c mlar -n "__fish_mlar_using_subcommand cat" -l skip-signature-verification -d 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
complete -c mlar -n "__fish_mlar_using_subcommand cat" -s g -l glob -d 'Treat given entries names as glob patterns'
complete -c mlar -n "__fish_mlar_using_subcommand cat" -l raw-escaped-names -d 'With this option, entries names given as positional arguments should be specified as displayed by mlar list with this same option. This lets you see entries that cannot be interpreted as valid path.'
complete -c mlar -n "__fish_mlar_using_subcommand cat" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand cat" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -s i -l input -d 'Archive path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -s k -l private-key -d 'MLA private key file. If A creates an archive for B, A uses A\'s private key for signing. For reading, B uses B\'s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -s p -l public-key -d 'MLA public key file. If A creates an archive for B, A uses B\'s public key for encryption. For reading, B uses A\'s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -l shared-secret -d 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -s o -l output -d 'Tar Archive path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -l accept-unencrypted -d 'Accept to operate on unencrypted archives'
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -l only-one-key-with-valid-signature-is-ok -d 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -l skip-signature-verification -d 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand to-tar" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -s i -l input -d 'Archive path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -s o -l output -d 'Output file path. Use - for stdout' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -s q -l compression_level -d 'Compression level (0-11); ; bigger values cause denser, but slower compression' -r
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -s k -l private-key -d 'MLA private key file. If A creates an archive for B, A uses A\'s private key for signing. For reading, B uses B\'s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -s p -l public-key -d 'MLA public key file. If A creates an archive for B, A uses B\'s public key for encryption. For reading, B uses A\'s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l shared-secret -d 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l out-pub -d 'MLA public key file for output archive encryption' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l out-priv -d 'MLA private key file for output archive signing' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l accept-unencrypted -d 'Accept to operate on unencrypted archives'
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l only-one-key-with-valid-signature-is-ok -d 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l skip-signature-verification -d 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l uncompressed -d 'Disable compression.'
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l unencrypted -d 'Disable encryption.'
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l unsigned -d 'Disable signature.'
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -l allow-unauthenticated-data -d 'Allow extraction of unauthenticated data from the archive. USE THIS OPTION ONLY IF NECESSARY'
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand clean-truncated" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand convert" -s i -l input -d 'Archive path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand convert" -s o -l output -d 'Output file path. Use - for stdout' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand convert" -s q -l compression_level -d 'Compression level (0-11); ; bigger values cause denser, but slower compression' -r
complete -c mlar -n "__fish_mlar_using_subcommand convert" -s k -l private-key -d 'MLA private key file. If A creates an archive for B, A uses A\'s private key for signing. For reading, B uses B\'s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand convert" -s p -l public-key -d 'MLA public key file. If A creates an archive for B, A uses B\'s public key for encryption. For reading, B uses A\'s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand convert" -l shared-secret -d 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand convert" -l out-pub -d 'MLA public key file for output archive encryption' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand convert" -l out-priv -d 'MLA private key file for output archive signing' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand convert" -l accept-unencrypted -d 'Accept to operate on unencrypted archives'
complete -c mlar -n "__fish_mlar_using_subcommand convert" -l only-one-key-with-valid-signature-is-ok -d 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
complete -c mlar -n "__fish_mlar_using_subcommand convert" -l skip-signature-verification -d 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
complete -c mlar -n "__fish_mlar_using_subcommand convert" -l uncompressed -d 'Disable compression.'
complete -c mlar -n "__fish_mlar_using_subcommand convert" -l unencrypted -d 'Disable encryption.'
complete -c mlar -n "__fish_mlar_using_subcommand convert" -l unsigned -d 'Disable signature.'
complete -c mlar -n "__fish_mlar_using_subcommand convert" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand convert" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and not __fish_seen_subcommand_from public-from-private help" -s s -l seed -d 'Initial seed for deterministic key generation. THE SEED IS AS SECRET AS THE RESULTING PRIVATE KEY. USE THIS OPTION ONLY IF NECESSARY' -r
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and not __fish_seen_subcommand_from public-from-private help" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and not __fish_seen_subcommand_from public-from-private help" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and not __fish_seen_subcommand_from public-from-private help" -a "public-from-private" -d 'Generate public key from private key'
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and not __fish_seen_subcommand_from public-from-private help" -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and __fish_seen_subcommand_from public-from-private" -s o -l output -d 'Output public key file (.mlapub). If omitted, the path is derived from the input filename' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and __fish_seen_subcommand_from public-from-private" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and __fish_seen_subcommand_from public-from-private" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and __fish_seen_subcommand_from help" -f -a "public-from-private" -d 'Generate public key from private key'
complete -c mlar -n "__fish_mlar_using_subcommand keygen; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c mlar -n "__fish_mlar_using_subcommand keyderive" -s p -l path-component -d 'Public derivation path, can be specified multiple times' -r
complete -c mlar -n "__fish_mlar_using_subcommand keyderive" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand keyderive" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand info" -s i -l input -d 'Archive path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand info" -l accept-unencrypted -d 'Accept to operate on unencrypted archives'
complete -c mlar -n "__fish_mlar_using_subcommand info" -l only-one-key-with-valid-signature-is-ok -d 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag '
complete -c mlar -n "__fish_mlar_using_subcommand info" -l skip-signature-verification -d 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.'
complete -c mlar -n "__fish_mlar_using_subcommand info" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand info" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and not __fish_seen_subcommand_from get-decryption-metadata decapsulate help" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and not __fish_seen_subcommand_from get-decryption-metadata decapsulate help" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and not __fish_seen_subcommand_from get-decryption-metadata decapsulate help" -f -a "get-decryption-metadata" -d 'Get decryption metadata'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and not __fish_seen_subcommand_from get-decryption-metadata decapsulate help" -f -a "decapsulate" -d 'Decapsulate metadata to obtain shared secret.'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and not __fish_seen_subcommand_from get-decryption-metadata decapsulate help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from get-decryption-metadata" -s i -l input -d 'Archive path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from get-decryption-metadata" -s o -l output -d 'Output file path. Use - for stdout' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from get-decryption-metadata" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from get-decryption-metadata" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from decapsulate" -s m -l decryption-metadata -d 'Decryption metadata file path' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from decapsulate" -s k -l private-key -d 'MLA private key file. If A creates an archive for B, A uses A\'s private key for signing. For reading, B uses B\'s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from decapsulate" -s o -l output -d 'Output file path. Use - for stdout' -r -F
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from decapsulate" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from decapsulate" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from help" -f -a "get-decryption-metadata" -d 'Get decryption metadata'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from help" -f -a "decapsulate" -d 'Decapsulate metadata to obtain shared secret.'
complete -c mlar -n "__fish_mlar_using_subcommand shared-secret; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c mlar -n "__fish_mlar_using_subcommand completions" -s s -l shell -d 'Shell to generate completions for' -r -f -a "bash\t''
zsh\t''
fish\t''
elvish\t''
powershell\t''"
complete -c mlar -n "__fish_mlar_using_subcommand completions" -s v -l verbose -d 'Increase verbosity level'
complete -c mlar -n "__fish_mlar_using_subcommand completions" -s h -l help -d 'Print help'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "create" -d 'Create a new MLA Archive'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "list" -d 'List entries inside a MLA Archive'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "extract" -d 'Extract entries from a MLA Archive to files'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "cat" -d 'Display entries from a MLA Archive, like \'cat\''
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "to-tar" -d 'Convert a MLA Archive to a TAR Archive'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "clean-truncated" -d 'Recover readable data from a truncated archive by creating a new archive. This process discards damaged metadata and skips signature verification.'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "convert" -d 'Convert a MLA Archive to a fresh new one, with potentially different options'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "keygen" -d 'Generate a public/private MLA keypair'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "keyderive" -d 'Advanced use case: Derive a new public/private keypair from an existing one and a public path, see `doc/KEY_DERIVATION.md`'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "info" -d 'Get info on a MLA Archive'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "shared-secret" -d 'Advanced use case: See Rust documentation of `mla::helpers::shared_secret`.'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "completions" -d 'Generate shell completion scripts'
complete -c mlar -n "__fish_mlar_using_subcommand help; and not __fish_seen_subcommand_from create list extract cat to-tar clean-truncated convert keygen keyderive info shared-secret completions help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c mlar -n "__fish_mlar_using_subcommand help; and __fish_seen_subcommand_from keygen" -f -a "public-from-private" -d 'Generate public key from private key'
complete -c mlar -n "__fish_mlar_using_subcommand help; and __fish_seen_subcommand_from shared-secret" -f -a "get-decryption-metadata" -d 'Get decryption metadata'
complete -c mlar -n "__fish_mlar_using_subcommand help; and __fish_seen_subcommand_from shared-secret" -f -a "decapsulate" -d 'Decapsulate metadata to obtain shared secret.'

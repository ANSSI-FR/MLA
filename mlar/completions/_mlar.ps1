
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'mlar' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'mlar'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'mlar' {
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('create', 'create', [CompletionResultType]::ParameterValue, 'Create a new MLA Archive')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List entries inside a MLA Archive')
            [CompletionResult]::new('extract', 'extract', [CompletionResultType]::ParameterValue, 'Extract entries from a MLA Archive to files')
            [CompletionResult]::new('cat', 'cat', [CompletionResultType]::ParameterValue, 'Display entries from a MLA Archive, like ''cat''')
            [CompletionResult]::new('to-tar', 'to-tar', [CompletionResultType]::ParameterValue, 'Convert a MLA Archive to a TAR Archive')
            [CompletionResult]::new('clean-truncated', 'clean-truncated', [CompletionResultType]::ParameterValue, 'Recover readable data from a truncated archive by creating a new archive. This process discards damaged metadata and skips signature verification.')
            [CompletionResult]::new('convert', 'convert', [CompletionResultType]::ParameterValue, 'Convert a MLA Archive to a fresh new one, with potentially different options')
            [CompletionResult]::new('keygen', 'keygen', [CompletionResultType]::ParameterValue, 'Generate a public/private MLA keypair')
            [CompletionResult]::new('keyderive', 'keyderive', [CompletionResultType]::ParameterValue, 'Advanced use case: Derive a new public/private keypair from an existing one and a public path, see `doc/KEY_DERIVATION.md`')
            [CompletionResult]::new('info', 'info', [CompletionResultType]::ParameterValue, 'Get info on a MLA Archive')
            [CompletionResult]::new('shared-secret', 'shared-secret', [CompletionResultType]::ParameterValue, 'Advanced use case: See Rust documentation of `mla::helpers::shared_secret`.')
            [CompletionResult]::new('completions', 'completions', [CompletionResultType]::ParameterValue, 'Generate shell completion scripts')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'mlar;create' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Compression level (0-11); ; bigger values cause denser, but slower compression')
            [CompletionResult]::new('--compression_level', '--compression_level', [CompletionResultType]::ParameterName, 'Compression level (0-11); ; bigger values cause denser, but slower compression')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--private-key', '--private-key', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--public-key', '--public-key', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--stdin-data-entry-names', '--stdin-data-entry-names', [CompletionResultType]::ParameterName, 'Comma-separated list of entry names to create with regards to content provided on stdin. Default: "default-entry".')
            [CompletionResult]::new('--stdin-data-separator', '--stdin-data-separator', [CompletionResultType]::ParameterName, 'Delimiter string used to separate multiple archive entries from stdin. Required if --stdin-data includes multiple entries. Default: no separator (stdin will thus be treated as a single entry).')
            [CompletionResult]::new('--uncompressed', '--uncompressed', [CompletionResultType]::ParameterName, 'Disable compression.')
            [CompletionResult]::new('--unencrypted', '--unencrypted', [CompletionResultType]::ParameterName, 'Disable encryption.')
            [CompletionResult]::new('--unsigned', '--unsigned', [CompletionResultType]::ParameterName, 'Disable signature.')
            [CompletionResult]::new('--stdin-filepath-list', '--stdin-filepath-list', [CompletionResultType]::ParameterName, 'Add filepaths specified on stdin (one UTF-8 path per line) rather than from positional arguments.')
            [CompletionResult]::new('--stdin-data', '--stdin-data', [CompletionResultType]::ParameterName, 'Pipe archive entries content from stdin. Can be customized with --stdin-data-entry-names and --stdin-data-separator.')
            [CompletionResult]::new('--skip-not-found', '--skip-not-found', [CompletionResultType]::ParameterName, 'Skip files that are not found instead of failing.')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;list' {
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('--input', '--input', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--private-key', '--private-key', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--public-key', '--public-key', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--shared-secret', '--shared-secret', [CompletionResultType]::ParameterName, 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.')
            [CompletionResult]::new('--accept-unencrypted', '--accept-unencrypted', [CompletionResultType]::ParameterName, 'Accept to operate on unencrypted archives')
            [CompletionResult]::new('--only-one-key-with-valid-signature-is-ok', '--only-one-key-with-valid-signature-is-ok', [CompletionResultType]::ParameterName, 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ')
            [CompletionResult]::new('--skip-signature-verification', '--skip-signature-verification', [CompletionResultType]::ParameterName, 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.')
            [CompletionResult]::new('--raw-escaped-names', '--raw-escaped-names', [CompletionResultType]::ParameterName, 'Do not try to interpret entry names as paths and encode everything not alphanumeric, dash, underscore or dot')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;extract' {
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('--input', '--input', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--private-key', '--private-key', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--public-key', '--public-key', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--shared-secret', '--shared-secret', [CompletionResultType]::ParameterName, 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output directory where files are extracted')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output directory where files are extracted')
            [CompletionResult]::new('--accept-unencrypted', '--accept-unencrypted', [CompletionResultType]::ParameterName, 'Accept to operate on unencrypted archives')
            [CompletionResult]::new('--only-one-key-with-valid-signature-is-ok', '--only-one-key-with-valid-signature-is-ok', [CompletionResultType]::ParameterName, 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ')
            [CompletionResult]::new('--skip-signature-verification', '--skip-signature-verification', [CompletionResultType]::ParameterName, 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.')
            [CompletionResult]::new('-g', '-g', [CompletionResultType]::ParameterName, 'Treat specified files as glob patterns')
            [CompletionResult]::new('--glob', '--glob', [CompletionResultType]::ParameterName, 'Treat specified files as glob patterns')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;cat' {
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('--input', '--input', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--private-key', '--private-key', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--public-key', '--public-key', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--shared-secret', '--shared-secret', [CompletionResultType]::ParameterName, 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output file')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output file')
            [CompletionResult]::new('--accept-unencrypted', '--accept-unencrypted', [CompletionResultType]::ParameterName, 'Accept to operate on unencrypted archives')
            [CompletionResult]::new('--only-one-key-with-valid-signature-is-ok', '--only-one-key-with-valid-signature-is-ok', [CompletionResultType]::ParameterName, 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ')
            [CompletionResult]::new('--skip-signature-verification', '--skip-signature-verification', [CompletionResultType]::ParameterName, 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.')
            [CompletionResult]::new('-g', '-g', [CompletionResultType]::ParameterName, 'Treat given entries names as glob patterns')
            [CompletionResult]::new('--glob', '--glob', [CompletionResultType]::ParameterName, 'Treat given entries names as glob patterns')
            [CompletionResult]::new('--raw-escaped-names', '--raw-escaped-names', [CompletionResultType]::ParameterName, 'With this option, entries names given as positional arguments should be specified as displayed by mlar list with this same option. This lets you see entries that cannot be interpreted as valid path.')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;to-tar' {
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('--input', '--input', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--private-key', '--private-key', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--public-key', '--public-key', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--shared-secret', '--shared-secret', [CompletionResultType]::ParameterName, 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Tar Archive path')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Tar Archive path')
            [CompletionResult]::new('--accept-unencrypted', '--accept-unencrypted', [CompletionResultType]::ParameterName, 'Accept to operate on unencrypted archives')
            [CompletionResult]::new('--only-one-key-with-valid-signature-is-ok', '--only-one-key-with-valid-signature-is-ok', [CompletionResultType]::ParameterName, 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ')
            [CompletionResult]::new('--skip-signature-verification', '--skip-signature-verification', [CompletionResultType]::ParameterName, 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;clean-truncated' {
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('--input', '--input', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Compression level (0-11); ; bigger values cause denser, but slower compression')
            [CompletionResult]::new('--compression_level', '--compression_level', [CompletionResultType]::ParameterName, 'Compression level (0-11); ; bigger values cause denser, but slower compression')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--private-key', '--private-key', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--public-key', '--public-key', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--shared-secret', '--shared-secret', [CompletionResultType]::ParameterName, 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.')
            [CompletionResult]::new('--out-pub', '--out-pub', [CompletionResultType]::ParameterName, 'MLA public key file for output archive encryption')
            [CompletionResult]::new('--out-priv', '--out-priv', [CompletionResultType]::ParameterName, 'MLA private key file for output archive signing')
            [CompletionResult]::new('--accept-unencrypted', '--accept-unencrypted', [CompletionResultType]::ParameterName, 'Accept to operate on unencrypted archives')
            [CompletionResult]::new('--only-one-key-with-valid-signature-is-ok', '--only-one-key-with-valid-signature-is-ok', [CompletionResultType]::ParameterName, 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ')
            [CompletionResult]::new('--skip-signature-verification', '--skip-signature-verification', [CompletionResultType]::ParameterName, 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.')
            [CompletionResult]::new('--uncompressed', '--uncompressed', [CompletionResultType]::ParameterName, 'Disable compression.')
            [CompletionResult]::new('--unencrypted', '--unencrypted', [CompletionResultType]::ParameterName, 'Disable encryption.')
            [CompletionResult]::new('--unsigned', '--unsigned', [CompletionResultType]::ParameterName, 'Disable signature.')
            [CompletionResult]::new('--allow-unauthenticated-data', '--allow-unauthenticated-data', [CompletionResultType]::ParameterName, 'Allow extraction of unauthenticated data from the archive. USE THIS OPTION ONLY IF NECESSARY')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;convert' {
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('--input', '--input', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Compression level (0-11); ; bigger values cause denser, but slower compression')
            [CompletionResult]::new('--compression_level', '--compression_level', [CompletionResultType]::ParameterName, 'Compression level (0-11); ; bigger values cause denser, but slower compression')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--private-key', '--private-key', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--public-key', '--public-key', [CompletionResultType]::ParameterName, 'MLA public key file. If A creates an archive for B, A uses B''s public key for encryption. For reading, B uses A''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--shared-secret', '--shared-secret', [CompletionResultType]::ParameterName, 'Advanced use case: File path to a shared secret. See Rust documentation of `mla::helpers::shared_secret`.')
            [CompletionResult]::new('--out-pub', '--out-pub', [CompletionResultType]::ParameterName, 'MLA public key file for output archive encryption')
            [CompletionResult]::new('--out-priv', '--out-priv', [CompletionResultType]::ParameterName, 'MLA private key file for output archive signing')
            [CompletionResult]::new('--accept-unencrypted', '--accept-unencrypted', [CompletionResultType]::ParameterName, 'Accept to operate on unencrypted archives')
            [CompletionResult]::new('--only-one-key-with-valid-signature-is-ok', '--only-one-key-with-valid-signature-is-ok', [CompletionResultType]::ParameterName, 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ')
            [CompletionResult]::new('--skip-signature-verification', '--skip-signature-verification', [CompletionResultType]::ParameterName, 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.')
            [CompletionResult]::new('--uncompressed', '--uncompressed', [CompletionResultType]::ParameterName, 'Disable compression.')
            [CompletionResult]::new('--unencrypted', '--unencrypted', [CompletionResultType]::ParameterName, 'Disable encryption.')
            [CompletionResult]::new('--unsigned', '--unsigned', [CompletionResultType]::ParameterName, 'Disable signature.')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;keygen' {
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Initial seed for deterministic key generation. THE SEED IS AS SECRET AS THE RESULTING PRIVATE KEY. USE THIS OPTION ONLY IF NECESSARY')
            [CompletionResult]::new('--seed', '--seed', [CompletionResultType]::ParameterName, 'Initial seed for deterministic key generation. THE SEED IS AS SECRET AS THE RESULTING PRIVATE KEY. USE THIS OPTION ONLY IF NECESSARY')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('public-from-private', 'public-from-private', [CompletionResultType]::ParameterValue, 'Generate public key from private key')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'mlar;keygen;public-from-private' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output public key file (.mlapub). If omitted, the path is derived from the input filename')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output public key file (.mlapub). If omitted, the path is derived from the input filename')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;keygen;help' {
            [CompletionResult]::new('public-from-private', 'public-from-private', [CompletionResultType]::ParameterValue, 'Generate public key from private key')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'mlar;keygen;help;public-from-private' {
            break
        }
        'mlar;keygen;help;help' {
            break
        }
        'mlar;keyderive' {
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Public derivation path, can be specified multiple times')
            [CompletionResult]::new('--path-component', '--path-component', [CompletionResultType]::ParameterName, 'Public derivation path, can be specified multiple times')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;info' {
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('--input', '--input', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('--accept-unencrypted', '--accept-unencrypted', [CompletionResultType]::ParameterName, 'Accept to operate on unencrypted archives')
            [CompletionResult]::new('--only-one-key-with-valid-signature-is-ok', '--only-one-key-with-valid-signature-is-ok', [CompletionResultType]::ParameterName, 'If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ')
            [CompletionResult]::new('--skip-signature-verification', '--skip-signature-verification', [CompletionResultType]::ParameterName, 'Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;shared-secret' {
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('get-decryption-metadata', 'get-decryption-metadata', [CompletionResultType]::ParameterValue, 'Get decryption metadata')
            [CompletionResult]::new('decapsulate', 'decapsulate', [CompletionResultType]::ParameterValue, 'Decapsulate metadata to obtain shared secret.')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'mlar;shared-secret;get-decryption-metadata' {
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('--input', '--input', [CompletionResultType]::ParameterName, 'Archive path')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;shared-secret;decapsulate' {
            [CompletionResult]::new('-m', '-m', [CompletionResultType]::ParameterName, 'Decryption metadata file path')
            [CompletionResult]::new('--decryption-metadata', '--decryption-metadata', [CompletionResultType]::ParameterName, 'Decryption metadata file path')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('--private-key', '--private-key', [CompletionResultType]::ParameterName, 'MLA private key file. If A creates an archive for B, A uses A''s private key for signing. For reading, B uses B''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('--output', '--output', [CompletionResultType]::ParameterName, 'Output file path. Use - for stdout')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;shared-secret;help' {
            [CompletionResult]::new('get-decryption-metadata', 'get-decryption-metadata', [CompletionResultType]::ParameterValue, 'Get decryption metadata')
            [CompletionResult]::new('decapsulate', 'decapsulate', [CompletionResultType]::ParameterValue, 'Decapsulate metadata to obtain shared secret.')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'mlar;shared-secret;help;get-decryption-metadata' {
            break
        }
        'mlar;shared-secret;help;decapsulate' {
            break
        }
        'mlar;shared-secret;help;help' {
            break
        }
        'mlar;completions' {
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Shell to generate completions for')
            [CompletionResult]::new('--shell', '--shell', [CompletionResultType]::ParameterName, 'Shell to generate completions for')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Increase verbosity level')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'mlar;help' {
            [CompletionResult]::new('create', 'create', [CompletionResultType]::ParameterValue, 'Create a new MLA Archive')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List entries inside a MLA Archive')
            [CompletionResult]::new('extract', 'extract', [CompletionResultType]::ParameterValue, 'Extract entries from a MLA Archive to files')
            [CompletionResult]::new('cat', 'cat', [CompletionResultType]::ParameterValue, 'Display entries from a MLA Archive, like ''cat''')
            [CompletionResult]::new('to-tar', 'to-tar', [CompletionResultType]::ParameterValue, 'Convert a MLA Archive to a TAR Archive')
            [CompletionResult]::new('clean-truncated', 'clean-truncated', [CompletionResultType]::ParameterValue, 'Recover readable data from a truncated archive by creating a new archive. This process discards damaged metadata and skips signature verification.')
            [CompletionResult]::new('convert', 'convert', [CompletionResultType]::ParameterValue, 'Convert a MLA Archive to a fresh new one, with potentially different options')
            [CompletionResult]::new('keygen', 'keygen', [CompletionResultType]::ParameterValue, 'Generate a public/private MLA keypair')
            [CompletionResult]::new('keyderive', 'keyderive', [CompletionResultType]::ParameterValue, 'Advanced use case: Derive a new public/private keypair from an existing one and a public path, see `doc/KEY_DERIVATION.md`')
            [CompletionResult]::new('info', 'info', [CompletionResultType]::ParameterValue, 'Get info on a MLA Archive')
            [CompletionResult]::new('shared-secret', 'shared-secret', [CompletionResultType]::ParameterValue, 'Advanced use case: See Rust documentation of `mla::helpers::shared_secret`.')
            [CompletionResult]::new('completions', 'completions', [CompletionResultType]::ParameterValue, 'Generate shell completion scripts')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'mlar;help;create' {
            break
        }
        'mlar;help;list' {
            break
        }
        'mlar;help;extract' {
            break
        }
        'mlar;help;cat' {
            break
        }
        'mlar;help;to-tar' {
            break
        }
        'mlar;help;clean-truncated' {
            break
        }
        'mlar;help;convert' {
            break
        }
        'mlar;help;keygen' {
            [CompletionResult]::new('public-from-private', 'public-from-private', [CompletionResultType]::ParameterValue, 'Generate public key from private key')
            break
        }
        'mlar;help;keygen;public-from-private' {
            break
        }
        'mlar;help;keyderive' {
            break
        }
        'mlar;help;info' {
            break
        }
        'mlar;help;shared-secret' {
            [CompletionResult]::new('get-decryption-metadata', 'get-decryption-metadata', [CompletionResultType]::ParameterValue, 'Get decryption metadata')
            [CompletionResult]::new('decapsulate', 'decapsulate', [CompletionResultType]::ParameterValue, 'Decapsulate metadata to obtain shared secret.')
            break
        }
        'mlar;help;shared-secret;get-decryption-metadata' {
            break
        }
        'mlar;help;shared-secret;decapsulate' {
            break
        }
        'mlar;help;completions' {
            break
        }
        'mlar;help;help' {
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}

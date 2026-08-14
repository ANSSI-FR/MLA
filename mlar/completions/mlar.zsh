#compdef mlar

autoload -U is-at-least

_mlar() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_mlar_commands" \
"*::: :->mlar" \
&& ret=0
    case $state in
    (mlar)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:mlar-command-$line[1]:"
        case $line[1] in
            (create)
_arguments "${_arguments_options[@]}" : \
'-o+[Output file path. Use - for stdout]: :_files' \
'--output=[Output file path. Use - for stdout]: :_files' \
'-q+[Compression level (0-11); ; bigger values cause denser, but slower compression]: :_default' \
'--compression_level=[Compression level (0-11); ; bigger values cause denser, but slower compression]: :_default' \
'*-k+[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--private-key=[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*-p+[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--public-key=[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'--stdin-data-entry-names=[Comma-separated list of entry names to create with regards to content provided on stdin. Default\: "default-entry".]: :_default' \
'--stdin-data-separator=[Delimiter string used to separate multiple archive entries from stdin. Required if --stdin-data includes multiple entries. Default\: no separator (stdin will thus be treated as a single entry).]: :_default' \
'--uncompressed[Disable compression.]' \
'--unencrypted[Disable encryption.]' \
'--unsigned[Disable signature.]' \
'(--stdin-data --stdin-data-entry-names --stdin-data-separator)--stdin-filepath-list[Add filepaths specified on stdin (one UTF-8 path per line) rather than from positional arguments.]' \
'--stdin-data[Pipe archive entries content from stdin. Can be customized with --stdin-data-entry-names and --stdin-data-separator.]' \
'--skip-not-found[Skip files that are not found instead of failing.]' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
'::files -- Files to add:_files' \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
'-i+[Archive path]: :_files' \
'--input=[Archive path]: :_files' \
'*-k+[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--private-key=[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*-p+[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--public-key=[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--shared-secret=[Advanced use case\: File path to a shared secret. See Rust documentation of \`mla\:\:helpers\:\:shared_secret\`.]: :_files' \
'--accept-unencrypted[Accept to operate on unencrypted archives]' \
'--only-one-key-with-valid-signature-is-ok[If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ]' \
'--skip-signature-verification[Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.]' \
'--raw-escaped-names[Do not try to interpret entry names as paths and encode everything not alphanumeric, dash, underscore or dot]' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(extract)
_arguments "${_arguments_options[@]}" : \
'-i+[Archive path]: :_files' \
'--input=[Archive path]: :_files' \
'*-k+[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--private-key=[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*-p+[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--public-key=[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--shared-secret=[Advanced use case\: File path to a shared secret. See Rust documentation of \`mla\:\:helpers\:\:shared_secret\`.]: :_files' \
'-o+[Output directory where files are extracted]: :_files' \
'--output=[Output directory where files are extracted]: :_files' \
'--accept-unencrypted[Accept to operate on unencrypted archives]' \
'--only-one-key-with-valid-signature-is-ok[If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ]' \
'--skip-signature-verification[Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.]' \
'-g[Treat specified files as glob patterns]' \
'--glob[Treat specified files as glob patterns]' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
'::entries -- List of entries to extract (all if none given):_files' \
&& ret=0
;;
(cat)
_arguments "${_arguments_options[@]}" : \
'-i+[Archive path]: :_files' \
'--input=[Archive path]: :_files' \
'*-k+[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--private-key=[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*-p+[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--public-key=[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--shared-secret=[Advanced use case\: File path to a shared secret. See Rust documentation of \`mla\:\:helpers\:\:shared_secret\`.]: :_files' \
'-o+[Output file]: :_files' \
'--output=[Output file]: :_files' \
'--accept-unencrypted[Accept to operate on unencrypted archives]' \
'--only-one-key-with-valid-signature-is-ok[If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ]' \
'--skip-signature-verification[Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.]' \
'-g[Treat given entries names as glob patterns]' \
'--glob[Treat given entries names as glob patterns]' \
'--raw-escaped-names[With this option, entries names given as positional arguments should be specified as displayed by mlar list with this same option. This lets you see entries that cannot be interpreted as valid path.]' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
':entries -- List of entries to output:_files' \
&& ret=0
;;
(to-tar)
_arguments "${_arguments_options[@]}" : \
'-i+[Archive path]: :_files' \
'--input=[Archive path]: :_files' \
'*-k+[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--private-key=[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*-p+[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--public-key=[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--shared-secret=[Advanced use case\: File path to a shared secret. See Rust documentation of \`mla\:\:helpers\:\:shared_secret\`.]: :_files' \
'-o+[Tar Archive path]: :_files' \
'--output=[Tar Archive path]: :_files' \
'--accept-unencrypted[Accept to operate on unencrypted archives]' \
'--only-one-key-with-valid-signature-is-ok[If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ]' \
'--skip-signature-verification[Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.]' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(clean-truncated)
_arguments "${_arguments_options[@]}" : \
'-i+[Archive path]: :_files' \
'--input=[Archive path]: :_files' \
'-o+[Output file path. Use - for stdout]: :_files' \
'--output=[Output file path. Use - for stdout]: :_files' \
'-q+[Compression level (0-11); ; bigger values cause denser, but slower compression]: :_default' \
'--compression_level=[Compression level (0-11); ; bigger values cause denser, but slower compression]: :_default' \
'*-k+[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--private-key=[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*-p+[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--public-key=[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--shared-secret=[Advanced use case\: File path to a shared secret. See Rust documentation of \`mla\:\:helpers\:\:shared_secret\`.]: :_files' \
'*--out-pub=[MLA public key file for output archive encryption]: :_files' \
'*--out-priv=[MLA private key file for output archive signing]: :_files' \
'--accept-unencrypted[Accept to operate on unencrypted archives]' \
'--only-one-key-with-valid-signature-is-ok[If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ]' \
'--skip-signature-verification[Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.]' \
'--uncompressed[Disable compression.]' \
'--unencrypted[Disable encryption.]' \
'--unsigned[Disable signature.]' \
'--allow-unauthenticated-data[Allow extraction of unauthenticated data from the archive. USE THIS OPTION ONLY IF NECESSARY]' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(convert)
_arguments "${_arguments_options[@]}" : \
'-i+[Archive path]: :_files' \
'--input=[Archive path]: :_files' \
'-o+[Output file path. Use - for stdout]: :_files' \
'--output=[Output file path. Use - for stdout]: :_files' \
'-q+[Compression level (0-11); ; bigger values cause denser, but slower compression]: :_default' \
'--compression_level=[Compression level (0-11); ; bigger values cause denser, but slower compression]: :_default' \
'*-k+[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--private-key=[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*-p+[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--public-key=[MLA public key file. If A creates an archive for B, A uses B'\''s public key for encryption. For reading, B uses A'\''s public key to verify the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--shared-secret=[Advanced use case\: File path to a shared secret. See Rust documentation of \`mla\:\:helpers\:\:shared_secret\`.]: :_files' \
'*--out-pub=[MLA public key file for output archive encryption]: :_files' \
'*--out-priv=[MLA private key file for output archive signing]: :_files' \
'--accept-unencrypted[Accept to operate on unencrypted archives]' \
'--only-one-key-with-valid-signature-is-ok[If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ]' \
'--skip-signature-verification[Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.]' \
'--uncompressed[Disable compression.]' \
'--unencrypted[Disable encryption.]' \
'--unsigned[Disable signature.]' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(keygen)
_arguments "${_arguments_options[@]}" : \
'-s+[Initial seed for deterministic key generation. THE SEED IS AS SECRET AS THE RESULTING PRIVATE KEY. USE THIS OPTION ONLY IF NECESSARY]: :_default' \
'--seed=[Initial seed for deterministic key generation. THE SEED IS AS SECRET AS THE RESULTING PRIVATE KEY. USE THIS OPTION ONLY IF NECESSARY]: :_default' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
'::output-prefix -- Output prefix for the keys. The private key will be in {output-prefix}.mlapriv and the public key will be in {output-prefix}.mlapub:_files' \
":: :_mlar__subcmd__keygen_commands" \
"*::: :->keygen" \
&& ret=0

    case $state in
    (keygen)
        words=($line[2] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:mlar-keygen-command-$line[2]:"
        case $line[2] in
            (public-from-private)
_arguments "${_arguments_options[@]}" : \
'-o+[Output public key file (.mlapub). If omitted, the path is derived from the input filename]: :_files' \
'--output=[Output public key file (.mlapub). If omitted, the path is derived from the input filename]: :_files' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
':input -- Input private key file or prefix (e.g. '\''key.mlapriv'\'' or '\''key'\'' will read key.mlapriv):_files' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_mlar__subcmd__keygen__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:mlar-keygen-help-command-$line[1]:"
        case $line[1] in
            (public-from-private)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(keyderive)
_arguments "${_arguments_options[@]}" : \
'*-p+[Public derivation path, can be specified multiple times]: :_default' \
'*--path-component=[Public derivation path, can be specified multiple times]: :_default' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
':input -- Input private key file:_files' \
':output-prefix -- Output prefix for the keys. The private key will be in {output}.mlapriv and the public key will be in {output}.mlapub:_files' \
&& ret=0
;;
(info)
_arguments "${_arguments_options[@]}" : \
'-i+[Archive path]: :_files' \
'--input=[Archive path]: :_files' \
'--accept-unencrypted[Accept to operate on unencrypted archives]' \
'--only-one-key-with-valid-signature-is-ok[If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ]' \
'--skip-signature-verification[Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.]' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(shared-secret)
_arguments "${_arguments_options[@]}" : \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
":: :_mlar__subcmd__shared-secret_commands" \
"*::: :->shared-secret" \
&& ret=0

    case $state in
    (shared-secret)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:mlar-shared-secret-command-$line[1]:"
        case $line[1] in
            (get-decryption-metadata)
_arguments "${_arguments_options[@]}" : \
'-i+[Archive path]: :_files' \
'--input=[Archive path]: :_files' \
'-o+[Output file path. Use - for stdout]: :_files' \
'--output=[Output file path. Use - for stdout]: :_files' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(decapsulate)
_arguments "${_arguments_options[@]}" : \
'-m+[Decryption metadata file path]: :_files' \
'--decryption-metadata=[Decryption metadata file path]: :_files' \
'*-k+[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'*--private-key=[MLA private key file. If A creates an archive for B, A uses A'\''s private key for signing. For reading, B uses B'\''s private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.]: :_files' \
'-o+[Output file path. Use - for stdout]: :_files' \
'--output=[Output file path. Use - for stdout]: :_files' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_mlar__subcmd__shared-secret__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:mlar-shared-secret-help-command-$line[1]:"
        case $line[1] in
            (get-decryption-metadata)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(decapsulate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(completions)
_arguments "${_arguments_options[@]}" : \
'-s+[Shell to generate completions for]: :(bash zsh fish elvish powershell)' \
'--shell=[Shell to generate completions for]: :(bash zsh fish elvish powershell)' \
'*-v[Increase verbosity level]' \
'*--verbose[Increase verbosity level]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_mlar__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:mlar-help-command-$line[1]:"
        case $line[1] in
            (create)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(extract)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(cat)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(to-tar)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(clean-truncated)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(convert)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(keygen)
_arguments "${_arguments_options[@]}" : \
":: :_mlar__subcmd__help__subcmd__keygen_commands" \
"*::: :->keygen" \
&& ret=0

    case $state in
    (keygen)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:mlar-help-keygen-command-$line[1]:"
        case $line[1] in
            (public-from-private)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(keyderive)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(info)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(shared-secret)
_arguments "${_arguments_options[@]}" : \
":: :_mlar__subcmd__help__subcmd__shared-secret_commands" \
"*::: :->shared-secret" \
&& ret=0

    case $state in
    (shared-secret)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:mlar-help-shared-secret-command-$line[1]:"
        case $line[1] in
            (get-decryption-metadata)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(decapsulate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(completions)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_mlar_commands] )) ||
_mlar_commands() {
    local commands; commands=(
'create:Create a new MLA Archive' \
'list:List entries inside a MLA Archive' \
'extract:Extract entries from a MLA Archive to files' \
'cat:Display entries from a MLA Archive, like '\''cat'\''' \
'to-tar:Convert a MLA Archive to a TAR Archive' \
'clean-truncated:Recover readable data from a truncated archive by creating a new archive. This process discards damaged metadata and skips signature verification.' \
'convert:Convert a MLA Archive to a fresh new one, with potentially different options' \
'keygen:Generate a public/private MLA keypair' \
'keyderive:Advanced use case\: Derive a new public/private keypair from an existing one and a public path, see \`doc/KEY_DERIVATION.md\`' \
'info:Get info on a MLA Archive' \
'shared-secret:Advanced use case\: See Rust documentation of \`mla\:\:helpers\:\:shared_secret\`.' \
'completions:Generate shell completion scripts' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'mlar commands' commands "$@"
}
(( $+functions[_mlar__subcmd__cat_commands] )) ||
_mlar__subcmd__cat_commands() {
    local commands; commands=()
    _describe -t commands 'mlar cat commands' commands "$@"
}
(( $+functions[_mlar__subcmd__clean-truncated_commands] )) ||
_mlar__subcmd__clean-truncated_commands() {
    local commands; commands=()
    _describe -t commands 'mlar clean-truncated commands' commands "$@"
}
(( $+functions[_mlar__subcmd__completions_commands] )) ||
_mlar__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'mlar completions commands' commands "$@"
}
(( $+functions[_mlar__subcmd__convert_commands] )) ||
_mlar__subcmd__convert_commands() {
    local commands; commands=()
    _describe -t commands 'mlar convert commands' commands "$@"
}
(( $+functions[_mlar__subcmd__create_commands] )) ||
_mlar__subcmd__create_commands() {
    local commands; commands=()
    _describe -t commands 'mlar create commands' commands "$@"
}
(( $+functions[_mlar__subcmd__extract_commands] )) ||
_mlar__subcmd__extract_commands() {
    local commands; commands=()
    _describe -t commands 'mlar extract commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help_commands] )) ||
_mlar__subcmd__help_commands() {
    local commands; commands=(
'create:Create a new MLA Archive' \
'list:List entries inside a MLA Archive' \
'extract:Extract entries from a MLA Archive to files' \
'cat:Display entries from a MLA Archive, like '\''cat'\''' \
'to-tar:Convert a MLA Archive to a TAR Archive' \
'clean-truncated:Recover readable data from a truncated archive by creating a new archive. This process discards damaged metadata and skips signature verification.' \
'convert:Convert a MLA Archive to a fresh new one, with potentially different options' \
'keygen:Generate a public/private MLA keypair' \
'keyderive:Advanced use case\: Derive a new public/private keypair from an existing one and a public path, see \`doc/KEY_DERIVATION.md\`' \
'info:Get info on a MLA Archive' \
'shared-secret:Advanced use case\: See Rust documentation of \`mla\:\:helpers\:\:shared_secret\`.' \
'completions:Generate shell completion scripts' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'mlar help commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__cat_commands] )) ||
_mlar__subcmd__help__subcmd__cat_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help cat commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__clean-truncated_commands] )) ||
_mlar__subcmd__help__subcmd__clean-truncated_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help clean-truncated commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__completions_commands] )) ||
_mlar__subcmd__help__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help completions commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__convert_commands] )) ||
_mlar__subcmd__help__subcmd__convert_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help convert commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__create_commands] )) ||
_mlar__subcmd__help__subcmd__create_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help create commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__extract_commands] )) ||
_mlar__subcmd__help__subcmd__extract_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help extract commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__help_commands] )) ||
_mlar__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help help commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__info_commands] )) ||
_mlar__subcmd__help__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help info commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__keyderive_commands] )) ||
_mlar__subcmd__help__subcmd__keyderive_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help keyderive commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__keygen_commands] )) ||
_mlar__subcmd__help__subcmd__keygen_commands() {
    local commands; commands=(
'public-from-private:Generate public key from private key' \
    )
    _describe -t commands 'mlar help keygen commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__keygen__subcmd__public-from-private_commands] )) ||
_mlar__subcmd__help__subcmd__keygen__subcmd__public-from-private_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help keygen public-from-private commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__list_commands] )) ||
_mlar__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help list commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__shared-secret_commands] )) ||
_mlar__subcmd__help__subcmd__shared-secret_commands() {
    local commands; commands=(
'get-decryption-metadata:Get decryption metadata' \
'decapsulate:Decapsulate metadata to obtain shared secret.' \
    )
    _describe -t commands 'mlar help shared-secret commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__shared-secret__subcmd__decapsulate_commands] )) ||
_mlar__subcmd__help__subcmd__shared-secret__subcmd__decapsulate_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help shared-secret decapsulate commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__shared-secret__subcmd__get-decryption-metadata_commands] )) ||
_mlar__subcmd__help__subcmd__shared-secret__subcmd__get-decryption-metadata_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help shared-secret get-decryption-metadata commands' commands "$@"
}
(( $+functions[_mlar__subcmd__help__subcmd__to-tar_commands] )) ||
_mlar__subcmd__help__subcmd__to-tar_commands() {
    local commands; commands=()
    _describe -t commands 'mlar help to-tar commands' commands "$@"
}
(( $+functions[_mlar__subcmd__info_commands] )) ||
_mlar__subcmd__info_commands() {
    local commands; commands=()
    _describe -t commands 'mlar info commands' commands "$@"
}
(( $+functions[_mlar__subcmd__keyderive_commands] )) ||
_mlar__subcmd__keyderive_commands() {
    local commands; commands=()
    _describe -t commands 'mlar keyderive commands' commands "$@"
}
(( $+functions[_mlar__subcmd__keygen_commands] )) ||
_mlar__subcmd__keygen_commands() {
    local commands; commands=(
'public-from-private:Generate public key from private key' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'mlar keygen commands' commands "$@"
}
(( $+functions[_mlar__subcmd__keygen__subcmd__help_commands] )) ||
_mlar__subcmd__keygen__subcmd__help_commands() {
    local commands; commands=(
'public-from-private:Generate public key from private key' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'mlar keygen help commands' commands "$@"
}
(( $+functions[_mlar__subcmd__keygen__subcmd__help__subcmd__help_commands] )) ||
_mlar__subcmd__keygen__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'mlar keygen help help commands' commands "$@"
}
(( $+functions[_mlar__subcmd__keygen__subcmd__help__subcmd__public-from-private_commands] )) ||
_mlar__subcmd__keygen__subcmd__help__subcmd__public-from-private_commands() {
    local commands; commands=()
    _describe -t commands 'mlar keygen help public-from-private commands' commands "$@"
}
(( $+functions[_mlar__subcmd__keygen__subcmd__public-from-private_commands] )) ||
_mlar__subcmd__keygen__subcmd__public-from-private_commands() {
    local commands; commands=()
    _describe -t commands 'mlar keygen public-from-private commands' commands "$@"
}
(( $+functions[_mlar__subcmd__list_commands] )) ||
_mlar__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'mlar list commands' commands "$@"
}
(( $+functions[_mlar__subcmd__shared-secret_commands] )) ||
_mlar__subcmd__shared-secret_commands() {
    local commands; commands=(
'get-decryption-metadata:Get decryption metadata' \
'decapsulate:Decapsulate metadata to obtain shared secret.' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'mlar shared-secret commands' commands "$@"
}
(( $+functions[_mlar__subcmd__shared-secret__subcmd__decapsulate_commands] )) ||
_mlar__subcmd__shared-secret__subcmd__decapsulate_commands() {
    local commands; commands=()
    _describe -t commands 'mlar shared-secret decapsulate commands' commands "$@"
}
(( $+functions[_mlar__subcmd__shared-secret__subcmd__get-decryption-metadata_commands] )) ||
_mlar__subcmd__shared-secret__subcmd__get-decryption-metadata_commands() {
    local commands; commands=()
    _describe -t commands 'mlar shared-secret get-decryption-metadata commands' commands "$@"
}
(( $+functions[_mlar__subcmd__shared-secret__subcmd__help_commands] )) ||
_mlar__subcmd__shared-secret__subcmd__help_commands() {
    local commands; commands=(
'get-decryption-metadata:Get decryption metadata' \
'decapsulate:Decapsulate metadata to obtain shared secret.' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'mlar shared-secret help commands' commands "$@"
}
(( $+functions[_mlar__subcmd__shared-secret__subcmd__help__subcmd__decapsulate_commands] )) ||
_mlar__subcmd__shared-secret__subcmd__help__subcmd__decapsulate_commands() {
    local commands; commands=()
    _describe -t commands 'mlar shared-secret help decapsulate commands' commands "$@"
}
(( $+functions[_mlar__subcmd__shared-secret__subcmd__help__subcmd__get-decryption-metadata_commands] )) ||
_mlar__subcmd__shared-secret__subcmd__help__subcmd__get-decryption-metadata_commands() {
    local commands; commands=()
    _describe -t commands 'mlar shared-secret help get-decryption-metadata commands' commands "$@"
}
(( $+functions[_mlar__subcmd__shared-secret__subcmd__help__subcmd__help_commands] )) ||
_mlar__subcmd__shared-secret__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'mlar shared-secret help help commands' commands "$@"
}
(( $+functions[_mlar__subcmd__to-tar_commands] )) ||
_mlar__subcmd__to-tar_commands() {
    local commands; commands=()
    _describe -t commands 'mlar to-tar commands' commands "$@"
}

if [ "$funcstack[1]" = "_mlar" ]; then
    _mlar "$@"
else
    compdef _mlar mlar
fi

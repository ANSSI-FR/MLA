Entry name documentation
=

An archive can store entries associated with a name. These entries may or may
not represent OS filesystem files. And their name may or may not represent an
OS file system path.

An entry name is a nonempty sequence of bytes (maximum length of 65536).

Please keep in mind that names, interpreted as paths or not, may contain
arbitrary bytes such as slashes, backslashes, `..`, `C:\\{}...]`, newlines, spaces,
carriage returns, terminal escape sequences, Unicode chars such as U+0085 or RTLO,
HTML, SQL, semicolons, homoglyphs, etc.

## Interpretation of an entry name as an OS filesystem file path

If it is to be interpreted as a file path, the underlying bytes must consist of
ASCII slash separated components and not begin with a slash.
The rules for each component are:
* must not be empty
* must not contain any ASCII NUL byte
* must not be ASCII dot
* must not be two ASCII dots

If it is to be interpreted as a Windows file path, in addition to previous rules:
* No byte should be an ASCII backslash (separators are represented by an ASCII slash).
* Byte values strictly below 32 (non-printable control characters) are forbidden. Additionally, the following ASCII values are forbidden: 34 (`"`), 42 (`*`), 58 (`:`), 60 (`<`), 62 (`>`), 63 (`?`), and 124 (`|`).
* Every component must be encoded as UTF-8.

These rules are checked by the accompanying Rust implementation (`EntryName::to_pathbuf`).

Even if respecting these rules, the OS may see the resulting path as invalid.

Please keep in mind that two different names, may map to same path on OS
(e.g. Windows case insensitivity).

In provided rust implementation, when given a path as input, before being
converted to an entry name by `EntryName::from_path` and `mlar` the path is
normalized by keeping only `Normal` `std::path::Component`s and popping an
eventual previous component when a `..` is encountered.

## String representation of entry names

To prevent some security risks, proposed string representations of entry names
are given with `EntryName::to_pathbuf_escaped_string` and
`EntryName::raw_content_to_escaped_string` and are used by `mlar`.

Other representations may be preferred depending on their usage context.

The idea of this representation is that unwanted bytes are replaced with a
percent and their hexadecimal representation. Details follow.

For an entry name interpreted as raw bytes, below generic escaping is applied
with ASCII alphanumeric, dot, dash and underscore as preserved bytes. This is used by
`mlar list --raw-escaped-names`.

For an entry name interpreted as a path, below generic escaping is applied
with ASCII alphanumeric chars, dot, dash, underscore and slash as preserved bytes.
This is used by default by `mlar list`.

### Generic escaping, implemented by `helpers::mla_percent_escape`

A `bytes_to_preserve` parameter tells which bytes are not escaped.
For every input byte:
* If listed in `bytes_to_preserve` then it will be output without transformation.
* Else, it will be replaced by `%xx` where `xx` is their hexadecimal representation.

### Generic unescaping, implemented by `helpers::mla_percent_unescape`

A `bytes_to_allow` parameter tells which bytes are not escaped.
Unescaping fails if fed with anything else than bytes listed in
`bytes_to_allow` and `%xx` where `xx` is the hexadecimal representation of a
byte not listed in `bytes_to_allow`. Otherwise it reverses the process described
in `Generic escaping`.

### Examples

For each following entry name found serialized in an archive, here is how they are represented as strings when interpreted as path:
* empty bytes -> invalid (even interpreted as arbitrary bytes)
* /a -> invalid path (root directory)
* a/b/../d -> invalid path (path traversal)
* a/b/.. -> invalid path (path traversal)
* a//b -> invalid path (not normalized)
* a/./b -> invalid path (not normalized)
* ./b -> invalid path (not normalized)
* a/. -> invalid path (not normalized)
* aNULb (where NUL here represent an ASCII NUL byte) -> invalid path
* m:abcd -> invalid path on Windows (`:` as second byte), m%3aabcd on UNIX-like
* a\b (where `\` represents an ASCII backslash, not an escaped b) -> invalid path on Windows (contains backslash), a%5cb on UNIX-like
* a/b.txt -> a/b.txt
* a/b!c -> a/b%21c

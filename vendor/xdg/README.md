# rust-xdg

[![CI](https://github.com/whitequark/rust-xdg/actions/workflows/ci.yml/badge.svg)](https://github.com/whitequark/rust-xdg/actions/workflows/ci.yml)
[![Documentation](https://github.com/whitequark/rust-xdg/actions/workflows/docs.yml/badge.svg)](https://github.com/whitequark/rust-xdg/actions/workflows/docs.yml)
![Crates.io Version](https://img.shields.io/crates/v/xdg?color=%23a55e08&link=https%3A%2F%2Fcrates.io%2Fcrates%2Fxdg)
![rustc version](https://img.shields.io/badge/msrv-1.60.0-lightgray.svg)


rust-xdg is a library that makes it easy to follow the X Desktop Group
specifications.

Currently, only [XDG Base Directory][basedir] specification is implemented.

[basedir]: http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html

## Installation

Add the following to `Cargo.toml`:

```toml
[dependencies]
xdg = "^2.6"
```

## Examples

See [documentation](https://whitequark.github.io/rust-xdg/xdg/).

## License

**rust-xdg** is distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT)
for details.

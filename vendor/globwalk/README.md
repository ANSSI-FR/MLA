# GlobWalk #

[![](https://docs.rs/globwalk/badge.svg)](https://docs.rs/globwalk/)
![License](https://img.shields.io/crates/l/globwalk.svg)
[![crates.io](https://img.shields.io/crates/v/globwalk.svg)](https://crates.io/crates/globwalk)

Recursively find files in a directory using globs.

This crate is now in a perpetual maintnance mode and new users should probably cosider using [`glob`](https://crates.io/crates/glob/).

### Comparison to the `glob` crate ###

This crate was origially written years ago, when [`glob`](https://crates.io/crates/glob/) was a very differet crate,
before it was adopted by the rust-lang org.

Nowadays `glob` is much better, and overall better maintained,
but there are a few features that it does not seem to have (based on [glob 0.3.1](https://docs.rs/glob/0.3.1/src/glob/lib.rs.html#466)):

 - The `glob` crate does not support having `{a,b}` in patterns.
 - `globwalk` can match several glob-patterns at the same time.
 - `globwalk` supports excluding results with `!`. (negative patterns)
 - `glob` searches for files in the current working directory, whereas `globwalk` starts at a specified base-dir.

### Usage ###

To use this crate, add `globwalk` as a dependency to your project's `Cargo.toml`:

```toml
[dependencies]
globwalk = "0.9.1"
```

The following piece of code recursively find all `png`, `jpg`, or `gif` files:

```rust
extern crate globwalk;

use std::fs;

for img in globwalk::glob("*.{png,jpg,gif}").unwrap() {
    if let Ok(img) = img {
        println!("{:?}", img.path());
    }
}
```

See the [documentation](https://docs.rs/globwalk/) for more details.

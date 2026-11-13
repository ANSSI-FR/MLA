#![no_std]
/*!
# **Humansize**

## Features
Humansize is a humanization library for information size that is:
- Simple & convenient to use
- Customizable
- Supports byte or bit sizes
- `no-std`
- Optionally non-allocating
- Optionally accepts signed values

## How to use it...

Add humansize as a dependency to your project's `cargo.toml`:
```toml
[dependencies]
...
humansize = "2.0.0"
```

### ... to easily format a size:

1. Import the `format_size` function as well as your preferred set of defaults:
    - `DECIMAL` (SI)
    - `BINARY` (IEC)
    - `WINDOWS` (IEC values but SI units)
2. Call `format_size` with an unsigned integer

```rust
use humansize::{format_size, DECIMAL};

let size = 1_000_000u64;
let res: String = format_size(size, DECIMAL);

assert_eq!(&res, "1 MB");

```

### ... to format many sizes:
To improve reusability, you can use `create_format`, which returns a formatter function akin to `format_size` but with the options argument curried so it doesn't need to be specified again:

```rust
use humansize::{make_format, DECIMAL};

let formatter = make_format(DECIMAL);

assert_eq!(formatter(1_000_000u64), "1 MB");
assert_eq!(formatter(1_000_000_000u64), "1 GB");
//...

```

### ... to avoid allocation:
Specify the `no_alloc` feature flag in your project's `cargo.toml`:
```toml
[dependencies]
...
humansize = { version = "2.0.0", features = ["no_alloc"] }
```
This excludes all allocating code from compilation. You may now use the library's internal `SizeFormatter` struct, which implements `core::fmt::display` so that you can `write!` it to a custom buffer of your choice:
```rust
use humansize::{SizeFormatter, DECIMAL};

let formatter = SizeFormatter::new(1_000_000usize, DECIMAL);
assert_eq!(format!("{}", formatter), "1 MB");
```
### ... with the `impl` style API:
For stylistic reasons, you may prefer to use the impl-style API of earlier versions of the crate.
To do so, specify the `impl-style` feature flag in your project's `cargo.toml`:

```toml
[dependencies]
...
humansize = { version = "2.0.0", features = ["impl_style"] }
```
Enabling this feature makes two methods available:
- `format_size` on unsigned integers types
- `format_size_i` on signed integer types.

To use it, bring the FormatSize trait into scope and call its method on an integer type:
```ignore
use humansize::{FormatSize, FormatSizeI DECIMAL};

assert_eq!(1_000_000u64.format_size(DECIMAL), "1 MB");
assert_eq!((-1_000_000).format_size_i(DECIMAL), "-1 MB");
```
### ... to further customize the output:
Humansize exports three default option sets:
* `Decimal`: kilo = 1000, unit format is `XB`.
* `Binary`: kilo = 1024, unit format is `XiB`.
* `WINDOWS` (Windows): kilo = 1024, unit format is `XB`.

The formatting can be further customized by providing providing your own option set. See the documentation of the `FormatSizeOptions` struct to see all the addressable parameters, and [this example](examples/custom_options.rs) for its usage.

### ... to accept negative values:
The solutions presented above only accept unsigned integer types as input (`usize`, `8`, `u16`, `u32` and `u64`). If however accepting negative values is correct for your application, a signed alternative exists for each of them that will accept signed integer types, and format them accordingly if negative:

- `format_size` : `format_size_i`
- `create_format` : `create_format_i`
- `FormatSize` trait : `FormatSizeI` trait
- `SizeFormatter` : `ISizeFormatter`
```rust
use humansize::{format_size_i, make_format_i, ISizeFormatter, DECIMAL};

assert_eq!(&format_size_i(-1_000_000, DECIMAL), "-1 MB");

let signed_formatter = make_format_i(DECIMAL);
assert_eq!(&signed_formatter(-1_000_000), "-1 MB");

// With the `impl-style` feature enabled:
// use humansize::FormatSizeI;
// assert_eq(-1_000_000.format_size(DECIMAL), "-1 MB");

let signed_size_formatter = ISizeFormatter::new(-1_000_000, DECIMAL);
assert_eq!(format!("{}", signed_size_formatter), "-1 MB");

```
*/

#[macro_use]
#[cfg(not(feature = "no_alloc"))]
extern crate alloc;
extern crate libm;

mod options;
pub use options::{BaseUnit, FixedAt, FormatSizeOptions, Kilo, BINARY, DECIMAL, WINDOWS};

mod numeric_traits;
pub use numeric_traits::{Signed, ToF64, Unsigned};

mod scales;
mod utils;

#[cfg(not(feature = "no_alloc"))]
mod allocating;
#[cfg(not(feature = "no_alloc"))]
pub use allocating::*;

#[cfg(feature = "impl_style")]
mod impl_style;
#[cfg(feature = "impl_style")]
pub use impl_style::{FormatSize, FormatSizeI};

mod formatters;
pub use formatters::{SizeFormatter, ISizeFormatter};

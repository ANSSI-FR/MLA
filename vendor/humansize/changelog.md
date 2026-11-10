# Changelog
Dates are DD-MM-YYYY

## [2.1.1] 16-11-2022
- Added changelog
- `Impl` `ToF64` for `f32` and `f64` so they can be used as inputs to the signed variants of the crate's utilities
- Manually implement the `Default` trait for enums to lower the Minimum Supported Rust Version to 1.56. Thanks @link2txt
- Added MSRV to cargo.toml. Thanks @link2txt
- Added maintenance level badge
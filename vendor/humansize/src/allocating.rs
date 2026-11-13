use alloc::string::String;

use crate::numeric_traits::*;
use crate::options::FormatSizeOptions;
use crate::ISizeFormatter;

pub fn format_size_i(input: impl ToF64, options: impl AsRef<FormatSizeOptions>) -> String {
    format!("{}", ISizeFormatter::new(input, options))
}

pub fn format_size(input: impl ToF64 + Unsigned, options: impl AsRef<FormatSizeOptions>) -> String {
    format_size_i(input, &options)
}

pub fn make_format_i<T: ToF64>(options: impl AsRef<FormatSizeOptions>) -> impl Fn(T) -> String {
    move |val| -> String { format_size_i(val, &options) }
}

pub fn make_format<T: ToF64 + Unsigned>(
    options: impl AsRef<FormatSizeOptions>,
) -> impl Fn(T) -> String {
    make_format_i(options)
}

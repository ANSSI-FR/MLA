use crate::{FormatSizeOptions, SizeFormatter, ISizeFormatter, Signed, ToF64, Unsigned};
use alloc::string::String;

pub trait FormatSize<T> {
    fn format_size(&self, opts: FormatSizeOptions) -> String;
}

pub trait FormatSizeI<T> {
    fn format_size_i(&self, opts: FormatSizeOptions) -> String;
}

impl<T: ToF64 + Unsigned + Copy> FormatSize<T> for T {
    fn format_size(&self, opts: FormatSizeOptions) -> String {
        format!("{}", SizeFormatter::new(*self, opts))
    }
}

impl<T: ToF64 + Signed + Copy> FormatSizeI<T> for T {
    fn format_size_i(&self, opts: FormatSizeOptions) -> String {
        format!("{}", ISizeFormatter::new(*self, opts))
    }
}

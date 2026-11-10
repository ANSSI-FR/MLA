use libm::{fabs, modf};

use crate::{scales, utils::f64_eq, BaseUnit, FormatSizeOptions, Kilo, ToF64, Unsigned};

pub struct ISizeFormatter<T: ToF64, O: AsRef<FormatSizeOptions>> {
    value: T,
    options: O,
}

impl<V: ToF64, O: AsRef<FormatSizeOptions>> ISizeFormatter<V, O> {
    pub fn new(value: V, options: O) -> Self {
        ISizeFormatter { value, options }
    }
}

impl<T: ToF64, O: AsRef<FormatSizeOptions>> core::fmt::Display for ISizeFormatter<T, O> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let opts = self.options.as_ref();
        let divider = opts.kilo.value();

        let mut size: f64 = self.value.to_f64();
        let mut scale_idx = 0;

        if let Some(val) = opts.fixed_at {
            while scale_idx != val as usize {
                size /= divider;
                scale_idx += 1;
            }
        } else {
            while fabs(size) >= divider {
                size /= divider;
                scale_idx += 1;
            }
        }

        let mut scale = match (opts.units, opts.long_units, opts.base_unit) {
            (Kilo::Decimal, false, BaseUnit::Byte) => scales::SCALE_DECIMAL[scale_idx],
            (Kilo::Decimal, true, BaseUnit::Byte) => scales::SCALE_DECIMAL_LONG[scale_idx],
            (Kilo::Binary, false, BaseUnit::Byte) => scales::SCALE_BINARY[scale_idx],
            (Kilo::Binary, true, BaseUnit::Byte) => scales::SCALE_BINARY_LONG[scale_idx],
            (Kilo::Decimal, false, BaseUnit::Bit) => scales::SCALE_DECIMAL_BIT[scale_idx],
            (Kilo::Decimal, true, BaseUnit::Bit) => scales::SCALE_DECIMAL_BIT_LONG[scale_idx],
            (Kilo::Binary, false, BaseUnit::Bit) => scales::SCALE_BINARY_BIT[scale_idx],
            (Kilo::Binary, true, BaseUnit::Bit) => scales::SCALE_BINARY_BIT_LONG[scale_idx],
        };

        // Remove "s" from the scale if the size is 1.x
        let (fpart, ipart) = modf(size);
        if f64_eq(ipart, 1.0)
            && (opts.long_units || (opts.base_unit == BaseUnit::Bit && scale_idx == 0))
        {
            scale = &scale[0..scale.len() - 1];
        }

        let places = if f64_eq(fpart, 0.0) {
            opts.decimal_zeroes
        } else {
            opts.decimal_places
        };

        let space = if opts.space_after_value { " " } else { "" };

        write!(f, "{:.*}{}{}{}", places, size, space, scale, opts.suffix)
    }
}

impl<'a, U: ToF64 + Unsigned + Copy, O: AsRef<FormatSizeOptions>> From<&'a SizeFormatter<U, O>>
    for ISizeFormatter<U, &'a O>
{
    fn from(source: &'a SizeFormatter<U, O>) -> Self {
        ISizeFormatter {
            value: source.value,
            options: &source.options,
        }
    }
}

pub struct SizeFormatter<T: ToF64 + Unsigned, O: AsRef<FormatSizeOptions>> {
    value: T,
    options: O,
}

impl<V: ToF64 + Unsigned, O: AsRef<FormatSizeOptions>> SizeFormatter<V, O> {
    pub fn new(value: V, options: O) -> Self {
        SizeFormatter { value, options }
    }
}

impl<T: ToF64 + Unsigned + Copy, O: AsRef<FormatSizeOptions> + Copy> core::fmt::Display
    for SizeFormatter<T, O>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", ISizeFormatter::from(self))
    }
}

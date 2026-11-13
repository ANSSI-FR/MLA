//! Describes the struct that holds the options needed by the formatting functions.
//! The three most common formats are provided as constants to be used easily

mod defaults;
pub use self::defaults::*;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// Holds the standard to use when displaying the size.
pub enum Kilo {
    /// The decimal scale and units. SI standard.
    Decimal,
    /// The binary scale and units.
    Binary,
}

impl Default for Kilo {
    fn default() -> Self {
        Self::Decimal
    }
}

impl Kilo {
    pub(crate) fn value(&self) -> f64 {
        match self {
            Kilo::Decimal => 1000.0,
            Kilo::Binary => 1024.0,
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Forces a certain representation of the resulting file size.
pub enum FixedAt {
    Base,
    Kilo,
    Mega,
    Giga,
    Tera,
    Peta,
    Exa,
    Zetta,
    Yotta,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BaseUnit {
    Bit,
    Byte,
}

impl Default for BaseUnit {
    fn default() -> Self {
        Self::Byte
    }
}

/// Holds the options for the `file_size` method.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct FormatSizeOptionsBuilder {
    /// Whether the value being formatted represents an amount of bits or bytes.
    pub base_unit: BaseUnit,

    /// The scale (binary/decimal) to divide against.
    pub kilo: Kilo,

    /// The unit set to display.
    pub units: Kilo,

    /// The amount of decimal places to display if the decimal part is non-zero.
    pub decimal_places: usize,

    /// The amount of zeroes to display if the decimal part is zero.
    pub decimal_zeroes: usize,

    /// Whether to force a certain representation and if so, which one.
    pub fixed_at: Option<FixedAt>,

    /// Whether to use the full unit (e.g. `Kilobyte`) or its abbreviation (`kB`).
    pub long_units: bool,

    /// Whether to place a space between value and units.
    pub space_after_value: bool,

    /// An optional suffix which will be appended after the unit. Useful to represent speeds (e.g. `1 kB/s)
    pub suffix: &'static str,
}

/// Holds the options for the `file_size` method.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct FormatSizeOptions {
    /// Whether the value being formatted represents an amount of bits or bytes.
    pub base_unit: BaseUnit,

    /// The scale (binary/decimal) to divide against.
    pub kilo: Kilo,

    /// The unit set to display.
    pub units: Kilo,

    /// The amount of decimal places to display if the decimal part is non-zero.
    pub decimal_places: usize,

    /// The amount of zeroes to display if the decimal part is zero.
    pub decimal_zeroes: usize,

    /// Whether to force a certain representation and if so, which one.
    pub fixed_at: Option<FixedAt>,

    /// Whether to use the full unit (e.g. `Kilobyte`) or its abbreviation (`kB`).
    pub long_units: bool,

    /// Whether to place a space between value and units.
    pub space_after_value: bool,

    /// An optional suffix which will be appended after the unit. Useful to represent speeds (e.g. `1 kB/s)
    pub suffix: &'static str,
}

impl FormatSizeOptions {
    pub fn from(from: FormatSizeOptions) -> FormatSizeOptions {
        FormatSizeOptions { ..from }
    }

    pub fn base_unit(mut self, base_unit: BaseUnit) -> FormatSizeOptions {
        self.base_unit = base_unit;
        self
    }

    pub fn kilo(mut self, kilo: Kilo) -> FormatSizeOptions {
        self.kilo = kilo;
        self
    }

    pub fn units(mut self, units: Kilo) -> FormatSizeOptions {
        self.units = units;
        self
    }

    pub fn decimal_places(mut self, decimal_places: usize) -> FormatSizeOptions {
        self.decimal_places = decimal_places;
        self
    }

    pub fn decimal_zeroes(mut self, decimal_zeroes: usize) -> FormatSizeOptions {
        self.decimal_zeroes = decimal_zeroes;
        self
    }

    pub fn fixed_at(mut self, fixed_at: Option<FixedAt>) -> FormatSizeOptions {
        self.fixed_at = fixed_at;
        self
    }

    pub fn long_units(mut self, long_units: bool) -> FormatSizeOptions {
        self.long_units = long_units;
        self
    }

    pub fn space_after_value(mut self, insert_space: bool) -> FormatSizeOptions {
        self.space_after_value = insert_space;
        self
    }

    pub fn suffix(mut self, suffix: &'static str) -> FormatSizeOptions {
        self.suffix = suffix;
        self
    }
}

impl AsRef<FormatSizeOptions> for FormatSizeOptions {
    fn as_ref(&self) -> &FormatSizeOptions {
        self
    }
}

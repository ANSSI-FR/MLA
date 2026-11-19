use super::{BaseUnit, FormatSizeOptions, Kilo};

/// Options to display sizes in the SI format.
pub const BINARY: FormatSizeOptions = FormatSizeOptions {
    base_unit: BaseUnit::Byte,
    kilo: Kilo::Binary,
    units: Kilo::Binary,
    decimal_places: 2,
    decimal_zeroes: 0,
    fixed_at: None,
    long_units: false,
    space_after_value: true,
    suffix: "",
};

/// Options to display sizes in the SI (decimal) format.
pub const DECIMAL: FormatSizeOptions = FormatSizeOptions {
    base_unit: BaseUnit::Byte,
    kilo: Kilo::Decimal,
    units: Kilo::Decimal,
    decimal_places: 2,
    decimal_zeroes: 0,
    fixed_at: None,
    long_units: false,
    space_after_value: true,
    suffix: "",
};

/// Options to display sizes in the "WINDOWS" format.
/// Uses 1024 as the value of the `Kilo`, but displays decimal-style units (`kB`, not `KiB`).
pub const WINDOWS: FormatSizeOptions = FormatSizeOptions {
    base_unit: BaseUnit::Byte,
    kilo: Kilo::Binary,
    units: Kilo::Decimal,
    decimal_places: 2,
    decimal_zeroes: 0,
    fixed_at: None,
    long_units: false,
    space_after_value: true,
    suffix: "",
};

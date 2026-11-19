pub trait ToF64 {
    fn to_f64(&self) -> f64;
}

macro_rules! impl_to_f64 {
  (for $($t:ty)*) => ($(
      impl ToF64 for $t {
          fn to_f64(&self) -> f64 {
              *self as f64
          }
      }
  )*)
}

impl_to_f64!(for usize u8 u16 u32 u64 isize i8 i16 i32 i64 f32 f64);

pub trait Unsigned {}

macro_rules! impl_unsigned {
  (for $($t:ty)*) => ($(
      impl Unsigned for $t {}
  )*)
}

impl_unsigned!(for usize u8 u16 u32 u64);

pub trait Signed {}

macro_rules! impl_unsigned {
  (for $($t:ty)*) => ($(
      impl Signed for $t {}
  )*)
}

impl_unsigned!(for isize i8 i16 i32 i64);

use libm::fabs;

pub(crate) fn f64_eq(left: f64, right: f64) -> bool {
    left == right || fabs(left - right) <= f64::EPSILON
}

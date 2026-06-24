#![no_main]

use libfuzzer_sys::fuzz_target;
use mla_fuzz::run;

fuzz_target!(|data: &[u8]| {
    run(data);
});

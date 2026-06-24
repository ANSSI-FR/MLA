#[cfg(fuzzing)]
use afl::fuzz;
extern crate afl;

use mla_fuzz::{produce_samples, run};
use std::io::{self, IsTerminal, Read};

#[cfg(fuzzing)]
fn main() {
    fuzz!(|data: &[u8]| {
        let mut buf = data.to_vec();
        run(&buf);
    });
}

#[cfg(not(fuzzing))]
fn main() {
    /*
    // Replay a sample:
    //
    // `$ /path/to/fuzz < sample`
    //
    // Or:
    //
    // let mut data = include_bytes!(
    //    "../out/default/crashes/my_crash"
    // ).to_vec();
    // run(&mut data);
    */

    // Try to read input from stdin
    if io::stdin().is_terminal() {
        // On a terminal without piped input, generate samples directly
        println!("Generating sample inputs in in/");
        produce_samples();
    } else {
        let mut input = Vec::new();
        if io::stdin().read_to_end(&mut input).is_ok() && !input.is_empty() {
            run(&input);
        } else {
            // Empty input from pipe
            println!("No input provided, generating samples in in/");
            produce_samples();
        }
    }
}

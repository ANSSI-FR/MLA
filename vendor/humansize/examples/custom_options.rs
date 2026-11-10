extern crate humansize;
use humansize::{format_size, FormatSizeOptions, DECIMAL};

fn main() {
    // Create a new FormatSizeOptions struct starting from one of the defaults
    let custom_options = FormatSizeOptions::from(DECIMAL).decimal_places(5);

    // Then use it
    println!("{}", format_size(3024usize, custom_options));
}

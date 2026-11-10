extern crate humansize;

use humansize::{format_size, format_size_i, SizeFormatter, ISizeFormatter, BINARY, DECIMAL, WINDOWS};

fn main() {
    println!("{}", format_size(5456usize, BINARY));
    println!("{}", format_size(1024usize, DECIMAL));
    println!("{}", format_size(1000usize, WINDOWS));

    println!("{}", format_size(1_023_654_123_654_u64, BINARY));
    println!("{}", format_size(123456789usize, DECIMAL));
    println!("{}", format_size_i(-123456789, WINDOWS));

    println!("{}", SizeFormatter::new(1234u32, BINARY));
    println!("{}", ISizeFormatter::new(1234, BINARY));
}

//! # Permutate
//!
//! Permutate exists as both a library and application for permutating generic lists of lists, as
//! well as individual lists, using an original Rust-based algorithm. It has been developed
//! primarily for the goal of inclusion within the Rust implementation of
//! the GNU Parallel program, and brace expansions within Redox's Ion shell.
//!
//! Permutations work by incrementing a vector of index counters, and returning a vector of
//! references to the underlying data. For optimal usage, it is best to perform one iteration
//! with the `next()` method, and follow up successive iterations with the `next_with_buffer()`
//! method, so that you can re-use the previous vector allocation. It is also possible to obtain
//! the state of the internal index counters by using the `get_indexes()` method, and set the
//! state with the `set_indexes` method.
//!
//! ## Examples
//!
//! These are a list of examples on how to use the library to manipulate string-based data.
//! The only thing we need to ensure is that our list of strings is in the `&[&[&str]]` format.
//!
//! ### An individual list
//!
//! ```rust
//! extern crate permutate;
//! use permutate::Permutator;
//! use std::io::{self, Write};
//!
//! fn main() {
//!     let stdout = io::stdout();
//!     let mut stdout = stdout.lock();
//!     let list: &[&str] = &["one", "two", "three", "four"];
//!     let list = [list];
//!     let mut permutator = Permutator::new(&list[..]);
//!
//!     if let Some(mut permutation) = permutator.next() {
//!         for element in &permutation {
//!             let _ = stdout.write(element.as_bytes());
//!         }
//!         let _ = stdout.write(b"\n");
//!         while permutator.next_with_buffer(&mut permutation) {
//!             for element in &permutation {
//!                 let _ = stdout.write(element.as_bytes());
//!             }
//!             let _ = stdout.write(b"\n");
//!         }
//!     }
//! }
//! ```
//!
//! ### An array of arrays: `&[&[&str]]`
//!
//! ```rust
//! extern crate permutate;
//! use permutate::Permutator;
//! use std::io::{self, Write};
//!
//! fn main() {
//!     let stdout = io::stdout();
//!     let mut stdout = stdout.lock();
//!     let lists = [
//!         &["one", "two", "three"][..],
//!         &["four", "five", "six"][..],
//!         &["seven", "eight", "nine"][..],
//!     ];
//!     let mut permutator = Permutator::new(&lists[..]);
//!
//!     if let Some(mut permutation) = permutator.next() {
//!         for element in &permutation {
//!             let _ = stdout.write(element.as_bytes());
//!         }
//!         let _ = stdout.write(b"\n");
//!         while permutator.next_with_buffer(&mut permutation) {
//!             for element in &permutation {
//!                 let _ = stdout.write(element.as_bytes());
//!             }
//!             let _ = stdout.write(b"\n");
//!         }
//!     }
//! }
//! ```
//!
//! ### A Vector of Vector of Strings: `Vec<Vec<String>>`
//!
//! This is the most complicated example to accomplish because you have to convert, essentially,
//! A vector of a vector of vectors into a slice of a slice of a slice, as the String type itself
//! is a vector of characters.
//!
//! ```rust
//! extern crate permutate;
//! use permutate::Permutator;
//! use std::io::{self, Write};
//!
//! fn main() {
//!     let stdout = io::stdout();
//!     let mut stdout = stdout.lock();
//!     let lists: Vec<Vec<String>> = vec![
//!         vec!["one".to_owned(), "two".to_owned(), "three".to_owned()],
//!         vec!["four".to_owned(), "five".to_owned(), "six".to_owned()],
//!         vec!["seven".to_owned(), "eight".to_owned(), "nine".to_owned()],
//!     ];
//!
//!     // Convert the `Vec<Vec<String>>` into a `Vec<Vec<&str>>`
//!     let tmp: Vec<Vec<&str>> = lists.iter()
//!         .map(|list| list.iter().map(AsRef::as_ref).collect::<Vec<&str>>())
//!         .collect();
//!
//!     // Convert the `Vec<Vec<&str>>` into a `Vec<&[&str]>`
//!     let vector_of_arrays: Vec<&[&str]> = tmp.iter()
//!         .map(AsRef::as_ref).collect();
//!
//!     // Pass the `Vec<&[&str]>` as an `&[&[&str]]`
//!     let mut permutator = Permutator::new(&vector_of_arrays[..]);
//!
//!     if let Some(mut permutation) = permutator.next() {
//!         for element in &permutation {
//!             let _ = stdout.write(element.as_bytes());
//!         }
//!         let _ = stdout.write(b"\n");
//!         while permutator.next_with_buffer(&mut permutation) {
//!             for element in &permutation {
//!                 let _ = stdout.write(element.as_bytes());
//!             }
//!             let _ = stdout.write(b"\n");
//!         }
//!     }
//! }
//! ```
//!

/// The `Permutator` contains the state of the iterator as well as the references to inputs
/// that are being permutated. The input should be provided as an array of an array of references.
pub struct Permutator<'a, T: 'a + ?Sized> {
    /// The indexes is used to point to the next permutation sequence.
    indexes:        IndexCounters,
    /// The internal data that the permutator is permutating against.
    lists:          &'a [&'a [&'a T]],
    /// The total number of lists that is being permutated with.
    nlists:         usize,
    /// Whether the permutator is permutating against a single list, or multiple lists.
    single_list:    bool
}

impl<'a, T: 'a + ?Sized> Permutator<'a, T> {
    /// Initialize a new `Permutator` with the list of input lists to permutate with.
    /// The input may be provided as either multiple lists via an array of arrays, or a single
    /// list as an array within an array.
    pub fn new(lists: &'a [&'a [&'a T]]) -> Permutator<T> {
        let mut nlists  = lists.len();
        let single_list = nlists == 1;

        // The max indexes values are calculated as the number of elements
        // in a slice, minus one to account for the zeroth value.
        let nvalues = if single_list {
            nlists = lists[0].len();
            (0..nlists).map(|_| nlists - 1).collect::<Vec<usize>>()
        } else {
            lists.iter().map(|list| list.len() - 1).collect::<Vec<usize>>()
        };

        let max_iters = nvalues.iter().map(|x| x + 1).product();

        Permutator {
            indexes: IndexCounters {
                indexes:   vec![0; nlists],
                max:       nvalues,
                curr_iter: 0,
                max_iters: max_iters,
            },
            lists:       lists,
            nlists:      nlists,
            single_list: single_list
        }
    }

    /// Sets the internal index counter's values to a specific state, which you will
    /// typically obtain when using the `get_index()` method. The `iter_no` parameter
    /// will specify what the iteration's position should be. If, for example, you set
    /// this value to `0`, then it will iterate through all possible permutations,
    /// including looping around back to the beginning and generating permutations
    /// for all possible values before the supplied state.
    ///
    /// # Panics
    /// This method will panic if the supplied indexes vector is not the correct length
    pub fn set_index(&mut self, iter_no: usize, indexes: Vec<usize>) {
        debug_assert!(indexes.len() == self.indexes.max.len(), "indexes have an invalid length");
        self.indexes.indexes = indexes;
        self.indexes.curr_iter = iter_no;
    }

    /// Obtains the current iteration number and the index counter's indexes.
    pub fn get_index(&self) -> (usize, Vec<usize>) {
        (self.indexes.curr_iter, self.indexes.indexes.clone())
    }

    /// Returns the total number of permutations possible
    pub fn max_permutations(&self) -> usize {
        self.indexes.max_iters
    }

    /// Resets the internal state of the `Permutator` to allow you to start permutating again.
    pub fn reset(&mut self) {
        self.indexes.reset();
        self.indexes.curr_iter = 0;
    }

    /// Provides similar functionality as the `Iterator` traits `next` method, but allows the ability to either
    /// supply your own buffer or re-use the `Vec` created by a prior `next` in order to avoid extra allocations.
    ///
    /// - If the method returns `true`, then there are more values to compute.
    /// - If the method returns `false`, then all values have been exhausted.
    ///
    /// # Panics
    /// This method will panic if the supplied buffer's length is invalid.
    pub fn next_with_buffer(&mut self, buffer: &mut [&'a T]) -> bool {
        if self.indexes.max_iters != 0 {
            if self.indexes.curr_iter == self.indexes.max_iters {
                return false
            }
        }
        debug_assert!(buffer.len() >= self.nlists, "buffer is not large enough to contain the permutation");

        self.indexes.curr_iter += 1;

        let mut index = 0;
        unsafe {
            if self.single_list {
                for value in self.indexes.indexes.iter().map(|v| *self.lists.get_unchecked(0).get_unchecked(*v)) {
                    *buffer.get_unchecked_mut(index) = value;
                    index += 1;
                }
            } else {
                for value in self.indexes.indexes.iter().enumerate()
                    .map(|(list, value)| *self.lists.get_unchecked(list).get_unchecked(*value))
                {
                    *buffer.get_unchecked_mut(index) = value;
                    index += 1;
                }
            };
        }

        self.indexes.increment(&self.nlists - 1);

        true
    }
}

impl<'a, T: 'a + ?Sized> Iterator for Permutator<'a, T> {
    type Item = Vec<&'a T>;

    fn nth(&mut self, mut n: usize) -> Option<Vec<&'a T>> {
        loop {
            if self.indexes.max_iters != 0 {
                if self.indexes.curr_iter == self.indexes.max_iters {
                    return None
                }
            }

            self.indexes.curr_iter += 1;

            if n == 0 {
                let output = if self.single_list {
                    self.indexes.indexes.iter()
                        .map(|value| unsafe {
                            *self.lists.get_unchecked(0).get_unchecked(*value)
                        })
                        .collect::<Vec<&T>>()
                } else {
                    self.indexes.indexes.iter().enumerate()
                        .map(|(list, value)| unsafe {
                            *self.lists.get_unchecked(list).get_unchecked(*value)
                        })
                        .collect::<Vec<&T>>()
                };

                self.indexes.increment(&self.nlists - 1);
                return Some(output)
            }

            self.indexes.increment(&self.nlists - 1);
            n -= 1;
        }
    }

    fn next(&mut self) -> Option<Vec<&'a T>> {
        // Without this check, the permutator would cycle forever and never return `None`
        // because my incrementing algorithim prohibits it.
        if self.indexes.max_iters != 0 {
            if self.indexes.curr_iter == self.indexes.max_iters {
                return None
            }
        }

        self.indexes.curr_iter += 1;

        // Generates the next permutation sequence using the current indexes.
        // We are using `get_unchecked()` here because the incrementing
        // algorithim prohibits values from being out of bounds.
        let output = if self.single_list {
            self.indexes.indexes.iter()
                .map(|value| unsafe {
                    *self.lists.get_unchecked(0).get_unchecked(*value)
                })
                .collect::<Vec<&T>>()
        } else {
            self.indexes.indexes.iter().enumerate()
                .map(|(list, value)| unsafe {
                    *self.lists.get_unchecked(list).get_unchecked(*value)
                })
                .collect::<Vec<&T>>()
        };

        // Increment the indexes to point towards the next set of values.
        self.indexes.increment(&self.nlists - 1);

        // Return the collected permutation
        Some(output)
    }
}

/// The `ValuePermutator` contains the state of the iterator as well as the values to inputs
/// that are being permutated. The input should be provided as an array of an array of values.
pub struct ValuePermutator<'a, T: 'a + Copy> {
    /// The indexes is used to point to the next permutation sequence.
    indexes:        IndexCounters,
    /// The internal data that the permutator is permutating against.
    lists:          &'a [&'a [T]],
    /// The total number of lists that is being permutated with.
    nlists:         usize,
    /// Whether the permutator is permutating against a single list, or multiple lists.
    single_list:    bool
}

impl<'a, T: Copy> ValuePermutator<'a, T> {
    /// Initialize a new `ValuePermutator` with the list of input lists to permutate with.
    /// The input may be provided as either multiple lists via an array of arrays, or a single
    /// list as an array within an array.
    pub fn new(lists: &'a [&'a [T]]) -> ValuePermutator<T> {
        let mut nlists  = lists.len();
        let single_list = nlists == 1;

        // The max indexes values are calculated as the number of elements
        // in a slice, minus one to account for the zeroth value.
        let nvalues = if single_list {
            nlists = lists[0].len();
            (0..nlists).map(|_| nlists - 1).collect::<Vec<usize>>()
        } else {
            lists.iter().map(|list| list.len() - 1).collect::<Vec<usize>>()
        };

        let max_iters = nvalues.iter().map(|x| x + 1).product();

        ValuePermutator {
            indexes: IndexCounters {
                indexes:   vec![0; nlists],
                max:       nvalues,
                curr_iter: 0,
                max_iters: max_iters,
            },
            lists:       lists,
            nlists:      nlists,
            single_list: single_list
        }
    }

    /// Sets the internal index counter's values to a specific state, which you will
    /// typically obtain when using the `get_index()` method. The `iter_no` parameter
    /// will specify what the iteration's position should be. If, for example, you set
    /// this value to `0`, then it will iterate through all possible permutations,
    /// including looping around back to the beginning and generating permutations
    /// for all possible values before the supplied state.
    ///
    /// # Panics
    /// This method will panic if the supplied indexes vector is not the correct length
    pub fn set_index(&mut self, iter_no: usize, indexes: Vec<usize>) {
        debug_assert!(indexes.len() == self.indexes.max.len(), "indexes have an invalid length");
        self.indexes.indexes = indexes;
        self.indexes.curr_iter = iter_no;
    }

    /// Obtains the current iteration number and the index counter's indexes.
    pub fn get_index(&self) -> (usize, Vec<usize>) {
        (self.indexes.curr_iter, self.indexes.indexes.clone())
    }

    /// Returns the total number of permutations possible
    pub fn max_permutations(&self) -> usize {
        self.indexes.max_iters
    }

    /// Resets the internal state of the `Permutator` to allow you to start permutating again.
    pub fn reset(&mut self) {
        self.indexes.reset();
        self.indexes.curr_iter = 0;
    }

    /// Provides similar functionality as the `Iterator` traits `next` method, but allows the ability to either
    /// supply your own buffer or re-use the `Vec` created by a prior `next` in order to avoid extra allocations.
    ///
    /// - If the method returns `true`, then there are more values to compute.
    /// - If the method returns `false`, then all values have been exhausted.
    ///
    /// # Panics
    /// This method will panic if the supplied buffer's length is invalid.
    pub fn next_with_buffer(&mut self, buffer: &mut [T]) -> bool {
        if self.indexes.max_iters != 0 {
            if self.indexes.curr_iter == self.indexes.max_iters {
                return false
            }
        }
        debug_assert!(buffer.len() >= self.nlists, "buffer is not large enough to contain the permutation");

        self.indexes.curr_iter += 1;

        let mut index = 0;
        unsafe {
            if self.single_list {
                for value in self.indexes.indexes.iter().map(|v| *self.lists.get_unchecked(0).get_unchecked(*v)) {
                    *buffer.get_unchecked_mut(index) = value;
                    index += 1;
                }
            } else {
                for value in self.indexes.indexes.iter().enumerate()
                    .map(|(list, value)| *self.lists.get_unchecked(list).get_unchecked(*value))
                {
                    *buffer.get_unchecked_mut(index) = value;
                    index += 1;
                }
            };
        }

        self.indexes.increment(&self.nlists - 1);

        true
    }
}

impl<'a, T: Copy> Iterator for ValuePermutator<'a, T> {
    type Item = Vec<T>;

    fn nth(&mut self, mut n: usize) -> Option<Vec<T>> {
        loop {
            if self.indexes.max_iters != 0 {
                if self.indexes.curr_iter == self.indexes.max_iters {
                    return None
                }
            }

            self.indexes.curr_iter += 1;

            if n == 0 {
                let output = if self.single_list {
                    self.indexes.indexes.iter()
                        .map(|value| unsafe {
                            *self.lists.get_unchecked(0).get_unchecked(*value)
                        })
                        .collect::<Vec<T>>()
                } else {
                    self.indexes.indexes.iter().enumerate()
                        .map(|(list, value)| unsafe {
                            *self.lists.get_unchecked(list).get_unchecked(*value)
                        })
                        .collect::<Vec<T>>()
                };

                self.indexes.increment(&self.nlists - 1);
                return Some(output)
            }

            self.indexes.increment(&self.nlists - 1);
            n -= 1;
        }
    }

    fn next(&mut self) -> Option<Vec<T>> {
        // Without this check, the permutator would cycle forever and never return `None`
        // because my incrementing algorithim prohibits it.
        if self.indexes.max_iters != 0 {
            if self.indexes.curr_iter == self.indexes.max_iters {
                return None
            }
        }

        self.indexes.curr_iter += 1;

        // Generates the next permutation sequence using the current indexes.
        // We are using `get_unchecked()` here because the incrementing
        // algorithim prohibits values from being out of bounds.
        let output = if self.single_list {
            self.indexes.indexes.iter()
                .map(|value| unsafe {
                    *self.lists.get_unchecked(0).get_unchecked(*value)
                })
                .collect::<Vec<T>>()
        } else {
            self.indexes.indexes.iter().enumerate()
                .map(|(list, value)| unsafe {
                    *self.lists.get_unchecked(list).get_unchecked(*value)
                })
                .collect::<Vec<T>>()
        };

        // Increment the indexes to point towards the next set of values.
        self.indexes.increment(&self.nlists - 1);

        // Return the collected permutation
        Some(output)
    }
}

#[derive(Clone, Debug)]
/// Tracks the state of the indexes of each list.
pub struct IndexCounters {
    /// The current state of the indexes
    indexes: Vec<usize>,
    /// The max possible values for each indexes
    max:     Vec<usize>,
    /// The current iteration position
    curr_iter: usize,
    /// The maximum number of iterations to perform
    max_iters: usize,
}

impl IndexCounters {
    /// Increments & resets index indexes according to their maximum values.
    fn increment(&mut self, mut nlists: usize) {
        loop {
            let mut increment = false;
            {
                let current = unsafe { self.indexes.get_unchecked_mut(nlists) };
                let max     = unsafe { self.max.get_unchecked(nlists) };
                if *current == *max {
                    if nlists != 0 {
                        *current = 0;
                        increment = true;
                    }
                } else {
                    *current += 1;
                }
            }

            if increment {
                nlists -= 1;
            } else {
                break
            }
        }
    }

    fn reset(&mut self) {
        for value in self.indexes.iter_mut() { *value = 0; }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    // Check to see if exactly 1,000,000 permutations were collected.
    fn test_million_permutations() {
        let inputs = [
            &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"][..],
            &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"][..],
            &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"][..],
            &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"][..],
            &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"][..],
            &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"][..]
        ];

        assert_eq!(1_000_000, Permutator::new(&inputs[..]).count())
    }

    #[test]
    // Verify that the permutations are generated with the correct values,
    // in the correct order.
    fn test_permutation_values() {
        let inputs = [&["1", "2", "3"][..], &["1", "2", "3"][..], &["1", "2", "3"][..]];
        let expected = [
            &["1", "1", "1"][..], &["1", "1", "2"][..], &["1", "1", "3"][..],
            &["1", "2", "1"][..], &["1", "2", "2"][..], &["1", "2", "3"][..],
            &["1", "3", "1"][..], &["1", "3", "2"][..], &["1", "3", "3"][..],
            &["2", "1", "1"][..], &["2", "1", "2"][..], &["2", "1", "3"][..],
            &["2", "2", "1"][..], &["2", "2", "2"][..], &["2", "2", "3"][..],
            &["2", "3", "1"][..], &["2", "3", "2"][..], &["2", "3", "3"][..],
            &["3", "1", "1"][..], &["3", "1", "2"][..], &["3", "1", "3"][..],
            &["3", "2", "1"][..], &["3", "2", "2"][..], &["3", "2", "3"][..],
            &["3", "3", "1"][..], &["3", "3", "2"][..], &["3", "3", "3"][..],
        ];

        for (output, expected) in Permutator::new(&inputs[..]).zip(expected[..].iter()) {
            assert_eq!(&output, expected);
        }

        let mut permutator = Permutator::new(&inputs[..]);
        let mut expected = expected[..].iter();
        assert_eq!(&(permutator.nth(10).unwrap()), expected.nth(10).unwrap());
        assert_eq!(&(permutator.nth(0).unwrap()), expected.nth(0).unwrap());
    }

    #[test]
    fn single_list_permutation() {
        let input = [&["1", "2", "3"][..]];
        let expected = [
            &["1", "1", "1"][..], &["1", "1", "2"][..], &["1", "1", "3"][..],
            &["1", "2", "1"][..], &["1", "2", "2"][..], &["1", "2", "3"][..],
            &["1", "3", "1"][..], &["1", "3", "2"][..], &["1", "3", "3"][..],
            &["2", "1", "1"][..], &["2", "1", "2"][..], &["2", "1", "3"][..],
            &["2", "2", "1"][..], &["2", "2", "2"][..], &["2", "2", "3"][..],
            &["2", "3", "1"][..], &["2", "3", "2"][..], &["2", "3", "3"][..],
            &["3", "1", "1"][..], &["3", "1", "2"][..], &["3", "1", "3"][..],
            &["3", "2", "1"][..], &["3", "2", "2"][..], &["3", "2", "3"][..],
            &["3", "3", "1"][..], &["3", "3", "2"][..], &["3", "3", "3"][..],
        ];
        for (output, expected) in Permutator::new(&input[..]).zip(expected[..].iter()) {
            assert_eq!(&output, expected);
        }
    }

    #[test]
    fn test_reset() {
        let input = [&["1", "2", "3"][..]];
        let expected = [
            &["1", "1", "1"][..], &["1", "1", "2"][..], &["1", "1", "3"][..],
            &["1", "2", "1"][..], &["1", "2", "2"][..], &["1", "2", "3"][..],
            &["1", "3", "1"][..], &["1", "3", "2"][..], &["1", "3", "3"][..],
            &["2", "1", "1"][..], &["2", "1", "2"][..], &["2", "1", "3"][..],
            &["2", "2", "1"][..], &["2", "2", "2"][..], &["2", "2", "3"][..],
            &["2", "3", "1"][..], &["2", "3", "2"][..], &["2", "3", "3"][..],
            &["3", "1", "1"][..], &["3", "1", "2"][..], &["3", "1", "3"][..],
            &["3", "2", "1"][..], &["3", "2", "2"][..], &["3", "2", "3"][..],
            &["3", "3", "1"][..], &["3", "3", "2"][..], &["3", "3", "3"][..],
        ];
        let mut permutator = Permutator::new(&input[..]);
        for (output, expected) in permutator.by_ref().zip(expected[..].iter()) {
            assert_eq!(&output, expected);
        }
        permutator.reset();
        for (output, expected) in permutator.zip(expected[..].iter()) {
            assert_eq!(&output, expected);
        }
    }
}

//! Buffer management.
//!
//! Some convenience functions to copying data between Rust and C.
//! When moving data to C, we use libc's allocator, which means that
//! the C code can free the memory in the usual way, i.e., using
//! libc's free.

use std::{
    ptr::{
        copy_nonoverlapping,
    },
};

use libc::{
    malloc,
    c_char,
};

/// Copies a Rust string to a buffer, adding a terminating zero.
pub fn rust_str_to_c_str<S: AsRef<str>>(s: S) -> *mut c_char {
    let s = s.as_ref();
    let bytes = s.as_bytes();
    unsafe {
        let buf = malloc(bytes.len() + 1);
        copy_nonoverlapping(bytes.as_ptr(), buf as *mut _, bytes.len());
        *((buf as *mut u8).add(bytes.len())) = 0; // Terminate.
        buf as *mut c_char
    }
}

/// Copies a C string to a buffer, adding a terminating zero.
///
/// Replaces embedded zeros with '_'.
pub fn rust_bytes_to_c_str_lossy<S: AsRef<[u8]>>(s: S) -> *mut c_char {
    let bytes = s.as_ref();
    unsafe {
        let buf = malloc(bytes.len() + 1);
        copy_nonoverlapping(bytes.as_ptr(), buf as *mut _, bytes.len());

        // Replace embedded zeros.
        let bytes_mut = std::slice::from_raw_parts_mut(buf as *mut u8,
                                                       bytes.len());
        bytes_mut.iter_mut().for_each(|b| if *b == 0 { *b = b'_' });

        *((buf as *mut u8).add(bytes.len())) = 0; // Terminate.
        buf as *mut c_char
    }
}

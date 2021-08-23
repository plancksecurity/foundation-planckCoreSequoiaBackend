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
    c_char,
};

use crate::Error;
use crate::Result;
use crate::ffi::MM;

/// Copies a Rust string to a buffer, adding a terminating zero.
pub fn rust_str_to_c_str<S: AsRef<str>>(mm: MM, s: S)
    -> Result<*mut c_char>
{
    let malloc = mm.malloc;

    let s = s.as_ref();
    let bytes = s.as_bytes();
    unsafe {
        let buf = malloc(bytes.len() + 1);
        if buf.is_null() {
            return Err(Error::OutOfMemory("rust_bytes_to_c_str_lossy".into(),
                                          bytes.len() + 1));
        };
        copy_nonoverlapping(bytes.as_ptr(), buf as *mut _, bytes.len());
        *((buf as *mut u8).add(bytes.len())) = 0; // Terminate.
        Ok(buf as *mut c_char)
    }
}

/// Copies a C string to a buffer, adding a terminating zero.
///
/// Replaces embedded zeros with '_'.
pub fn rust_bytes_to_c_str_lossy<S: AsRef<[u8]>>(mm: MM, s: S)
    -> Result<*mut c_char>
{
    let malloc = mm.malloc;

    let bytes = s.as_ref();
    unsafe {
        let buf = malloc(bytes.len() + 1);
        if buf.is_null() {
            return Err(Error::OutOfMemory("rust_bytes_to_c_str_lossy".into(),
                                          bytes.len() + 1));
        };
        copy_nonoverlapping(bytes.as_ptr(), buf as *mut _, bytes.len());

        // Replace embedded zeros.
        let bytes_mut = std::slice::from_raw_parts_mut(buf as *mut u8,
                                                       bytes.len());
        bytes_mut.iter_mut().for_each(|b| if *b == 0 { *b = b'_' });

        *((buf as *mut u8).add(bytes.len())) = 0; // Terminate.
        Ok(buf as *mut c_char)
    }
}

pub fn malloc_cleared<T>(mm: MM) -> Result<*mut T>
{
    let malloc = mm.malloc;

    let size = std::mem::size_of::<T>();
    let buffer = unsafe { malloc(size) };
    if buffer.is_null() {
        return Err(Error::OutOfMemory("malloc".into(), size));
    };

    unsafe { libc::memset(buffer, 0, size) };
    Ok(buffer as *mut T)
}

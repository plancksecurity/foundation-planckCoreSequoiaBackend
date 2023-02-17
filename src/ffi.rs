use libc::{
    c_void,
    size_t,
};

/// How to free the memory allocated by the callback.
pub type Free = unsafe extern "C" fn(*mut c_void);

/// How to free the memory allocated by the callback.
pub type Malloc = unsafe extern "C" fn(size_t) -> *mut c_void;

#[derive(Copy, Clone)]
pub struct MM {
    pub malloc: Malloc,
    pub free: Free,
}

// Wraps an ffi function.
//
// This wrapper allows the function to return a Result.  The Ok
// variant should be ().  It may be something else.  In that case, the
// value is simply discarded.  The Error variant must be convertible
// to a `crate::ErrorCode` using `Into`.
macro_rules! ffi {
    (fn $f:ident( $( $v:ident: $t:ty ),* ) -> $rt:ty $body:block ) => {
        // The wrapper.  It calls $f and turns the result into an
        // error code.
        #[no_mangle] pub extern "C"
        fn $f($($v: $t,)*) -> crate::ErrorCode {
            tracer!(*crate::TRACE, stringify!($f));

            // The actual function.
            fn inner($($v: $t,)*) -> $rt { $body }

            t!("entered");
            // We use AssertUnwindSafe.  This is safe, because if we
            // catch a panic, we abort.  If we turn the panic into an
            // error, then we need to reexamine this assumption.
            let r = std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                match inner($($v,)*) {
                    Ok(_) => {
                        t!("-> success");
                        ErrorCode::from(crate::Error::StatusOk)
                    }
                    Err(err) => {
                        t!("-> error: {}{}",
                           err,
                           {
                               use std::error::Error;

                               let mut causes = String::new();
                               let mut cause = err.source();
                               while let Some(e) = cause {
                                   causes.push_str("\n  because: ");
                                   causes.push_str(&e.to_string());
                                   cause = e.source();
                               }
                               causes
                           });

                        ErrorCode::from(err)
                    }
                }
            }));
            match r {
                Ok(code) => code,
                Err(_) => {
                    t!("-> panic!");
                    unsafe { ::libc::abort() };
                }
            }
        }
    }
}

// Creates a stub for a ffi, which returns an error.
#[allow(unused_macros)]
macro_rules! stub {
    ($f:ident) => {
        #[no_mangle] pub extern "C"
        fn $f() -> crate::ErrorCode {
            tracer!(*crate::TRACE, stringify!($f));
            t!("{} is a stub\n", stringify!($f));
            crate::Error::UnknownError(
                anyhow::anyhow!("Function not implemented"),
                stringify!($f).into()).into()
        }
    };
}

// Checks if a `*const T` pointer is NULL if so, returns an error.
// Otherwise, returns `&T`.
macro_rules! check_ptr {
    ($p:ident) => {
        if let Some(p) = $p.as_ref() {
            p
        } else {
            return Err(Error::IllegalValue(
                format!("{} must not be NULL", stringify!($p))));
        }
    }
}

// Checks if a `*mut T` pointer is NULL if so, returns an error.
// Otherwise, returns `&mut T`.
macro_rules! check_mut {
    ($p:ident) => {
        if let Some(p) = $p.as_mut() {
            p
        } else {
            return Err(Error::IllegalValue(
                format!("{} must not be NULL", stringify!($p))));
        }
    }
}

// Checks if a `*const T` pointer is NULL if so, returns an error.
// Otherwise, returns a slice `&[T]` with `l` elements.
macro_rules! check_slice {
    ($p:ident, $l:expr) => {
        if $p.is_null() {
            return Err(Error::IllegalValue(
                format!("{} must not be NULL", stringify!($p))));
        } else {
            std::slice::from_raw_parts($p as *const u8, $l)
        }
    }
}

// Checks if a `*mut T` pointer is NULL if so, returns an error.
// Otherwise, returns a slice `&mut [T]` with `l` elements.
macro_rules! check_slice_mut {
    ($p:ident, $l:expr) => {
        if $p.is_null() {
            return Err(Error::IllegalValue(
                format!("{} must not be NULL", stringify!($p))));
        } else {
            std::slice::from_raw_parts_mut($p as *mut u8, $l)
        }
    }
}

// Checks if a `*const c_char` pointer is NULL if so, returns an
// error.  Otherwise, returns a CStr.
macro_rules! check_cstr {
    ($s:ident) => {{
        let _: *const libc::c_char = $s;
        let s = check_ptr!($s);
        CStr::from_ptr(s)
    }}
}

// Checks if a `*const c_char` pointer is NULL if so, returns an
// error.  Otherwise, interprets the C string as an OpenPGP
// fingerprint.  If it is not a valid fingerprint, returns an error.
// Otherwise returns a `Fingerprint`.
macro_rules! check_fpr {
    ($fpr:ident) => {{
        let fpr = check_cstr!($fpr);
        wrap_err!(
            Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
            UnknownError,
            "Not a fingerprint")?
    }}
}

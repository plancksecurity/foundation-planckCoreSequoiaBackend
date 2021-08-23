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
// value is simply discarded.  The Error variant must be convertable
// to a `crate::ErrorCode` using `Into`.
macro_rules! ffi {
    (fn $f:ident( $( $v:ident: $t:ty ),* ) -> $rt:ty $body:block ) => {
        // The wrapper.  It calls $f and turns the result into an
        // error code.
        #[no_mangle] pub extern "C"
        fn $f($($v: $t,)*) -> crate::ErrorCode {
            tracer!(*crate::TRACE, stringify!($f));

            // The actual function.
            fn inner($($v: $t,)*) -> $rt { $body };

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

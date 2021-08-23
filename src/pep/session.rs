use std::ptr;
use std::ffi::CStr;
use std::convert::TryInto;

use libc::c_char;

use sequoia_openpgp as openpgp;
use openpgp::crypto::Password;

use crate::Error;
use crate::Keystore;
use crate::PepCipherSuite;
use crate::Result;
use crate::ffi::MM;

const MAGIC: u64 = 0xE3F3_05AD_48EE_0DF5;

pub struct State {
    ks: Keystore,
    mm: MM,
    magic: u64,
}

impl State {
    /// Converts the raw pointer to a Rust reference.
    ///
    /// This does *not* take ownership of the object.
    ///
    /// Sanity checks the data structure.
    pub fn as_mut(ptr: *mut Self) -> &'static mut Self {
        let s = unsafe { ptr.as_mut() }.expect("NULL pointer");
        assert_eq!(s.magic, MAGIC, "magic");

        s
    }

    /// Converts a raw pointer back into a Rust object.
    ///
    /// Takes ownership of the object.
    pub fn to_rust(ptr: *mut Self) -> Box<Self> {
        assert!(! ptr.is_null());
        let s = unsafe { Box::from_raw(ptr) };
        assert_eq!(s.magic, MAGIC, "magic");

        s
    }

    /// Converts the Rust object to a raw pointer.
    ///
    /// Transfers ownership to the caller.
    pub fn to_c(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }
}

#[repr(C)]
pub struct Session {
    pub version: *const u8,
    pub state: *mut State,
    pub curr_passphrase: *const c_char,
    pub new_key_pass_enabled: bool,
    pub generation_passphrase: *const c_char,
    pub cipher_suite: PepCipherSuite,
}

impl Session {
    /// Returns a new session.
    ///
    /// This is normally initialized by the engine, but we need this
    /// for testing.
    #[cfg(test)]
    pub fn new() -> *mut Session {
        Box::into_raw(Box::new(Session {
            version: ptr::null(),
            state: Box::into_raw(Box::new(State {
                ks: Keystore::init_in_memory().unwrap(),
                mm: MM {
                    malloc: libc::malloc,
                    free: libc::free,
                },
                magic: MAGIC,
            })),
            curr_passphrase: ptr::null(),
            new_key_pass_enabled: false,
            generation_passphrase: ptr::null(),
            cipher_suite: PepCipherSuite::Default,
        }))
    }

    pub fn init(&mut self,
                mm: MM,
                ks: Keystore)
    {
        assert!(self.state.is_null());

        self.state = Box::into_raw(Box::new(State {
            ks: ks,
            mm,
            magic: MAGIC,
        }));
    }

    pub fn deinit(&mut self) {
        let _ = State::to_rust(self.state);
        self.state = ptr::null_mut();
    }

    /// Converts the raw pointer to a Rust reference.
    ///
    /// This does not take ownership of the object.
    pub fn as_mut(ptr: *mut Self) -> Result<&'static mut Self> {
        if let Some(session) = unsafe { ptr.as_mut() } {
            Ok(session)
        } else {
            Err(Error::IllegalValue(
                "session may not be NULL".into()))
        }
    }

    /// Returns a reference to the keystore.
    ///
    /// This panics if the keystore has not yet been set (see
    /// [`Session::set_keystore`].
    pub fn keystore(&mut self) -> &mut Keystore {
        &mut State::as_mut(self.state).ks
    }

    /// Returns the application's memory management routines.
    pub fn mm(&self) -> MM {
        State::as_mut(self.state).mm
    }

    /// Returns the value of curr_passphrase.
    pub fn curr_passphrase(&self) -> Option<Password> {
        unsafe {
            self.curr_passphrase.as_ref().and_then(|ptr| {
                let bytes = CStr::from_ptr(ptr).to_bytes();
                // A zero-length password is not a password.
                if bytes.len() == 0 {
                    None
                } else {
                    Some(Password::from(bytes))
                }
            })
        }
    }

    /// Returns the value of new_key_pass_enabled.
    pub fn new_key_pass_enabled(&self) -> bool {
        self.new_key_pass_enabled
    }

    /// Returns the value of generation_passphrase.
    pub fn generation_passphrase(&self) -> Option<Password> {
        unsafe {
            self.generation_passphrase.as_ref().and_then(|ptr| {
                let bytes = CStr::from_ptr(ptr).to_bytes();
                // A zero-length password is not a password.
                if bytes.len() == 0 {
                    None
                } else {
                    Some(Password::from(bytes))
                }
            })
        }
    }

    /// Returns the value of cipher_suite.
    pub fn cipher_suite(&self) -> PepCipherSuite {
        self.cipher_suite
    }

    /// Sets the value of cipher suite.
    ///
    /// If suite is known and supported, this function returns
    /// success.  If suite is not known or not supported, then this
    /// sets the cipher suite to the default!
    pub fn set_cipher_suite(&mut self, suite: PepCipherSuite) -> Result<()> {
        let sq_suite: Result<openpgp::cert::CipherSuite> = suite.try_into();
        match sq_suite {
            Ok(_) => {
                self.cipher_suite = suite;
                Ok(())
            }
            Err(_err) => {
                self.cipher_suite = PepCipherSuite::Rsa2K;
                Err(Error::CannotConfig("cipher suite".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Make sure the pointer is cleared when the state is dropped.
    #[test]
    fn state() {
        let session = Session::new();

        {
            let session: &mut Session = Session::as_mut(session).unwrap();

            let ks = session.keystore() as *mut _;
            let ks2 = session.keystore() as *mut _;
            assert!(ptr::eq(ks, ks2));
            session.deinit();

            // If the state pointer is non-NULL, this will panic.
            session.init(MM { malloc: libc::malloc, free: libc::free },
                         Keystore::init_in_memory().unwrap());
            let ks = session.keystore() as *mut _;
            let ks2 = session.keystore() as *mut _;
            assert!(ptr::eq(ks, ks2));
            session.deinit();
        }

        unsafe { Box::from_raw(session) };
    }
}

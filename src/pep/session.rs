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

#[repr(C)]
pub struct Session {
    pub version: *const u8,
    pub ks: *mut Keystore,
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
            ks: ptr::null_mut(),
            curr_passphrase: ptr::null(),
            new_key_pass_enabled: false,
            generation_passphrase: ptr::null(),
            cipher_suite: PepCipherSuite::Default,
        }))
    }

    /// Converts the raw pointer to a Rust reference.
    ///
    /// This does not take ownership of the object.
    pub fn as_mut(ptr: *mut Self) -> &'static mut Self {
        unsafe { ptr.as_mut() }.expect("NULL pointer")
    }

    /// Returns a reference to the keystore.
    ///
    /// This panics if the keystore has not yet been set (see
    /// [`Session::set_keystore`].
    pub fn keystore(&mut self) -> &mut Keystore {
        Keystore::as_mut(self.ks)
    }

    /// Sets the keystore.
    ///
    /// This panics if a keystore has already been set.
    ///
    /// The keystore can be dropped using [`Session::drop_keystore`].
    pub fn set_keystore(&mut self, ks: Keystore) {
        assert!(self.ks.is_null());
        self.ks = ks.to_c();
    }

    /// Drops the keystore.
    ///
    /// This panics if a keystore has already been set.
    pub fn drop_keystore(&mut self) {
        let _ = Keystore::to_rust(self.ks);
        // Reset the pointer.
        self.ks = ptr::null_mut() as *mut _;
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

    // Make sure the pointer is cleared when the key store is dropped.
    #[test]
    fn keystore() {
        let session = Session::new();

        {
            let session: &mut Session = Session::as_mut(session);

            session.set_keystore(Keystore::init_in_memory().unwrap());
            let ks = session.keystore() as *mut _;
            let ks2 = session.keystore() as *mut _;
            assert!(ptr::eq(ks, ks2));
            session.drop_keystore();

            // If the keystore pointer is non-NULL, this will panic.
            session.set_keystore(Keystore::init_in_memory().unwrap());
            let ks = session.keystore() as *mut _;
            let ks2 = session.keystore() as *mut _;
            assert!(ptr::eq(ks, ks2));
            session.drop_keystore();
        }

        unsafe { Box::from_raw(session) };
    }
}

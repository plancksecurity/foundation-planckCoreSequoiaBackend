use std::ptr;
use std::ffi::{CStr, CString};
use std::convert::TryInto;

use libc::c_char;

use sequoia_openpgp as openpgp;
use openpgp::crypto::Password;
use crate::buffer::rust_str_to_c_str;

use crate::Error;
use crate::Keystore;
use crate::PepCipherSuite;
use crate::Result;
use crate::ffi::MM;
use crate::pep::StringPairListItem;

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
        assert!(!ptr.is_null());
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
    pub curr_passphrases: *mut StringPairListItem,
    pub new_key_pass_enabled: bool,
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
            curr_passphrases: ptr::null_mut(),
            new_key_pass_enabled: false,
            cipher_suite: PepCipherSuite::Default,
        }))
    }

    pub fn init(&mut self,
                mm: MM,
                ks: Keystore)
    {
        assert!(self.state.is_null());

        self.state = Box::into_raw(Box::new(State {
            ks,
            mm,
            magic: MAGIC,
        }));

        // Initialize curr_passphrases
        self.curr_passphrases = StringPairListItem::empty(mm);
    }

    pub fn deinit(&mut self) {
        let _ = State::to_rust(self.state);
        self.state = ptr::null_mut();

        // Deinitialize curr_passphrases
        if !self.curr_passphrases.is_null() {
            unsafe {
                let mut current = self.curr_passphrases;
                while !current.is_null() {
                    let next = (*current).next;
                    if !(*current).value.is_null() {
                        let pair = Box::from_raw((*current).value);
                        //rust_str_to_c_str(self.mm(), pair.key);
                        //rust_str_to_c_str(self.mm(), pair.value);
                        let _ = CString::from_raw(pair.key);
                        let __ = CString::from_raw(pair.value);
                    }
                    libc::free(current as *mut libc::c_void);
                    current = next;
                }
            }
            self.curr_passphrases = ptr::null_mut();
        }
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

    /// Adds a new passphrase to curr_passphrases.
    pub fn add_passphrase(&mut self, key: &str, passphrase: &str) {
        if self.curr_passphrases.is_null() {
            self.curr_passphrases = StringPairListItem::empty(self.mm());
        }

        let list = unsafe { &mut *self.curr_passphrases };
        list.add(self.mm(), key, passphrase);
    }

    /// Finds a passphrase by key in curr_passphrases.
    pub fn find_passphrase(&self, search_key: &str) -> Option<Password> {
        if self.curr_passphrases.is_null() {
            return None;
        }

        let list = unsafe { &*self.curr_passphrases };
        for (key, value) in list.iter() {
            if key.to_str().unwrap() == search_key {
                let value_bytes = value.to_str().unwrap().as_bytes();
                return Some(Password::from(value_bytes));
            }
        }
        None
    }

    /// Finds a passphrase by key in curr_passphrases.
    pub fn find_passphrase_c(&self, search_key: *const c_char) -> Option<Password> {
        if self.curr_passphrases.is_null() || search_key.is_null() {
            return None;
        }

        // Convert the C string to a Rust string slice
        let search_key = unsafe {
            CStr::from_ptr(search_key)
                .to_str()
                .expect("Invalid UTF-8 string")
        };

        let list = unsafe { &*self.curr_passphrases };
        for (key, value) in list.iter() {
            if key.to_str().unwrap() == search_key {
                let value_bytes = value.to_str().unwrap().as_bytes();
                return Some(Password::from(value_bytes));
            }
        }
        None
    }

    /// Returns an iterator over the current passphrases.
    pub fn curr_passphrases(&self) -> Option<impl Iterator<Item = (&CStr, &CStr)>> {
        if self.curr_passphrases.is_null() {
            None
        } else {
            Some(unsafe { &*self.curr_passphrases }.iter())
        }
    }

    /// Returns the value of new_key_pass_enabled.
    pub fn new_key_pass_enabled(&self) -> bool {
        self.new_key_pass_enabled
    }

    /// Returns the value of cipher_suite.
    pub fn cipher_suite(&self) -> PepCipherSuite {
        self.cipher_suite
    }

    /// Sets the value of cipher suite.
    ///
    /// If suite is known and supported, this function returns
    /// success. If suite is not known or not supported, then this
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

        unsafe { let _ = Box::from_raw(session); };
    }

    #[test]
    fn add_and_iter_passphrases() {
        let mm = MM { malloc: libc::malloc, free: libc::free };
        let mut session = Session {
            version: ptr::null(),
            state: Box::into_raw(Box::new(State {
                ks: Keystore::init_in_memory().unwrap(),
                mm,
                magic: MAGIC,
            })),
            curr_passphrases: ptr::null_mut(),
            new_key_pass_enabled: true,
            cipher_suite: PepCipherSuite::Default,
        };

        session.add_passphrase("key1", "passphrase1");
        session.add_passphrase("key2", "passphrase2");

        let passphrases: Vec<(&CStr, &CStr)> = session.curr_passphrases().unwrap().collect();
        assert_eq!(passphrases.len(), 2);
        assert_eq!(passphrases[0].0.to_str().unwrap(), "key1");
        assert_eq!(passphrases[0].1.to_str().unwrap(), "passphrase1");
        assert_eq!(passphrases[1].0.to_str().unwrap(), "key2");
        assert_eq!(passphrases[1].1.to_str().unwrap(), "passphrase2");
    }
}

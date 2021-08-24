//! A wrapper for pep's pEp_identity and identity_list structures.
//!
//! See pEpEngine.h and identity_list.c for details.
//!
//! This is needed by, for instance:
//!
//!   - pgp_generate_keypair
//!   - pgp_import_keydata
//!
//! We need to reimplement the following functions:
//!
//!   - new_identity
//!   - new_identity_list
//!   - identity_list_add
//!
//! The following fields of pEp_identity are used:
//!
//!   - address
//!   - username
//!   - fpr
//!   - flags
//!
//! PepCommType is also needed by:
//!
//!   - pgp_get_key_rating
use std::ffi::CStr;
use std::mem;
use std::os::raw::{
    c_char,
    c_uint,
};
use std::ptr;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;

use crate::Error;
use crate::Result;
use crate::buffer::{
    malloc_cleared,
    rust_str_to_c_str,
};
use crate::ffi::MM;
use crate::pep::{
    PepCommType,
    PepEncFormat,
    PepIdentityFlags,
};

/// A `PepIdentity` template.
///
/// Unlike `PepIdentity`, the object is managed by Rust.
#[derive(Debug)]
pub struct PepIdentityTemplate {
    address: String,
    fpr: Fingerprint,
    username: Option<String>,
}

impl PepIdentityTemplate {
    /// Returns a new identity.
    ///
    /// The memory is allocated using the libc allocator.  The caller
    /// is responsible for freeing it explicitly.
    pub fn new<S1, S2>(email: S1, fingerprint: Fingerprint, username: Option<S2>)
        -> Self
        where S1: AsRef<str>, S2: AsRef<str>
    {
        Self {
            address: email.as_ref().into(),
            fpr: fingerprint,
            username: username.map(|s| s.as_ref().into()),
        }
    }
}

// See pEpEngine/src/pEpEngine.h:pEp_identity.
//
//   https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/branch/master/src/pEpEngine.h#L788
#[repr(C)]
pub struct PepIdentity {
    pub address: *mut c_char,
    pub fpr: *mut c_char,
    pub userid: *mut c_char,
    pub username: *mut c_char,
    pub comm_type: PepCommType,
    pub lang: [u8; 3],
    pub me: bool,
    pub major_ver: c_uint,
    pub minor_ver: c_uint,
    pub enc_format: PepEncFormat,
    pub flags: PepIdentityFlags,
}

impl PepIdentity {
    /// Returns a new identity.
    ///
    /// The memory is allocated using the libc allocator.  The caller
    /// is responsible for freeing it explicitly.
    pub fn new(mm: MM, template: &PepIdentityTemplate)
        -> &'static mut Self
    {
        let buffer = if let Ok(buffer) = malloc_cleared::<Self>(mm) {
            buffer
        } else {
            panic!("Out of memory allocating a PepIdentity");
        };
        let ident = unsafe { &mut *(buffer as *mut Self) };
        ident.address = rust_str_to_c_str(mm, &template.address)
            .expect("Out of memory allocating ident.address");
        ident.fpr = rust_str_to_c_str(mm, &template.fpr.to_hex())
            .expect("Out of memory allocating ident.fpr");
        if let Some(username) = template.username.as_ref() {
            ident.username = rust_str_to_c_str(mm, username)
                .expect("Out of memory allocating ident.username");
        }
        ident
    }

    /// Converts the raw pointer to a Rust reference.
    ///
    /// This does not take ownership of the object.
    pub fn as_mut(ptr: *mut Self) -> Result<&'static mut Self> {
        if let Some(identity) = unsafe { ptr.as_mut() } {
            Ok(identity)
        } else {
            Err(Error::IllegalValue(
                "PepIdentity may not be NULL".into()))
        }
    }

    /// Returns the address.
    pub fn address(&self) -> Option<&CStr> {
        if self.address.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(self.address) })
        }
    }

    /// Returns the fingerprint.
    pub fn fingerprint(&self) -> Option<&CStr> {
        if self.fpr.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(self.fpr) })
        }
    }

    /// Replaces the fingerprint.
    pub fn set_fingerprint(&mut self, mm: MM, fpr: Fingerprint) {
        unsafe { libc::free(self.fpr as *mut _) };
        // Clear to avoid a dangling pointers if the following
        // allocation fails.
        self.fpr = ptr::null_mut();
        self.fpr = rust_str_to_c_str(mm, fpr.to_hex())
            .expect("Out of memory allocating fingerprint");
    }

    /// Returns the username (in RFC 2822 speak: the display name).
    pub fn username(&self) -> Option<&CStr> {
        if self.username.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(self.username) })
        }
    }

    /// Returns the identity flags.
    pub fn identity_flags(&self) -> PepIdentityFlags {
        self.flags
    }

    /// Returns whether the specified identity flag is set.
    pub fn identity_flag(&self, flag: PepIdentityFlags) -> bool {
        self.identity_flags().is_set(flag)
    }
}

impl std::fmt::Debug for PepIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PepIdentity")
         .field("address", &self.address())
         .field("fingerprint", &self.fingerprint())
         .field("username", &self.username())
         .finish()
    }
}

// See pEpEngine/src/pEpEngine.h:identity_list.
//
//   https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/branch/master/src/pEpEngine.h#L817
#[repr(C)]
pub struct PepIdentityListItem {
    ident: *mut PepIdentity,
    next: *mut PepIdentityListItem,
}

impl PepIdentityListItem {
    /// Returns a new PepIdentityListItem containing `ident`.
    ///
    /// `next` is set to NULL.
    ///
    /// The memory is allocated using the libc allocator.  The caller
    /// is responsible for freeing it explicitly.
    fn new(mm: MM, ident: &'static mut PepIdentity) -> &'static mut Self
    {
        let buffer = if let Ok(buffer) = malloc_cleared::<Self>(mm) {
            buffer
        } else {
            panic!("Out of memory allocating a PepIdentityListItem");
        };
        let item = unsafe { &mut *(buffer as *mut Self) };
        item.ident = ident as *mut _;
        item
    }

    /// Converts the raw pointer to a Rust reference.
    ///
    /// This does not take ownership of the object.
    fn as_mut(ptr: *mut Self) -> Option<&'static mut Self> {
        unsafe { ptr.as_mut() }
    }
}

/// A wrapper structure for a `PepIdentity` list.
pub struct PepIdentityList {
    head: *mut PepIdentityListItem,
    owned: bool,
    mm: MM,
}

impl PepIdentityList {
    /// Converts the raw pointer to a Rust object.
    ///
    /// `owned` indicates whether the rust code should own the items.
    /// If so, when the `PepIdentityList` is dropped, the items will
    /// also be freed.
    pub fn to_rust(mm: MM, l: *mut PepIdentityListItem, owned: bool) -> Self
    {
        Self {
            head: l,
            owned,
            mm,
        }
    }

    /// Converts the Rust object to a raw pointer.
    ///
    /// The items are owned by the raw pointer and need to be freed
    /// explicitly using libc's `free`.
    pub fn to_c(mut self) -> *mut PepIdentityListItem {
        mem::replace(&mut self.head, ptr::null_mut())
    }

    /// Creates a new, empty PepIdentityList.
    ///
    /// Any added items are owned by the `PepIdentityList`, and when
    /// it is dropped, they are freed.  To take ownership of the
    /// items, call `PepIdentityList::to_c`.
    pub fn empty(mm: MM) -> Self {
        Self {
            head: ptr::null_mut(),
            owned: true,
            mm,
        }
    }

    /// Prepends the item to the list.
    ///
    /// The item's ownership is determined by the list's ownership
    /// property.
    pub fn add(&mut self, ident: &PepIdentityTemplate) {
        let ident = PepIdentityListItem::new(
            self.mm, PepIdentity::new(self.mm, ident));
        ident.next = self.head;
        self.head = ident;
    }
}

impl Drop for PepIdentityList {
    fn drop(&mut self) {
        let free = self.mm.free;

        let mut curr: *mut PepIdentityListItem = self.head;
        self.head = ptr::null_mut();

        if self.owned {
            loop {
                let next = if let Some(curr) = PepIdentityListItem::as_mut(curr) {
                    let next = curr.next;
                    unsafe { free(curr.ident as *mut _) };
                    curr.ident = ptr::null_mut();
                    next
                } else {
                    break;
                };

                unsafe { free(curr as *mut _) };
                curr = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn identity() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        let address = "addr@ess";
        let fpr = Fingerprint::from_str(
            "0123 4567 89AB CDEF 0000 0123 4567 89ab cdef 0000").unwrap();
        let username = "User Name";

        let template = PepIdentityTemplate::new(address, fpr, Some(username));
        let ident = PepIdentity::new(mm, &template);

        assert_eq!(ident.address().map(|s| s.to_bytes()),
                   Some(address.as_bytes()));
        // Be careful: the fingerprint is normalized.
        assert_eq!(ident.fingerprint().map(|s| s.to_bytes()),
                   Some("0123456789ABCDEF00000123456789ABCDEF0000".as_bytes()));
        assert_eq!(ident.username().map(|s| s.to_bytes()),
                   Some(username.as_bytes()));
    }

    #[test]
    fn list() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        let mut list = PepIdentityList::empty(mm);
        assert!(list.head.is_null());

        let address = "addr@ess";
        let fpr = Fingerprint::from_str(
            "0123 4567 89AB CDEF 0000 0123 4567 89ab cdef 0000").unwrap();
        let username = "User Name";

        let template = PepIdentityTemplate::new(address, fpr, Some(username));

        list.add(&template);

        assert!(! list.head.is_null());
        let item = PepIdentityListItem::as_mut(list.head).unwrap();

        assert!(! item.ident.is_null());
        let ident = PepIdentity::as_mut(item.ident).unwrap();
        assert!(item.next.is_null());

        assert_eq!(ident.address().map(|s| s.to_bytes()),
                   Some(address.as_bytes()));
        // Be careful: the fingerprint is normalized.
        assert_eq!(ident.fingerprint().map(|s| s.to_bytes()),
                   Some("0123456789ABCDEF00000123456789ABCDEF0000".as_bytes()));
        assert_eq!(ident.username().map(|s| s.to_bytes()),
                   Some(username.as_bytes()));
    }
}

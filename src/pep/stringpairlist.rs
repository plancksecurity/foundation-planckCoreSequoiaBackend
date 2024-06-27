//! A reimplementation of the engine's stringpairlist module in Rust.
//!
//! We could call out to the implementation in the engine, however,
//! then it would only be possible to use this crate when also linking
//! to the engine.  This would mean that the CLI and tests would need
//! to link to the engine, which is undesirable.
//!
//! We only implement the functionality that we actually use:
//!
//!   - new_stringpair_list
//!   - stringpair_list_length
//!   - stringpair_list_add
//!   - ////stringlist_add_unique
//!   - stringpair_list_append

use std::ptr;
use std::ffi::{CString, CStr};
use libc::c_char;

use crate::ffi::MM;
use crate::buffer::{malloc_cleared, rust_str_to_c_str};

#[repr(C)]
pub struct StringPair {
    pub key: *mut c_char,
    pub value: *mut c_char,
}

impl StringPair {
    fn empty(mm: MM) -> &'static mut Self {
        let buffer = if let Ok(buffer) = malloc_cleared::<Self>(mm) {
            buffer
        } else {
            panic!("Out of memory allocating a StringPair");
        };
        unsafe { &mut *(buffer as *mut Self) }
    }

    fn new<S: AsRef<str>>(mm: MM, key: S, value: S) -> &'static mut Self {
        let item = Self::empty(mm);

        item.value = rust_str_to_c_str(mm, value)
            .expect("Out of memory allocating StringPair");
        item.key = rust_str_to_c_str(mm, key)
            .expect("Out of memory allocating StringPair");

        item
    }

    fn as_mut(ptr: *mut Self) -> Option<&'static mut Self> {
        unsafe { ptr.as_mut() }
    }
}

#[repr(C)]
pub struct StringPairListItem {
    pub value: *mut StringPair,
    pub next: *mut StringPairListItem,
}

impl StringPairListItem {
    pub fn empty(mm: MM) -> &'static mut Self {
        let buffer = if let Ok(buffer) = malloc_cleared::<Self>(mm) {
            buffer
        } else {
            panic!("Out of memory allocating a StringPairListItem");
        };
        unsafe { &mut *(buffer as *mut Self) }
    }

    pub fn new(mm: MM, value: &mut StringPair, next: *mut Self) -> &'static mut Self {
        let item = Self::empty(mm);

        item.value = value;
        item.next = next;

        item
    }

    fn as_mut(ptr: *mut Self) -> Option<&'static mut Self> {
        unsafe { ptr.as_mut() }
    }

    pub fn add<S: AsRef<str>>(&mut self, mm: MM, key: S, value: S) {
        let mut current = self;
        while !current.next.is_null() {
            current = unsafe { &mut *current.next };
        }
        let new_pair = StringPair::new(mm, key, value);
        let new_item = StringPairListItem::new(mm, new_pair, ptr::null_mut());
        current.next = new_item;
    }

    pub fn add_unique<S: AsRef<str>>(&mut self, mm: MM, key: S, value: S) {
        let key = key.as_ref();
        let value = value.as_ref();
        let mut current: *mut StringPairListItem = self;
        let mut prev: Option<*mut StringPairListItem> = None;

        while !unsafe { (*current).next }.is_null() {
            let pair = unsafe { &*(*current).value };
            if unsafe { CStr::from_ptr(pair.key) }.to_bytes() == key.as_bytes() {
                let v = unsafe { CStr::from_ptr(pair.value) };
                if v.to_bytes() != value.as_bytes() {
                    unsafe {
                        (*current).value = Box::into_raw(Box::new(StringPair {
                            key: rust_str_to_c_str(mm, key).expect("Out of memory allocating StringPair"),
                            value: rust_str_to_c_str(mm, value).expect("Out of memory allocating StringPair"),
                        }));
                    }
                }
                return;
            }
            prev = Some(current);
            current = unsafe { (*current).next };
        }

        let new_pair = StringPair::new(mm, key, value);
        let new_item = StringPairListItem::new(mm, new_pair, ptr::null_mut());
        unsafe { (*current).next = new_item; }
    }


    pub fn append(&mut self, other: &mut Self) {
        let mut current = self;
        while !current.next.is_null() {
            current = unsafe { &mut *current.next };
        }
        current.next = other;
    }

    pub fn iter(&self) -> StringPairListItemIter {
        StringPairListItemIter { item: Some(self) }
    }
}

pub struct StringPairListItemIter<'a> {
    item: Option<&'a StringPairListItem>,
}

impl<'a> Iterator for StringPairListItemIter<'a> {
    type Item = (&'a CStr, &'a CStr);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.item {
            if item.value.is_null() {
                self.item = unsafe { item.next.as_ref() };
                return None;
            }
            let pair = unsafe { &*item.value };
            let key = unsafe { CStr::from_ptr(pair.key) };
            let value = unsafe { CStr::from_ptr(pair.value) };
            self.item = unsafe { item.next.as_ref() };
            Some((key, value))
        } else {
            None
        }
    }
}

impl Drop for StringPairListItem {
    fn drop(&mut self) {
        unsafe {
            let mut current = self as *mut StringPairListItem;
            while !current.is_null() {
                let next = (*current).next;
                if !(*current).value.is_null() {
                    let pair = Box::from_raw((*current).value);
                    CString::from_raw(pair.key);
                    CString::from_raw(pair.value);
                }
                libc::free(current as *mut libc::c_void);
                current = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        // Initialize a single item with an empty StringPair
        let empty_pair = StringPair::new(mm, "", "");
        let empty_list = StringPairListItem::new(mm, empty_pair, ptr::null_mut());
        assert_eq!(empty_list.iter().count(), 0);
    }

    #[test]
    fn add() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        // Initialize the list with an initial StringPair
        let pair = StringPair::new(mm, "key1", "value1");
        let mut list = StringPairListItem::new(mm, pair, ptr::null_mut());

        // Add items to the list
        for i in 2..5 {
            list.add(mm, format!("key{}", i), format!("value{}", i));
        }

        let keys_values: Vec<(&str, &str)> = list.iter().map(|(k, v)| (k.to_str().unwrap(), v.to_str().unwrap())).collect();
        assert_eq!(keys_values, vec![
            ("key1", "value1"),
            ("key2", "value2"),
            ("key3", "value3"),
            ("key4", "value4")
        ]);
    }

    #[test]
    fn add_unique() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        // Initialize the list with an initial StringPair
        let pair = StringPair::new(mm, "key1", "value1");
        let mut list = StringPairListItem::new(mm, pair, ptr::null_mut());

        // Add unique items to the list
        for i in 2..5 {
            list.add_unique(mm, format!("key{}", i), format!("value{}", i));
        }

        // Add duplicates
        list.add_unique(mm, "key2", "new_value2");

        let keys_values: Vec<(&str, &str)> = list.iter().map(|(k, v)| (k.to_str().unwrap(), v.to_str().unwrap())).collect();
        assert_eq!(keys_values, vec![
            ("key1", "value1"),
            ("key2", "new_value2"),
            ("key3", "value3"),
            ("key4", "value4")
        ]);
    }

    #[test]
    fn append() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        // Initialize the first list
        let pair_a1 = StringPair::new(mm, "a_key1", "a_value1");
        let mut list_a = StringPairListItem::new(mm, pair_a1, ptr::null_mut());

        for i in 2..4 {
            list_a.add(mm, format!("a_key{}", i), format!("a_value{}", i));
        }

        // Initialize the second list
        let pair_b1 = StringPair::new(mm, "b_key1", "b_value1");
        let mut list_b = StringPairListItem::new(mm, pair_b1, ptr::null_mut());

        for i in 2..4 {
            list_b.add(mm, format!("b_key{}", i), format!("b_value{}", i));
        }

        // Append list_b to list_a
        list_a.append(&mut list_b);

        let keys_values: Vec<(&str, &str)> = list_a.iter().map(|(k, v)| (k.to_str().unwrap(), v.to_str().unwrap())).collect();
        assert_eq!(keys_values, vec![
            ("a_key1", "a_value1"),
            ("a_key2", "a_value2"),
            ("a_key3", "a_value3"),
            ("b_key1", "b_value1"),
            ("b_key2", "b_value2"),
            ("b_key3", "b_value3")
        ]);
    }
}

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
use crate::buffer::{
    malloc_cleared,
    rust_str_to_c_str,
};

#[repr(C)]
pub struct StringPair {
    key: *mut c_char,
    value: *mut c_char,
}

impl StringPair {
    /// Allocates a new string pair with the specified key and value.
    ///
    /// The memory is allocated using the libc allocator. The caller
    /// is responsible for freeing it explicitly.
    fn new<S: AsRef<str>>(mm: MM, key: S, value: S) -> &'static mut Self {
        let buffer = if let Ok(buffer) = malloc_cleared::<Self>(mm) {
            buffer
        } else {
            panic!("Out of memory allocating a StringPair");
        };
        let key = rust_str_to_c_str(mm, key).expect("Out of memory allocating StringPair key");
        let value = rust_str_to_c_str(mm, value).expect("Out of memory allocating StringPair value");

        unsafe {
            (*buffer).key = key;
            (*buffer).value = value;
            &mut *buffer
        }
    }

    /// Converts the raw pointer to a Rust reference.
    ///
    /// This does not take ownership of the object.
    fn as_mut(ptr: *mut Self) -> Option<&'static mut Self> {
        unsafe { ptr.as_mut() }
    }
}

#[repr(C)]
pub struct StringPairListItem {
    pair: *mut StringPair,
    next: *mut StringPairListItem,
}

impl StringPairListItem {
    /// Allocates a new string pair item with the specified pair and next pointer.
    ///
    /// The memory is allocated using the libc allocator. The caller
    /// is responsible for freeing it explicitly.
    fn new(mm: MM, key: &str, value: &str, next: *mut Self) -> &'static mut Self {
        let buffer = if let Ok(buffer) = malloc_cleared::<Self>(mm) {
            buffer
        } else {
            panic!("Out of memory allocating a StringPairListItem");
        };

        unsafe {
            (*buffer).pair = StringPair::new(mm, key, value);
            (*buffer).next = next;
            &mut *buffer
        }
    }

    /// Converts the raw pointer to a Rust reference.
    ///
    /// This does not take ownership of the object.
    fn as_mut(ptr: *mut Self) -> Option<&'static mut Self> {
        unsafe { ptr.as_mut() }
    }
}

pub struct StringPairList {
    head: *mut StringPairListItem,
    // If set, when the StringPairList is dropped, the items are freed.
    owned: bool,
    mm: MM,
}

impl StringPairList {
    /// Converts the raw pointer to a Rust object.
    ///
    /// `owned` indicates whether the Rust code should own the items.
    /// If so, when the `StringPairList` is dropped, the items will also
    /// be freed.
    pub fn to_rust(mm: MM, head: *mut StringPairListItem, owned: bool) -> Self {
        StringPairList {
            head,
            owned,
            mm,
        }
    }

    /// Converts the Rust object to a raw pointer.
    ///
    /// The items are owned by the raw pointer and need to be freed
    /// explicitly using libc's `free`.
    pub fn to_c(mut self) -> *mut StringPairListItem {
        std::mem::replace(&mut self.head, ptr::null_mut())
    }

    /// Creates a new string pair list.
    ///
    /// The items are owned by the `StringPairList`, and when it is
    /// dropped, they are freed. To take ownership of the items, call
    /// `StringPairList::to_c`.
    pub fn new(mm: MM, key: &str, value: &str) -> Self {
        StringPairList {
            head: StringPairListItem::new(mm, key, value, ptr::null_mut()),
            owned: true,
            mm,
        }
    }

    /// Creates a new, empty string pair list.
    ///
    /// Any added items are owned by the `StringPairList`, and when it is
    /// dropped, they are freed. To take ownership of the items, call
    /// `StringPairList::to_c`.
    pub fn empty(mm: MM) -> Self {
        StringPairList {
            head: ptr::null_mut(),
            owned: true,
            mm,
        }
    }

    /// Returns an iterator over the items.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = (&'a CStr, &'a CStr)> {
        StringPairListIter {
            item: &self.head,
        }
    }

    /// Returns a mutable iterator over the items.
    pub fn iter_mut<'a>(&'a mut self) -> StringPairListIterMut {
        StringPairListIterMut {
            item: &mut self.head,
        }
    }

    /// Returns the number of items in the list.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    fn add_<S: AsRef<str>>(&mut self, key: S, value: S, dedup: bool) {
        let mm = self.mm;
        let key = key.as_ref();
        let value = value.as_ref();

        // See if the key already exists in the string pair list.
        let mut iter = self.iter_mut();
        for (k, v) in &mut iter {
            if dedup && k.to_bytes() == key.as_bytes() {
                // Update the value if deduplication is required and key already exists.
                unsafe {
                    libc::free(v.as_ptr() as *mut _);
                    *v = CString::new(value).unwrap().into_raw();
                }
                return;
            }
        }

        // It's not present yet. Add it.
        let itemp = iter.item();
        if (*itemp).is_null() {
            // 1. head is NULL (this is the case if item is NULL).
            *itemp = StringPairListItem::new(mm, key, value, ptr::null_mut());
        } else {
            let item: &mut StringPairListItem = StringPairListItem::as_mut(*itemp).expect("just checked");

            if item.pair.is_null() {
                // 2. head is not NULL, but head.pair is NULL.
                item.pair = StringPair::new(mm, key, value);
            } else {
                // 3. neither head nor head.pair are NULL.
                assert!(item.next.is_null());
                item.next = StringPairListItem::new(mm, key, value, ptr::null_mut());
            }
        }
    }

    /// Appends the item to the list.
    ///
    /// The item's ownership is determined by the list's ownership
    /// property.
    pub fn add<S: AsRef<str>>(&mut self, key: S, value: S) {
        self.add_(key, value, false)
    }

    /// Appends the item to the list if it isn't already present.
    ///
    /// The item's ownership is determined by the list's ownership
    /// property.
    pub fn add_unique<S: AsRef<str>>(&mut self, key: S, value: S) {
        self.add_(key, value, true)
    }

    /// Appends `other` to the list.
    ///
    /// The items in other have the same ownership as items in `self`.
    /// `other` is reset to an empty list.
    pub fn append(&mut self, other: &mut StringPairList) {
        let free = self.mm.free;

        let mut iter = self.iter_mut();
        (&mut iter).last();

        // There are three cases to consider:
        let itemp = iter.item();
        if (*itemp).is_null() {
            // 1. head is NULL (this is the case if item is NULL).
            *itemp = other.head;
        } else {
            let item: &mut StringPairListItem = StringPairListItem::as_mut(*itemp).expect("just checked");

            if item.pair.is_null() {
                // 2. head is not NULL, but head.pair is NULL.
                unsafe { free((*itemp) as *mut _) };
                *itemp = other.head;
            } else {
                // 3. neither head nor head.pair are NULL.
                assert!(item.next.is_null());
                item.next = other.head;
            }
        }

        other.head = ptr::null_mut();
    }
}

impl Drop for StringPairList {
    fn drop(&mut self) {
        let free = self.mm.free;

        let mut curr: *mut StringPairListItem = self.head;
        self.head = ptr::null_mut();

        if self.owned {
            loop {
                let next = if let Some(curr) = StringPairListItem::as_mut(curr) {
                    let next = curr.next;
                    if !curr.pair.is_null() {
                        unsafe {
                            let pair = StringPair::as_mut(curr.pair).unwrap();
                            libc::free(pair.key as *mut _);
                            libc::free(pair.value as *mut _);
                            libc::free(curr.pair as *mut _);
                        }
                    }
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

pub struct StringPairListIterMut<'a> {
    item: &'a mut *mut StringPairListItem,
}

impl<'a> StringPairListIterMut<'a> {
    /// Returns a reference to the StringPairListItem that will be
    /// returned next, or, if none, then a reference to the last
    /// StringPairListItem. If the list is empty, this returns a
    /// reference to the initial pointer, which will be NULL.
    fn item(&'a mut self) -> &'a mut *mut StringPairListItem {
        self.item
    }
}

impl<'a> Iterator for StringPairListIterMut<'a> {
    type Item = (&'a mut CString, &'a mut CString);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = StringPairListItem::as_mut(*self.item) {
            if item.pair.is_null() {
                None
            } else {
                self.item = &mut item.next;
                let pair = unsafe { StringPair::as_mut(item.pair).unwrap() };
                Some((
                    unsafe { CString::from_raw(pair.key) },
                    unsafe { CString::from_raw(pair.value) },
                ))
            }
        } else {
            None
        }
    }
}

pub struct StringPairListIter<'a> {
    item: &'a *mut StringPairListItem,
}

impl<'a> Iterator for StringPairListIter<'a> {
    type Item = (&'a CStr, &'a CStr);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = StringPairListItem::as_mut(*self.item) {
            if item.pair.is_null() {
                None
            } else {
                self.item = &item.next;
                let pair = unsafe { StringPair::as_mut(item.pair).unwrap() };
                Some((
                    unsafe { CStr::from_ptr(pair.key) },
                    unsafe { CStr::from_ptr(pair.value) },
                ))
            }
        } else {
            None
        }
    }
}

impl<'a> IntoIterator for &'a StringPairList {
    type Item = (&'a CStr, &'a CStr);
    type IntoIter = StringPairListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        StringPairListIter {
            item: &self.head,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        // There are two ways to make an empty list. Either head is
        // NULL or the string list item's value and next are NULL.
        let empty = StringPairList {
            head: ptr::null_mut(),
            owned: true,
            mm: mm,
        };
        assert_eq!(empty.len(), 0);

        let empty = StringPairList {
            head: StringPairListItem::new(mm, "", "", ptr::null_mut()),
            owned: true,
            mm: mm,
        };
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn add() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        for variant in 0..3 {
            let (mut list, mut v) = match variant {
                0 => {
                    let list = StringPairList::new(mm, "key1", "value1");
                    assert_eq!(list.len(), 1);

                    let mut v: Vec<(String, String)> = Vec::new();
                    v.push(("key1".into(), "value1".into()));

                    (list, v)
                },
                1 => (StringPairList::empty(mm), Vec::new()),
                2 => (StringPairList::empty(mm), Vec::new()),
                _ => unreachable!(),
            };

            let mut add_one = |k: String, v: String| {
                list.add(&k, &v);
                v.push((k, v));

                assert_eq!(list.len(), v.len());
                assert_eq!(
                    &list
                        .iter()
                        .map(|(k, v)| (String::from(k.to_str().unwrap()), String::from(v.to_str().unwrap())))
                        .collect::<Vec<(String, String)>>(),
                    &v);
            };

            for i in 1..100 {
                add_one(format!("key{}", i), format!("value{}", i));
            }
        }
    }

    #[test]
    fn add_unique() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        for variant in 0..3 {
            let (mut list, mut v) = match variant {
                0 => {
                    let list = StringPairList::new(mm, "key1", "value1");
                    assert_eq!(list.len(), 1);

                    let mut v: Vec<(String, String)> = Vec::new();
                    v.push(("key1".into(), "value1".into()));

                    (list, v)
                },
                1 => (StringPairList::empty(mm), Vec::new()),
                2 => (StringPairList::empty(mm), Vec::new()),
                _ => unreachable!(),
            };

            let mut add_one = |k: String, v: String| {
                list.add_unique(&k, &v);
                // Add adds to the back.
                if v.iter().find(|(key, _)| key == &k).is_none() {
                    v.push((k, v));
                }

                assert_eq!(list.len(), v.len());
                assert_eq!(
                    &list
                        .iter()
                        .map(|(k, v)| (String::from(k.to_str().unwrap()), String::from(v.to_str().unwrap())))
                        .collect::<Vec<(String, String)>>(),
                    &v);
            };

            for i in 1..13 {
                add_one(format!("key{}", i), format!("value{}", i));
            }
            for i in 1..19 {
                add_one(format!("key{}", i), format!("value{}", i));
            }
            for i in 1..19 {
                add_one(format!("key{}", i), format!("value{}", i));
            }
        }
    }

    #[test]
    fn append() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        for variant in 0..2 {
            // Returns a list and a vector with `count` items whose
            // values are `prefix_0`, `prefix_1`, etc.
            let list = |count: usize, prefix: &str| -> (StringPairList, Vec<(String, String)>) {
                let mut l = match variant {
                    0 => StringPairList::empty(mm),
                    1 => StringPairList::empty(mm),
                    _ => unreachable!(),
                };

                let mut v = Vec::new();
                for i in 0..count {
                    let key = format!("{}_key{}", prefix, i);
                    let value = format!("{}_value{}", prefix, i);
                    l.add(&key, &value);
                    v.push((key, value));
                }
                (l, v)
            };

            for i in 0..10 {
                for j in 0..10 {
                    let (mut a, mut av) = list(i, "a");
                    let (mut b, mut bv) = list(j, "b");

                    a.append(&mut b);
                    assert_eq!(a.len(), i + j);

                    av.append(&mut bv);
                    assert_eq!(av.len(), i + j);

                    for (i, ((ak, av), (ek, ev))) in a.iter().zip(av.iter()).enumerate() {
                        assert_eq!(ak.to_bytes(), ek.as_bytes(), "index: {}", i);
                        assert_eq!(av.to_bytes(), ev.as_bytes(), "index: {}", i);
                    }
                }
            }
        }
    }
}

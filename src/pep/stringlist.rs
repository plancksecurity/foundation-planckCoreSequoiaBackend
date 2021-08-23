//! A reimplementation of the engine's stringlist module in Rust.
//!
//! We could call out to the implementation in the engine, however,
//! then it would only be possible to use this crate when also linking
//! to the engine.  This would mean that the CLI and tests would need
//! to link to the engine, which is undesirable.
//!
//! We only implement the functionality that we actually use:
//!
//!   - new_stringlist
//!   - stringlist_length
//!   - stringlist_add
//!   - stringlist_add_unique
//!   - stringlist_append

use std::ptr;
use std::ffi::CStr;

use libc::c_char;

use crate::ffi::MM;
use crate::buffer::{
    malloc_cleared,
    rust_str_to_c_str,
};

#[repr(C)]
pub struct StringListItem {
    value: *mut c_char,
    next: *mut StringListItem,
}

impl StringListItem {
    /// Allocates a new string item with no value (i.e., NULL).
    ///
    /// The memory is allocated using the libc allocator.  The caller
    /// is responsible for freeing it explicitly.
    fn empty(mm: MM) -> &'static mut Self {
        let buffer = if let Ok(buffer) = malloc_cleared::<Self>(mm) {
            buffer
        } else {
            panic!("Out of memory allocating a StringListItem");
        };
        unsafe { &mut *(buffer as *mut Self) }
    }

    /// Allocates a new string item with the specified value and next
    /// pointer.
    ///
    /// The memory is allocated using the libc allocator.  The caller
    /// is responsible for freeing it explicitly.
    fn new<S: AsRef<str>>(mm: MM, value: S, next: *mut Self) -> &'static mut Self {
        let item = Self::empty(mm);

        item.value = rust_str_to_c_str(mm, value);
        item.next = next;

        item
    }

    /// Converts the raw pointer to a Rust reference.
    ///
    /// This does not take ownership of the object.
    fn as_mut(ptr: *mut Self) -> Option<&'static mut Self> {
        unsafe { ptr.as_mut() }
    }
}

// We wrap the StringList in a Rust object, because NULL is a valid
// stringlist_t (it's an empty string list).
pub struct StringList {
    head: *mut StringListItem,
    // If set, when the StringList is dropped, the items are freed.
    owned: bool,
    mm: MM,
}

impl StringList {
    /// Converts the raw pointer to a Rust object.
    ///
    /// `owned` indicates whether the rust code should own the items.
    /// If so, when the `StringList` is dropped, the items will also
    /// be freed.
    pub fn to_rust(mm: MM, sl: *mut StringListItem, owned: bool) -> Self
    {
        StringList {
            head: sl,
            owned,
            mm,
        }
    }

    /// Converts the Rust object to a raw pointer.
    ///
    /// The items are owned by the raw pointer and need to be freed
    /// explicitly using libc's `free`.
    pub fn to_c(mut self) -> *mut StringListItem {
        std::mem::replace(&mut self.head, ptr::null_mut())
    }

    /// Creates a new string list.
    ///
    /// The items are owned by the `StringList`, and when it is
    /// dropped, they are freed.  To take ownership of the items, call
    /// `StringList::to_c`.
    pub fn new<S: AsRef<str>>(mm: MM, value: S) -> Self {
        StringList {
            head: StringListItem::new(mm, value, ptr::null_mut()),
            owned: true,
            mm,
        }
    }

    /// Creates a new, empty string list.
    ///
    /// Any added items are owned by the `StringList`, and when it is
    /// dropped, they are freed.  To take ownership of the items, call
    /// `StringList::to_c`.
    pub fn empty(mm: MM) -> Self
    {
        StringList {
            head: ptr::null_mut(),
            owned: true,
            mm,
        }
    }

    /// There are two ways to make an empty list.  Either head is NULL
    /// or the first element's value is NULL.  This creates the second
    /// variant, which we use for testing.
    #[cfg(test)]
    fn empty_alt() -> Self {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        StringList {
            head: StringListItem::empty(mm),
            owned: true,
            mm,
        }
    }

    /// Returns an iterator over the items.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = &'a CStr> {
        StringListIter {
            item: &self.head,
        }
    }

    /// Returns a mutable iterator over the items.
    pub fn iter_mut<'a>(&'a mut self) -> StringListIterMut {
        StringListIterMut {
            item: &mut self.head,
        }
    }

    /// Returns the number of items in the list.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    fn add_<S: AsRef<str>>(&mut self, value: S, dedup: bool) {
        let mm = self.mm;

        let value = value.as_ref();

        // See if the value already exists in the string list.
        let mut iter = self.iter_mut();
        for i in &mut iter {
            if dedup && i.to_bytes() == value.as_bytes() {
                return;
            }
        }

        // It's not present yet.  Add it.

        // There are three cases to consider:
        let itemp = iter.item();
        if (*itemp).is_null() {
            // 1. head is NULL (this is the case if item is NULL).
            *itemp = StringListItem::new(mm, value, ptr::null_mut());
        } else {
            let item: &mut StringListItem
                = StringListItem::as_mut(*itemp).expect("just checked");

            if item.value.is_null() {
                // 2. head is not NULL, but head.value is NULL.
                item.value = rust_str_to_c_str(mm, value);
            } else {
                // 3. neither head nor head.value are NULL.
                assert!(item.next.is_null());
                item.next = StringListItem::new(mm, value, ptr::null_mut());
            }
        }
    }

    /// Appends the item to the list.
    ///
    /// The item's ownership is determined by the list's ownership
    /// property.
    pub fn add<S: AsRef<str>>(&mut self, value: S) {
        self.add_(value, false)
    }

    /// Appends the item to the list if it isn't already present.
    ///
    /// The item's ownership is determined by the list's ownership
    /// property.
    pub fn add_unique<S: AsRef<str>>(&mut self, value: S) {
        self.add_(value, true)
    }

    /// Appends `other` to the list.
    ///
    /// The items in other have the same ownership as items in `self`.
    /// `other` is reset to an empty list.
    pub fn append(&mut self, other: &mut StringList) {
        let free = self.mm.free;

        let mut iter = self.iter_mut();
        (&mut iter).last();

        // There are three cases to consider:
        let itemp = iter.item();
        if (*itemp).is_null() {
            // 1. head is NULL (this is the case if item is NULL).
            *itemp = other.head;
        } else {
            let item: &mut StringListItem
                = StringListItem::as_mut(*itemp).expect("just checked");

            if item.value.is_null() {
                // 2. head is not NULL, but head.value is NULL.
                unsafe { free((*itemp) as *mut _) };
                *itemp = other.head;
            } else {
                // 3. neither head nor head.value are NULL.
                assert!(item.next.is_null());
                item.next = other.head;
            }
        }

        other.head = ptr::null_mut();
    }
}

impl Drop for StringList {
    fn drop(&mut self) {
        let free = self.mm.free;

        let mut curr: *mut StringListItem = self.head;
        self.head = ptr::null_mut();

        if self.owned {
            loop {
                let next = if let Some(curr) = StringListItem::as_mut(curr) {
                    let next = curr.next;
                    unsafe { free(curr.value as *mut _) };
                    curr.value = ptr::null_mut();
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

pub struct StringListIterMut<'a> {
    item: &'a mut *mut StringListItem,
}

impl<'a> StringListIterMut<'a> {
    /// Returns a reference to the StringListItem that will be
    /// returned next, or, if none, then a reference to the last
    /// StringListItem.  If the list is empty, this returns a
    /// reference to the initial pointer, which will be NULL.
    fn item(&'a mut self) -> &'a mut *mut StringListItem {
        self.item
    }
}

impl<'a> Iterator for StringListIterMut<'a> {
    type Item = &'a CStr;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = StringListItem::as_mut(*self.item) {
            if item.value.is_null() {
                None
            } else {
                self.item = &mut item.next;
                Some(unsafe { CStr::from_ptr(item.value) })
            }
        } else {
            None
        }
    }
}

pub struct StringListIter<'a> {
    item: &'a *mut StringListItem,
}

impl<'a> Iterator for StringListIter<'a> {
    type Item = &'a CStr;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = StringListItem::as_mut(*self.item) {
            if item.value.is_null() {
                None
            } else {
                self.item = &item.next;
                Some(unsafe { CStr::from_ptr(item.value) })
            }
        } else {
            None
        }
    }
}

impl<'a> IntoIterator for &'a StringList {
    type Item = &'a CStr;
    type IntoIter = StringListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        StringListIter {
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

        // There are two ways to make an empty list.  Either head is
        // NULL or the string list item's value and next are NULL.
        let empty = StringList {
            head: ptr::null_mut(),
            owned: true,
            mm: mm,
        };
        assert_eq!(empty.len(), 0);

        let empty = StringList {
            head: StringListItem::empty(mm),
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
                    let list = StringList::new(mm, "abc");
                    assert_eq!(list.len(), 1);

                    let mut v: Vec<String> = Vec::new();
                    v.push("abc".into());

                    (list, v)
                },
                1 => (StringList::empty(mm), Vec::new()),
                2 => (StringList::empty_alt(), Vec::new()),
                _ => unreachable!(),
            };

            let mut add_one = |s: String| {
                list.add(&s);
                v.push(s);

                assert_eq!(list.len(), v.len());
                assert_eq!(
                    &list
                        .iter()
                        .map(|s| String::from(s.to_str().unwrap()))
                        .collect::<Vec<String>>(),
                    &v);
            };

            for i in 1..100 {
                add_one(format!("{}", i));
            }
        }
    }

    #[test]
    fn add_unique() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        for variant in 0..3 {
            let (mut list, mut v) = match variant {
                0 => {
                    let list = StringList::new(mm, "abc");
                    assert_eq!(list.len(), 1);

                    let mut v: Vec<String> = Vec::new();
                    v.push("abc".into());

                    (list, v)
                },
                1 => (StringList::empty(mm), Vec::new()),
                2 => (StringList::empty_alt(), Vec::new()),
                _ => unreachable!(),
            };

            let mut add_one = |s: String| {
                list.add_unique(&s);
                // Add adds to the back.
                if v.iter().find(|&x| x == &s).is_none() {
                    v.push(s);
                }

                assert_eq!(list.len(), v.len());
                assert_eq!(
                    &list
                        .iter()
                        .map(|s| String::from(s.to_str().unwrap()))
                        .collect::<Vec<String>>(),
                    &v);
            };

            for i in 1..13 {
                add_one(format!("{}", i));
            }
            for i in 1..19 {
                add_one(format!("{}", i));
            }
            for i in 1..19 {
                add_one(format!("{}", i));
            }
        }
    }

    #[test]
    fn append() {
        let mm = MM { malloc: libc::malloc, free: libc::free };

        for variant in 0..2 {
            // Returns a list and a vector with `count` items whose
            // values are `prefix_0`, `prefix_1`, etc.
            let list = |count: usize, prefix: &str| -> (StringList, Vec<String>) {
                let mut l = match variant {
                    0 => StringList::empty(mm),
                    1 => StringList::empty_alt(),
                    _ => unreachable!(),
                };

                let mut v = Vec::new();
                for i in 0..count {
                    let value = format!("{}_{}", prefix, i);
                    l.add(&value);
                    v.push(value);
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

                    for (i, (a, av)) in a.iter().zip(av.iter()).enumerate() {
                        assert_eq!(a.to_bytes(), av.as_bytes(),
                                   "index: {}", i);
                    }
                }
            }
        }
    }
}

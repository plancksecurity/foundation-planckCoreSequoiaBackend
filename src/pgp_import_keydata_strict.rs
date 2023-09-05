ffi!(fn pgp_import_keydata_strict(session: *mut Session,
                                   keydata: *const c_char,
                                   keydata_len: size_t,
                                   identity_key: *mut PepIdentity,
                                   identity_listp: *mut *mut PepIdentityListItem,
                                   imported_keysp: *mut *mut StringListItem,
                                   changed_key_indexp: *mut u64)
    -> Result<()>
{
    let session = Session::as_mut(session)?;
    let mm = session.mm();

    if imported_keysp.is_null() && ! changed_key_indexp.is_null() {
        return Err(Error::IllegalValue(
            "When changed_key_index is provided, \
             import_keys must also be provided."
                .into()));
    }

    let keydata = unsafe { check_slice!(keydata, keydata_len) };

    // We add(!) to the existing lists.
    let mut identity_list = unsafe { identity_listp.as_mut() }
        .map(|p| PepIdentityList::to_rust(mm, *p, false))
        .unwrap_or_else(|| PepIdentityList::empty(mm));
    let mut imported_keys = unsafe { imported_keysp.as_mut() }
        .map(|p| StringList::to_rust(mm, *p, false))
        .unwrap_or_else(|| StringList::empty(mm));
    let mut changed_key_index: u64 = unsafe { changed_key_indexp.as_mut() }
        .map(|p| *p)
        .unwrap_or(0);
    let identity_key = unsafe { identity_key.as_mut() }.unwrap();

    // Get the start of each ascii armor block.
    let mut offsets = Vec::new();
    let searcher = TwoWaySearcher::new(b"-----BEGIN PGP");
    loop {
        let start = offsets.iter().last().map(|&i| i + 1).unwrap_or(0);
        if let Some(i) = searcher.search_in(&keydata[start..]) {
            offsets.push(start + i);
        } else {
            break;
        }
    }

    log::trace!("armor block offsets: {:?}", offsets);

    let retval = if offsets.len() == 0 {
        return Err(Error::IllegalValue(
            "No ASCII armor found"
                .into()));
    } else if offsets.len() == 1 {
        import_keydata_strict(session,
                       &keydata[offsets[0]..],
                       identity_key,
                       &mut identity_list,
                       &mut imported_keys,
                       &mut changed_key_index)
    } else {
        return Err(Error::IllegalValue(
            "Too ASCII armored messages found."
                .into()));

    };

    unsafe { identity_listp.as_mut() }.map(|p| {
        *p = identity_list.to_c();
    });
    unsafe { imported_keysp.as_mut() }.map(|p| {
        *p = imported_keys.to_c();
    });
    unsafe { changed_key_indexp.as_mut() }.map(|p| {
        *p = changed_key_index;
    });

    retval

});
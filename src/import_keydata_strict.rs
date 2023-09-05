// Imports the keyring.  If keydata contains more than one
// ascii-armored keyring, this only imports the first ascii-armored
// keyring.
fn import_keydata_strict(session: &mut Session,
                  keydata: &[u8],
                  identity_key: &PepIdentity,
                  private_idents: &mut PepIdentityList,
                  imported_keys: &mut StringList,
                  changed_bitvec: &mut u64)
    -> Result<()>
{
    log::trace!("import_keydata");

    let keystore = session.keystore();

    // We need to look at the first packet to figure out what we
    // should do.
    let ppr = match PacketParser::from_bytes(keydata) {
        Ok(ppr) => ppr,
        Err(err) =>
            return Err(Error::UnknownError(
                err, "Creating packet parser".into())),
    };
    let packet = match ppr.as_ref() {
        Ok(pp) => &pp.packet,
        Err(_eof) => {
            return Err(Error::UnknownError(
                anyhow::anyhow!("Unexpected EOF").into(),
                "No data".into()));
        }
    };

    match packet {
        Packet::Signature(sig) => {
            // Check that we have a certificate revocation
            // certification.  If so, try to import it.
            if sig.typ() != SignatureType::KeyRevocation {
                log::trace!("Can't import a {} signature", sig.typ());
                return Err(Error::NoKeyImported);
            }

            for issuer in sig.get_issuers().into_iter() {
                match keystore.cert_find_with_key(issuer.clone(), false) {
                    Err(err) => {
                        log::trace!("Can't merge signature: \
                            no certificate for {} available: {}",
                           issuer, err);
                    }
                    Ok((cert, _)) => {
                        let fpr = cert.fingerprint();
                        if let Err(err)
                            = sig.clone().verify_primary_key_revocation(
                                &cert.primary_key(),
                                &cert.primary_key())
                        {
                            log::trace!("Revocation certificate not issued by {}: {}",
                               fpr, err);
                            continue;
                        }

                        match cert.insert_packets(sig.clone()) {
                            Err(err) => {
                                log::trace!("Merging signature with {} failed: {}",
                                   fpr, err);
                                // This trumps any other error.
                                return wrap_err!(
                                    Err(err),
                                    UnknownError,
                                    "inserting packets");
                            }
                            Ok(cert) => {
                                match keystore.cert_save(cert) {
                                    Ok((_, changed)) => {
                                        let count = imported_keys.len();
                                        if changed && count < 64 {
                                            *changed_bitvec |= 1 << count;
                                        }
                                        imported_keys.add(fpr.to_hex());
                                        return Err(Error::KeyImported);
                                    }
                                    Err(err) => {
                                        log::trace!("Saving updated certificate {} \
                                            failed: {}",
                                           fpr, err);
                                        // This trumps any other error.
                                        return Err(err);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            log::trace!("Failed to import revocation certificate allegedly issued by {:?}.",
               sig
                 .issuers().next()
                 .map(|kh| kh.to_hex())
                 .unwrap_or("<no issuer subpacket>".into()));

            return Err(Error::NoKeyImported);
        }
        Packet::PublicKey(_) | Packet::SecretKey(_) => {
            let mut got_one = false;
            for certo in CertParser::from(ppr) {
                match certo {
                    Ok(cert) => {
                        let fpr = cert.fingerprint();

                        log::trace!("Importing certificate {}", fpr);
                        let mut contained = false;
                        for ua in cert.userids() {
                            log::trace!("  User ID: {}", ua.userid());
                            if let Ok(Some(key_id)) = ua.userid().email(){
                                if let Some(user_id) = identity_key.address() {
                                    if (key_id == String::from_utf8_lossy(user_id.to_bytes())){
                                        contained=true;
                                    }
                                }
                            }
                        }
                        //If we do not contain the ID given, cease.
                        if (!contained){
                            continue;
                        }
                        let is_tsk = cert.is_tsk();
                        let (ident, changed)
                            = session.keystore().cert_save(cert)?;
                        imported_keys.add(fpr.to_hex());
                        log::trace!("Adding {} to imported_keys", fpr);
                        if let Some(ident) = ident {
                            if is_tsk {
                                log::trace!("Adding {:?} to private_idents", ident);
                                private_idents.add(&ident);
                            }
                        }
                        if changed {
                            let i = imported_keys.len() - 1;
                            if i < 64 {
                                (*changed_bitvec) |= 1 << i;
                            }
                        }

                        got_one = true;
                    }
                    e @ Err(_) => {
                        wrap_err!(e,
                                  UnknownError,
                                  "Error reading keyring")?;
                    }
                }
            }

            if !got_one {
                Err(Error::NoKeyImported)
            } else {
                Err(Error::KeyImported)
            }
        }
        packet => {
            log::trace!("Can't import a {} packet", packet.tag());
            Err(Error::NoKeyImported)
        }
    }
}
use libc::c_char;
use sequoia_openpgp::packet::key::{
    KeyRole, PrimaryRole, SecretKeyMaterial, SecretParts, SubordinateRole,
};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::{crypto::Password, Fingerprint};
use sequoia_openpgp::{Cert, Packet};
use std::ffi::CStr;

use crate::pep::{Error, PepIdentity, Result, Session};

use crate::ErrorCode;

ffi!(
    fn pgp_manage_passphrase(
        session: &mut Session,
        identity: *const PepIdentity,
        old_passphrase: *const c_char,
        passphrase: *const c_char) -> Result<()> {
        let fpr_str = unsafe { identity.as_ref() }
            .map(|i| i.fingerprint())
            .flatten()
            .ok_or_else(|| illegal_value("no fingerprint on identity"))?
            .to_str()
            .map_err(|_| illegal_value("cannot convert identity fingerprint to a string"))?;

        let fingerprint = Fingerprint::from_hex(fpr_str)
            .map_err(|_| illegal_value("cannot create fingerprint from hex value"))?;

        let (cert, _) = session.keystore().cert_find(fingerprint.clone(), true)?;

        if !cert.is_tsk() {
            return Err(illegal_value("have no secret key"));
        }

        let new_passphrase = unsafe { check_cstr!(passphrase) }
            .to_str()
            .map_err(|_| illegal_value("new passphrase cannot be converted to string"))?;

        let remove_passphrase = { new_passphrase.is_empty() };

        let new_passphrase = Password::from(new_passphrase);
        let old_passphrase = unsafe { check_cstr!(old_passphrase) }
            .to_str()
            .map_err(|_| illegal_value("passphrase cannot be converted to string"))
            .map(|s| Password::from(s))?;

        let decrypted_packets = decrypted_packets(&cert, &old_passphrase)?;

        let cert = cert
            .insert_packets(decrypted_packets)
            .map_err(|_| illegal_value("cannot not re-insert decrypted packets"))?;

        let cert = if remove_passphrase {
            cert
        } else {
            let encrypted_packets = encrypted_packets(&cert, &new_passphrase)?;
            cert.insert_packets(encrypted_packets)
                .map_err(|_| illegal_value("cannot not re-insert encrypted packets"))?
        };

        // The way `cert_save` handles certificate merging makes this step necessary.
        // Otherwise, you'll end up with secrets encrypted with the old key.
        session.keystore().cert_delete(fingerprint)?;

        session.keystore().cert_save(cert)?;

        Ok(())
    }
);

fn illegal_value(str: &str) -> Error {
    Error::IllegalValue(str.to_string())
}

fn wrong_passphrase() -> Error {
    Error::WrongPassphrase(
        anyhow::anyhow!("wrong passphrase"),
        "wrong passphrase".to_string(),
    )
}

fn decrypt_key<R>(key: Key<SecretParts, R>, password: &Password) -> Result<Key<SecretParts, R>>
where
    R: KeyRole + Clone,
{
    let key = key
        .parts_as_secret()
        .map_err(|e| illegal_value(&e.to_string()))?;
    match key.secret() {
        SecretKeyMaterial::Unencrypted(_) => Ok(key.clone()),
        SecretKeyMaterial::Encrypted(e) => {
            if !e.s2k().is_supported() {
                return Err(illegal_value("unsupported key protection"));
            }

            if let Ok(key) = key.clone().decrypt_secret(password) {
                return Ok(key);
            }

            Err(wrong_passphrase())
        }
    }
}

fn _map_packets<
    R: KeyRole + Clone,
    F1: Fn(Key<SecretParts, PrimaryRole>) -> Key<SecretParts, PrimaryRole>,
    F2: Fn(Key<SecretParts, SubordinateRole>) -> Key<SecretParts, SubordinateRole>,
>(
    cert: &Cert,
    primary_fn: F1,
    subordinate_fn: F2,
) -> Result<Vec<Packet>> {
    let primary_key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| illegal_value("primary key has no secret parts"))?;
    let primary_key = primary_fn(primary_key);

    let mut packets: Vec<Packet> = vec![primary_key.into()];

    for key_amalgamation in cert.keys().subkeys().secret() {
        let secondary_key = key_amalgamation
            .key()
            .clone()
            .parts_into_secret()
            .map_err(|_| illegal_value("secondary key has no secret parts"))?;
        let secondary_key = subordinate_fn(secondary_key);
        let secondary_packet: Packet = secondary_key.into();
        packets.push(secondary_packet);
    }
    Ok(packets)
}

fn decrypted_packets(cert: &Cert, passphrase: &Password) -> Result<Vec<Packet>> {
    let primary_key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| illegal_value("primary key has no secret parts"))?;

    let pk_packet: Packet = decrypt_key(primary_key, &passphrase)?.into();
    let mut decrypted_packets: Vec<Packet> = vec![pk_packet];

    for key_amalgamation in cert.keys().subkeys().secret() {
        let secondary_key = key_amalgamation
            .key()
            .clone()
            .parts_into_secret()
            .map_err(|_| illegal_value("secondary key has no secret parts"))?;
        let secondary_packet: Packet = decrypt_key(secondary_key, &passphrase)?.into();
        decrypted_packets.push(secondary_packet);
    }

    Ok(decrypted_packets)
}

fn encrypted_packets(cert: &Cert, passphrase: &Password) -> Result<Vec<Packet>> {
    let pk_packet: Packet = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| illegal_value("primary key has no secret parts"))?
        .encrypt_secret(&passphrase)
        .map_err(|_| illegal_value("cannot encrypt primary key"))?
        .into();
    let mut encrypted_packets: Vec<Packet> = vec![pk_packet];

    for key_amalgamation in cert.keys().subkeys().unencrypted_secret() {
        let secondary_packet: Packet = key_amalgamation
            .key()
            .clone()
            .parts_into_secret()
            .map_err(|_| illegal_value("unencrypted secondary key has no secret parts"))?
            .encrypt_secret(&passphrase)
            .map_err(|_| illegal_value("cannot encrypt secondary key"))?
            .into();
        encrypted_packets.push(secondary_packet);
    }

    Ok(encrypted_packets)
}

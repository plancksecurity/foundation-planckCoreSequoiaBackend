use libc::c_char;
use sequoia_openpgp::packet::key::{KeyRole, SecretKeyMaterial, SecretParts};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::Packet;
use sequoia_openpgp::{crypto::Password, Fingerprint};

use crate::pep::{Error, PepIdentity, Result, Session};

use crate::ErrorCode;

fn decrypt_key<R>(key: Key<SecretParts, R>, password: &Password) -> Result<Key<SecretParts, R>>
where
    R: KeyRole + Clone,
{
    let error_fn = |s: &str| Error::IllegalValue(s.to_string());

    let key = key
        .parts_as_secret()
        .map_err(|e| error_fn(&e.to_string()))?;
    match key.secret() {
        SecretKeyMaterial::Unencrypted(_) => Ok(key.clone()),
        SecretKeyMaterial::Encrypted(e) => {
            if !e.s2k().is_supported() {
                return Err(error_fn("unsupported key protection"));
            }

            if let Ok(key) = key.clone().decrypt_secret(password) {
                return Ok(key);
            }

            Err(error_fn("unable to decrypt secret key material"))
        }
    }
}

ffi!(
    fn pgp_manage_passphrase(
        session: &mut Session,
        identity: *const PepIdentity,
        old_passphrase: *const c_char,
        passphrase: *const c_char) -> Result<()> {
        trace!(
            "pgp_manage_passphrase({:?}, {:?}, {:?}, {:?})",
            session.version,
            identity,
            old_passphrase,
            passphrase
        );

        let error_fn = |s: &str| Error::IllegalValue(s.to_string());

        let fpr_str = unsafe {
            identity
                .as_ref()
                .map(|i| i.fingerprint())
                .flatten()
                .ok_or_else(|| error_fn("no fingerprint on identity"))?
                .to_str()
                .map_err(|_| error_fn("cannot convert identity fingerprint to a string"))?
        };

        let fingerprint = Fingerprint::from_hex(fpr_str)
            .map_err(|_| error_fn("cannot create fingerprint from hex value"))?;

        let (cert, _) = session.keystore().cert_find(fingerprint, true)?;

        if !cert.is_tsk() {
            return Err(error_fn("have no secret key"));
        }

        let mk_passphrase = |pass: *const c_char| {
            unsafe { pass.as_ref() }
                .map(|chars| chars.to_string())
                .map(|s| Password::from(s))
                .ok_or_else(|| error_fn("passphrase cannot be converted"))
        };

        let old_passphrase = mk_passphrase(old_passphrase)?;
        let _new_passphrase = mk_passphrase(passphrase)?;

        let pk = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .map_err(|_| error_fn("primary key has no secret parts"))?;

        let pk_packet: Packet = decrypt_key(pk, &old_passphrase)?.into();
        let mut _decrypted: Vec<Packet> = vec![pk_packet];

        Ok(())
    }
);

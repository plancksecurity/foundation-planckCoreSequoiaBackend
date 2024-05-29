use libc::c_char;
use sequoia_openpgp::packet::key::{KeyRole, SecretKeyMaterial, SecretParts};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::{crypto::Password, Fingerprint};

use crate::pep::{Error, PepIdentity, Result, Session};

use crate::ErrorCode;

fn _decrypt_key<R>(key: Key<SecretParts, R>, password: &Password) -> Result<Key<SecretParts, R>>
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

        let illegal_value = || Error::IllegalValue("malformed identity fpr".to_string());
        let no_secret_key = || Error::IllegalValue("no secret key".to_string());

        let fpr_str = unsafe {
            identity
                .as_ref()
                .map(|i| i.fingerprint())
                .flatten()
                .ok_or_else(|| illegal_value())?
                .to_str()
                .map_err(|_| illegal_value())?
        };

        let fingerprint = Fingerprint::from_hex(fpr_str).map_err(|_| illegal_value())?;

        let (cert, _) = session.keystore().cert_find(fingerprint, true)?;

        if !cert.is_tsk() {
            return Err(no_secret_key());
        }

        let mk_passphrase = |pass: *const c_char| {
            unsafe { pass.as_ref() }
                .map(|chars| chars.to_string())
                .map(|s| Password::from(s))
                .ok_or_else(|| Error::IllegalValue("passphrase cannot be converted".to_string()))
        };

        let _old_passphrase = mk_passphrase(old_passphrase)?;
        let _new_passphrase = mk_passphrase(passphrase)?;

        let _pk = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .map_err(|_| no_secret_key())?;

        Ok(())
    }
);

use libc::c_char;
use sequoia_openpgp::{crypto::Password, Fingerprint};

use crate::pep::{Error, PepIdentity, Result, Session};

use crate::ErrorCode;

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

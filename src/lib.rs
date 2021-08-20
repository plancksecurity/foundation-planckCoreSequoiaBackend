use std::cmp;
use std::convert::TryInto;
use std::env;
use std::ffi::{
    CStr,
    OsStr,
};
use std::io::{
    Read,
    Write,
};
use std::mem;
use std::path::Path;
use std::ptr;
use std::slice;
use std::time::{
    Duration,
    SystemTime,
    UNIX_EPOCH,
};

use libc::{
    c_char,
    c_uint,
    malloc,
    size_t,
    time_t,
};

use chrono::Utc;
use chrono::TimeZone;

use memmem::{Searcher, TwoWaySearcher};

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::{
    amalgamation::ValidAmalgamation,
    CertBuilder,
    CertParser,
    ValidCert,
};
use openpgp::crypto::{
    Password,
    SessionKey,
};
use openpgp::Fingerprint;
use openpgp::Packet;
use openpgp::packet::{
    key,
    Key,
    PKESK,
    SKESK,
    UserID,
};
use openpgp::parse::{
    Parse,
    PacketParser,
    stream::{
        DecryptionHelper,
        DecryptorBuilder,
        DetachedVerifierBuilder,
        GoodChecksum,
        MessageLayer,
        MessageStructure,
        VerificationHelper,
        VerificationError,
    }
};
use openpgp::policy::NullPolicy;
use openpgp::serialize::{
    stream::{
        Armorer,
        Encryptor,
        LiteralWriter,
        Message,
        Recipient,
        Signer,
    },
    Serialize,
};
use openpgp::types::{
    ReasonForRevocation,
    RevocationStatus,
    SignatureType,
    SymmetricAlgorithm,
};

#[macro_use] mod log;
mod constants;
#[macro_use] mod pep;
use pep::{
    Error,
    ErrorCode,
    PepCipherSuite,
    PepCommType,
    PepEncFormat,
    PepIdentity,
    PepIdentityFlags,
    PepIdentityList,
    PepIdentityListItem,
    Result,
    Session,
    StringList,
    StringListItem,
    Timestamp,
};
#[macro_use] mod ffi;
mod keystore;
use keystore::Keystore;
mod buffer;

use crate::buffer::rust_bytes_to_c_str_lossy;

// If the PEP_TRACE environment variable is set or we are built in
// debug mode, then enable tracing.
lazy_static::lazy_static! {
    static ref TRACE: bool = {
        if cfg!(debug_assertions) {
            true
        } else if let Ok(_) = env::var("PEP_TRACE") {
            true
        } else {
            false
        }
    };
}

pub const P: &NullPolicy = &NullPolicy::new();

// Given the pEp cipher suite indicator enum, return the equivalent
// sequoia cipher suite enum value
//
// PEP_STATUS pgp_config_cipher_suite(PEP_SESSION session,
//         PEP_CIPHER_SUITE suite)
ffi!(fn pgp_config_cipher_suite(session: *mut Session, suite: PepCipherSuite)
    -> Result<()>
{
    let session = Session::as_mut(session);
    session.set_cipher_suite(suite)
});

// Decrypts the key.
//
// On success, returns the decrypted key.
fn _pgp_get_decrypted_key(key: Key<key::SecretParts, key::UnspecifiedRole>,
                          pass: Option<&Password>)
    -> Result<Key<key::SecretParts, key::UnspecifiedRole>>
{
    tracer!(*crate::TRACE, "_pgp_get_decrypted_key");

    match key.secret() {
        key::SecretKeyMaterial::Unencrypted { .. } => Ok(key),
        key::SecretKeyMaterial::Encrypted { .. } => {
            let fpr = key.fingerprint();
            if let Some(pass) = pass {
                wrap_err!(
                    key.decrypt_secret(pass),
                    WrongPassphrase,
                    format!("Decrypting secret key material for {}", fpr))
            } else {
                t!("Can't decrypt {}: no password configured", fpr);
                Err(Error::PassphraseRequired)
            }
        }
    }
}

// Returns the first key in iter that is already decrypted or can be
// decrypted using `pass`.
fn _pgp_get_decrypted_key_iter<'a, I>(iter: I, pass: Option<&Password>)
    -> Result<Key<key::SecretParts, key::UnspecifiedRole>>
    where I: Iterator<Item=&'a Key<key::SecretParts, key::UnspecifiedRole>>
{
    // Return the "best" (most helpful to the user) error.
    let mut bad_pass = None;
    let mut missing_pass = false;
    let mut other_error = None;

    for key in iter {
        match _pgp_get_decrypted_key(key.clone(), pass) {
            Ok(key) => return Ok(key),
            Err(err @ Error::WrongPassphrase(_, _)) => bad_pass = Some(err),
            Err(Error::PassphraseRequired) => missing_pass = true,
            Err(err) => other_error = Some(err),
        }
    }

    if let Some(err) = bad_pass {
        Err(err)
    } else if missing_pass {
        Err(Error::PassphraseRequired)
    } else if let Some(err) = other_error {
        Err(err)
    } else {
        Err(Error::UnknownError(
            anyhow::anyhow!("decrypting secret key material"),
            "empty iterator".into()))
    }
}

// PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
ffi!(fn pgp_init_(session: *mut Session, _in_first: bool,
                  per_user_directory: *const c_char,
                  session_size: c_uint,
                  session_cookie_offset: c_uint,
                  session_curr_passphrase_offset: c_uint,
                  session_new_key_pass_enable: c_uint,
                  session_generation_passphrase_offset: c_uint,
                  session_cipher_suite_offset: c_uint,
                  pep_status_size: c_uint,
                  pep_comm_type_size: c_uint,
                  pep_enc_format_size: c_uint,
                  pep_identity_flags_size: c_uint,
                  pep_cipher_suite_size: c_uint,
                  string_list_item_size: c_uint,
                  pep_identity_size: c_uint,
                  pep_identity_list_item_size: c_uint,
                  timestamp_size: c_uint,
                  _stringpair_size: c_uint,
                  _stringpair_list_size: c_uint,
                  magic: c_uint)
    -> Result<()>
{
    use std::mem::size_of;
    use memoffset::offset_of;

    assert_eq!(magic, 0xDEADBEEF);

    assert!(session_size as usize >= size_of::<Session>());
    assert_eq!(session_cookie_offset as usize,
               offset_of!(Session, state));
    assert_eq!(session_curr_passphrase_offset as usize,
               offset_of!(Session, curr_passphrase));
    assert_eq!(session_new_key_pass_enable as usize,
               offset_of!(Session, new_key_pass_enabled));
    assert_eq!(session_generation_passphrase_offset as usize,
               offset_of!(Session, generation_passphrase));
    assert_eq!(session_cipher_suite_offset as usize,
               offset_of!(Session, cipher_suite));
    assert_eq!(pep_status_size as usize, size_of::<ErrorCode>());
    assert_eq!(pep_comm_type_size as usize, size_of::<PepCommType>());
    assert_eq!(pep_enc_format_size as usize, size_of::<PepEncFormat>());
    assert_eq!(pep_identity_flags_size as usize, size_of::<PepIdentityFlags>());
    assert_eq!(pep_cipher_suite_size as usize, size_of::<PepCipherSuite>());
    assert_eq!(string_list_item_size as usize, size_of::<StringListItem>());
    assert_eq!(pep_identity_size as usize, size_of::<PepIdentity>());
    assert_eq!(pep_identity_list_item_size as usize, size_of::<PepIdentityListItem>());
    assert_eq!(timestamp_size as usize, size_of::<Timestamp>());
    // assert_eq!(stringpair_size as usize, size_of::<StringPair>());
    // assert_eq!(stringpair_list_size as usize, size_of::<StringPairList>());

    let session = Session::as_mut(session);

    if per_user_directory.is_null() {
        return Err(Error::IllegalValue(
            "per_user_directory may not be NULL".into()));
    }
    let per_user_directory = unsafe { CStr::from_ptr(per_user_directory) };

    #[cfg(not(windows))]
    let per_user_directory = {
        use std::os::unix::ffi::OsStrExt;
        OsStr::from_bytes(per_user_directory.to_bytes())
    };
    #[cfg(windows)]
    let per_user_directory = {
        use std::ffi::OsString;
        use std::os::windows::prelude::*;

        let os_string = OsString::from_wide(per_user_directory.as_bytes());
        os_string.as_os_str()
    };

    let ks = keystore::Keystore::init(Path::new(per_user_directory))?;
    session.init(ks);

    Ok(())
});

// void pgp_release(PEP_SESSION session, bool out_last)
ffi!(fn pgp_release(session: *mut Session, _out_last: bool) -> Result<()> {
    Session::as_mut(session).deinit();
    Ok(())
});

// Cookie used by the decryption and verification logic.
struct Helper<'a> {
    session: &'a mut Session,

    secret_keys_called: bool,
    recipient_keylist: StringList,
    signer_keylist: StringList,

    good_checksums: usize,
    malformed_signature: usize,
    missing_keys: usize,
    unbound_key: usize,
    revoked_key: usize,
    expired_key: usize,
    bad_key: usize,
    bad_checksums: usize,

    // Whether we decrypted anything.
    decrypted: bool,

    // The filename stored in the literal data packet.  Note: this is
    // *not* protected by the signature and should not be trusted!!!
    filename: Option<Vec<u8>>,
}

impl<'a> Helper<'a> {
    fn new(session: &'a mut Session) -> Self {
        Helper {
            session: session,
            secret_keys_called: false,
            recipient_keylist: StringList::empty(),
            signer_keylist: StringList::empty(),
            good_checksums: 0,
            malformed_signature: 0,
            missing_keys: 0,
            unbound_key: 0,
            revoked_key: 0,
            expired_key: 0,
            bad_key: 0,
            bad_checksums: 0,
            decrypted: false,
            filename: None,
        }
    }
}

impl<'a> VerificationHelper for &mut Helper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle])
        -> openpgp::Result<Vec<Cert>>
    {
        let mut certs = Vec::new();

        for id in ids {
            if let Ok((cert, _private))
                = self.session.keystore().cert_find_with_key(id.clone(), false)
            {
                certs.push(cert);
            }
        }

        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure)
        -> openpgp::Result<()>
    {
        tracer!(*crate::TRACE, "Helper::check");

        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    match result {
                        Ok(GoodChecksum { sig, ka }) => {
                            // We need to add the fingerprint of
                            // the primary key to signer_keylist.

                            let primary_fpr = ka.cert().fingerprint();

                            self.signer_keylist.add_unique(
                                primary_fpr.to_hex());

                            t!("Good signature ({:02X}{:02X}) from {}",
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               primary_fpr);

                            self.good_checksums += 1;
                        }
                        Err(VerificationError::MalformedSignature { sig, error }) => {
                            t!("Malformed signature ({:02X}{:02X}) \
                                allegedly from {:?}: {}",
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               sig.issuers().next(),
                               error);
                            self.malformed_signature += 1;
                        }
                        Err(VerificationError::MissingKey { sig }) => {
                            t!("No key to check signature ({:02X}{:02X}) \
                                allegedly from {:?}",
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               sig.issuers().next());
                            self.missing_keys += 1;
                        }
                        Err(VerificationError::UnboundKey { sig, cert, error }) => {
                            // This happens if the key doesn't have a binding
                            // signature.

                            t!("Certificate {} has no valid self-signature; \
                                can't check signature ({:02X}{:02X}): {}",
                               cert.fingerprint(),
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               error);

                            self.unbound_key += 1;
                        }
                        Err(VerificationError::BadKey { sig, ka, error }) => {
                            // This happens if the certificate is not
                            // alive or revoked, if the key is not
                            // alive or revoked, of if the key is not
                            // signing capable.
                            t!("Can't check signature ({:02X}{:02X}): \
                                key {} is bad: {}",
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               ka.cert().fingerprint(),
                               error);

                            // Check if the key or certificate is revoked.
                            if let RevocationStatus::Revoked(_)
                                = ka.revocation_status()
                            {
                                t!("reason: key is revoked");
                                self.revoked_key += 1;
                            } else if let RevocationStatus::Revoked(_)
                                = ka.cert().revocation_status()
                            {
                                t!("reason: cert is revoked");
                                self.revoked_key += 1;
                            }
                            // Check if the key or certificate is expired.
                            else if let Err(err) = ka.cert().alive() {
                                t!("reason: cert is expired: {}", err);
                                self.expired_key += 1;
                            }
                            else if let Err(err) = ka.alive() {
                                // Key is expired.
                                t!("reason: key is expired: {}", err);
                                self.expired_key += 1;
                            }
                            // Wrong key flags or something similar.
                            else {
                                t!("reason: other");
                                self.bad_key += 1;
                            }
                        }
                        Err(VerificationError::BadSignature { sig, ka, error }) => {
                            t!("Bad signature ({:02X}{:02X}) from {}: {}",
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               ka.cert().fingerprint(),
                               error);
                            self.bad_checksums += 1;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // Save the filename in the literal data packet.
    fn inspect(&mut self, pp: &PacketParser<'_>) -> openpgp::Result<()> {
        if let Packet::Literal(ref lit) = pp.packet {
            if let Some(filename) = lit.filename() {
                self.filename = Some(filename.to_vec());
            }
        }

        Ok(())
    }
}

impl<'a> DecryptionHelper for &mut Helper<'a> {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], _: &[SKESK],
                  sym_algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D)
        -> openpgp::Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        tracer!(*crate::TRACE, "Helper::decrypt");

        let password = self.session.curr_passphrase();
        let keystore = self.session.keystore();

        // Whether there are any wildcard recipients.
        let mut have_wildcards = false;

        // The certificate that decrypted the message.
        let mut decryption_identity = None;

        let mut missing_passphrase = false;
        let mut bad_passphrase = None;

        if self.secret_keys_called {
            // Prevent iterations, which isn't needed since we don't
            // support SKESKs.
            return Err(anyhow::anyhow!("SKESKs not supported"));
        }
        self.secret_keys_called = true;

        t!("{} PKESKs", pkesks.len());

        for pkesk in pkesks.iter() {
            let keyid = pkesk.recipient();
            if keyid.is_wildcard() {
                // Initially ignore wildcards.
                have_wildcards = true;
                continue;
            }

            t!("Considering PKESK for {}", keyid);

            // Collect the recipients.  Note: we must return the
            // primary key's fingerprint.
            let (cert, private)
                = match keystore.cert_find_with_key(keyid.clone(), false)
            {
                Err(Error::KeyNotFound(_)) => continue,
                Err(err) => {
                    t!("Error looking up {}: {}", keyid, err);
                    continue;
                }
                Ok((cert, private)) => (cert, private)
            };

            self.recipient_keylist.add_unique(cert.fingerprint().to_hex());

            if self.decrypted {
                // We already have the session key.  We are just
                // trying to collect the alleged recipients now.
                continue;
            }

            // Try to decrypt this PKESK.
            if ! private {
                continue;
            }

            let ka = match cert.keys().filter(|ka| *keyid == ka.keyid()).next() {
                Some(ka) => ka,
                None => {
                    t!("Inconsistent DB: cert {} doesn't contain a subkey with \
                        keyid {}, but DB says it does!",
                       cert.fingerprint(), keyid);
                    continue;
                }
            };

            if let Ok(key) = ka.key().clone().parts_into_secret() {
                let fpr = key.fingerprint();
                let key = match _pgp_get_decrypted_key(key, password.as_ref()) {
                    Ok(key) => key,
                    Err(err @ Error::WrongPassphrase(_, _)) => {
                        bad_passphrase = Some(err);
                        continue;
                    }
                    Err(Error::PassphraseRequired) => {
                        missing_passphrase = true;
                        continue;
                    }
                    Err(err) => {
                        t!("While decrypting {}: {}", fpr, err);
                        continue;
                    }
                };

                let mut keypair = match key.into_keypair() {
                    Ok(keypair) => keypair,
                    Err(err) => {
                        t!("Creating keypair for {}: {}", fpr, err);
                        continue;
                    }
                };

                match pkesk.decrypt(&mut keypair, sym_algo) {
                    Some((sym_algo, sk)) => {
                        if decrypt(sym_algo, &sk) {
                            decryption_identity = Some(cert.fingerprint());
                            self.decrypted = true;
                        }
                    }
                    None => {
                        t!("Failed to decrypt PKESK for {}", fpr);
                    }
                }
            }
        }

        let mut tsks = None;
        if have_wildcards && ! self.decrypted {
            for pkesk in pkesks.iter() {
                let keyid = pkesk.recipient();
                if ! keyid.is_wildcard() {
                    // We're only considering the wildcard PKESKs.
                    continue;
                }

                if tsks.is_none() {
                    // Load all certificates with secret key material.
                    tsks = Some(keystore.cert_all(true)?);
                    if tsks.as_ref().unwrap().len() == 0 {
                        // We don't have any keys with secret key
                        // material.  We're done.
                        break;
                    }
                }

                for (tsk, _private) in tsks.as_ref().unwrap().iter() {
                    for ka in tsk.keys().secret() {
                        let key = match _pgp_get_decrypted_key(
                            ka.key().clone(), password.as_ref())
                        {
                            Ok(key) => key,
                            Err(err @ Error::WrongPassphrase(_, _)) => {
                                bad_passphrase = Some(err);
                                continue;
                            }
                            Err(Error::PassphraseRequired) => {
                                missing_passphrase = true;
                                continue;
                            }
                            Err(err) => {
                                t!("decrypting {}: {}",
                                   ka.fingerprint(), err);
                                continue;
                            }
                        };

                        let mut keypair = match key.into_keypair() {
                            Ok(keypair) => keypair,
                            Err(err) => {
                                t!("Creating keypair for {}: {}",
                                   ka.fingerprint(), err);
                                continue;
                            }
                        };

                        // Note: for decryption to appear to succeed,
                        // we must get a valid algorithm (8 of 256
                        // values) and a 16-bit checksum must match.
                        // Thus, we have about a 1 in 2**21 chance of
                        // having a false positive here.

                        match pkesk.decrypt(&mut keypair, sym_algo) {
                            Some((sym_algo, sk)) => {
                                // Add it to the recipient list.
                                t!("wildcard recipient appears to be {}",
                                   ka.fingerprint());

                                if decrypt (sym_algo, &sk) {
                                    decryption_identity
                                        = Some(tsk.fingerprint());
                                    self.recipient_keylist.add_unique(
                                        tsk.fingerprint().to_hex());
                                    self.decrypted = true;
                                    break;
                                } else {
                                    t!("Failed to decrypt message \
                                        using ESK decrypted by {}",
                                       ka.fingerprint());
                                    continue;
                                }
                            }
                            None => {
                                t!("Failed to decrypt PKESK for {}",
                                   ka.fingerprint());
                                continue;
                            }
                        };
                    }
                }
            }
        }

        if self.decrypted {
            Ok(decryption_identity)
        } else {
            if let Some(err) = bad_passphrase.take() {
                Err(err.into())
            } else if missing_passphrase {
                Err(Error::PassphraseRequired.into())
            } else {
                Err(Error::DecryptNoKey(
                    anyhow::anyhow!("No key")).into())
            }
        }
    }
}

// PEP_STATUS pgp_decrypt_and_verify(
//     PEP_SESSION session, const char *ctext, size_t csize,
//     const char *dsigtext, size_t dsigsize,
//     char **ptext, size_t *psize, stringlist_t **keylist,
//     char** filename_ptr)
ffi!(fn pgp_decrypt_and_verify(session: *mut Session,
                               ctext: *const c_char, csize: size_t,
                               dsigtext: *const c_char, _dsigsize: size_t,
                               ptext: *mut *mut c_char, psize: *mut size_t,
                               keylistp: *mut *mut StringListItem,
                               filename_ptr: *mut *mut c_char)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if ctext.is_null() {
        return Err(Error::IllegalValue(
            "ctext may not be NULL".into()));
    }
    let ctext = unsafe {
        std::slice::from_raw_parts(ctext as *const u8, csize)
    };

    // XXX: We don't handle detached signatures over encrypted
    // messages (and never have).
    if ! dsigtext.is_null() {
        return Err(Error::IllegalValue(
            "detached signatures over encrypted data are not supported".into()));
    }

    unsafe {
        ptext.as_mut().map(|p| *p = ptr::null_mut());
        psize.as_mut().map(|p| *p = 0);
    }

    let mut h = Helper::new(session);

    let decryptor = wrap_err!(
        DecryptorBuilder::from_bytes(ctext),
        UnknownError,
        "DecryptorBuilder")?;

    let mut decryptor = match decryptor.with_policy(crate::P, None, &mut h) {
        Ok(decryptor) => decryptor,
        Err(err) => {
            match err.downcast::<Error>() {
                Ok(err) => return Err(err),
                Err(err) => return Err(Error::DecryptNoKey(err)),
            }
        }
    };

    let mut content = Vec::new();
    wrap_err!(decryptor.read_to_end(&mut content),
              UnknownError,
              "read_to_end")?;

    let h = decryptor.helper_mut();
    if ! h.decrypted {
        return Err(Error::DecryptNoKey(anyhow::anyhow!("decryption failed")));
    }

    // Add a terminating NUL for naive users.
    content.push(0);

    unsafe {
        if let Some(ptextp) = ptext.as_mut() {
            let buffer = malloc(content.len()) as *mut u8;
            if buffer.is_null() {
                return Err(Error::OutOfMemory(
                    "content".into(), content.len()));
            }
            slice::from_raw_parts_mut(buffer, content.len())
                .copy_from_slice(&content);

            *ptextp = buffer as *mut _;
        }
        psize.as_mut().map(|p| {
            // Don't count the trailing NUL.
            *p = content.len() - 1
        });
    }

    if h.signer_keylist.len() == 0 {
        h.signer_keylist.add("");
    }
    h.signer_keylist.append(&mut h.recipient_keylist);

    unsafe { keylistp.as_mut() }.map(|p| {
        *p = mem::replace(&mut h.signer_keylist, StringList::empty()).to_c();
    });

    if ! filename_ptr.is_null() {
        unsafe { filename_ptr.as_mut() }.map(|p| {
            if let Some(filename) = h.filename.as_ref() {
                *p = rust_bytes_to_c_str_lossy(filename);
            } else {
                *p = ptr::null_mut();
            }
        });
    }

    // **********************************
    // Sync changes with pgp_verify_text.
    // **********************************
    if h.good_checksums > 0 {
        // If there is at least one signature that we can verify,
        // succeed.
        return Err(Error::DecryptedAndVerified);
    } else if h.revoked_key > 0 {
        // If there are any signatures from revoked keys, fail.
        return Err(Error::VerifySignerKeyRevoked);
    } else if h.expired_key > 0 {
        // If there are any signatures from expired keys, fail.
        return Err(Error::Decrypted);
    } else if h.bad_key > 0 {
        // If there are any signatures from invalid keys (keys
        // that are not signing capable), fail.
        return Err(Error::Decrypted);
    } else if h.bad_checksums > 0 {
        // If there are any bad signatures, fail.
        return Err(Error::DecryptSignatureDoesNotMatch);
    } else {
        // We couldn't verify any signatures (possibly because we
        // don't have the keys).
        return Err(Error::Decrypted);
    }
});

// PEP_STATUS pgp_verify_text(
//     PEP_SESSION session, const char *text, size_t size,
//     const char *signature, size_t sig_size, stringlist_t **keylist)
ffi!(fn pgp_verify_text(session: *mut Session,
                        text: *const c_char, size: size_t,
                        signature: *const c_char, sig_size: size_t,
                        keylistp: *mut *mut StringListItem)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if size == 0 || sig_size == 0 {
        return Err(Error::DecryptWrongFormat);
    }

    if text.is_null() {
        return Err(Error::IllegalValue(
            "text may not be NULL".into()));
    }
    let text = unsafe {
        std::slice::from_raw_parts(text as *const u8, size)
    };

    if signature.is_null() {
        return Err(Error::IllegalValue(
            "signature may not be NULL".into()));
    }
    let signature = unsafe {
        std::slice::from_raw_parts(signature as *const u8, sig_size)
    };

    // ASCII text is sometimes mangled in transport.  Show some stats
    // to make detecting this easier.
    if *crate::TRACE {
        let mut cr = 0;
        let mut crlf = 0;
        let mut lf = 0;

        for i in 0..text.len() {
            // CR
            if text[i] == b'\r' {
                cr += 1;
            }
            // LF
            if text[i] == b'\n' {
                if i > 0 && text[i - 1] == b'\r' {
                    cr -= 1;
                    crlf += 1;
                } else {
                    lf += 1;
                }
            }
        }

        t!("Text to verify: {} bytes with {} crlfs, {} bare crs and {} bare lfs",
           size, crlf, cr, lf);
    }

    let mut h = Helper::new(session);

    let verifier = wrap_err!(
        DetachedVerifierBuilder::from_bytes(&signature[..]),
        UnknownError,
        "Creating DetachedVerifierBuilder")?;

    let mut verifier = match verifier.with_policy(crate::P, None, &mut h) {
        Ok(verifier) => verifier,
        Err(err) => {
            match err.downcast::<Error>() {
                Ok(err) => return Err(err),
                Err(err) => return Err(Error::VerifyNoKey(err)),
            }
        }
    };

    wrap_err!(
        verifier.verify_bytes(text),
        UnknownError,
        "Verifying text")?;

    if h.signer_keylist.len() == 0 {
        h.signer_keylist.add("");
    }
    h.signer_keylist.append(&mut h.recipient_keylist);
    unsafe { keylistp.as_mut() }.map(|p| {
        *p = mem::replace(&mut h.signer_keylist, StringList::empty()).to_c();
    });


    // *****************************************
    // Sync changes with pgp_decrypt_and_verify.
    // *****************************************
    if h.good_checksums > 0 {
        // If there is at least one signature that we can verify,
        // succeed.
        return Err(Error::Verified);
    } else if h.revoked_key > 0 {
        // If there are any signatures from revoked keys, fail.
        return Err(Error::VerifySignerKeyRevoked);
    } else if h.expired_key > 0 {
        // If there are any signatures from expired keys, fail.
        return Err(Error::Decrypted);
    } else if h.bad_key > 0 {
        // If there are any signatures from invalid keys (keys
        // that are not signing capable), fail.
        return Err(Error::Decrypted);
    } else if h.bad_checksums > 0 {
        // If there are any bad signatures, fail.
        return Err(Error::DecryptSignatureDoesNotMatch);
    } else {
        // We couldn't verify any signatures (possibly because we
        // don't have the keys).
        return Err(Error::Unencrypted);
    }
});

// PEP_STATUS pgp_sign_only(
//     PEP_SESSION session, const char* fpr, const char *ptext,
//     size_t psize, char **stext, size_t *ssize)
ffi!(fn pgp_sign_only(
    session: *mut Session,
    fpr: *const c_char,
    ptext: *const c_char, psize: size_t,
    stextp: *mut *mut c_char, ssizep: *mut size_t)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if fpr.is_null() {
        return Err(Error::IllegalValue(
            "fpr may not be NULL".into()));
    }
    let fpr = unsafe { CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    if ptext.is_null() {
        return Err(Error::IllegalValue(
            "ptext may not be NULL".into()));
    }
    let ptext = unsafe {
        slice::from_raw_parts(ptext as *const u8, psize)
    };

    unsafe {
        stextp.as_mut().map(|p| *p = ptr::null_mut());
        ssizep.as_mut().map(|p| *p = 0);
    }

    let password = session.curr_passphrase();
    let keystore = session.keystore();


    let (cert, _private) = keystore.cert_find(fpr, true)?;

    let vc = wrap_err!(
        cert.with_policy(crate::P, None),
        KeyUnsuitable,
        format!("{} rejected by policy", cert.fingerprint()))?;

    let key =
        _pgp_get_decrypted_key_iter(
            vc.keys().alive().revoked(false).for_signing().secret()
                .map(|ka| ka.key()),
            password.as_ref())?;

    let signer_keypair = wrap_err!(
        key.into_keypair(),
        UnknownError,
        "Creating key pair from signing key")?;

    let mut stext = Vec::new();

    let message = Message::new(&mut stext);

    let message = wrap_err!(
        Armorer::new(message).build(),
        UnknownError,
        "Setting up armorer")?;

    let mut message = wrap_err!(
        Signer::new(message, signer_keypair).detached().build(),
        UnknownError,
        "Setting up signer")?;

    wrap_err!(
        message.write_all(ptext),
        UnknownError,
        "Signing message")?;

    wrap_err!(
        message.finalize(),
        UnknownError,
        "Finalizing message")?;

    // Add a trailing NUL.
    stext.push(0);

    // We need to store it in a buffer backed by the libc allocator.
    unsafe {
        if let Some(stextp) = stextp.as_mut() {
            let buffer = malloc(stext.len()) as *mut u8;
            if buffer.is_null() {
                return Err(Error::OutOfMemory("stext".into(), stext.len()));
            }
            slice::from_raw_parts_mut(buffer, stext.len())
                .copy_from_slice(&stext);
            *stextp = buffer as *mut _;
        }
        ssizep.as_mut().map(|p| {
            // Don't count the trailing NUL.
            *p = stext.len() - 1
        });
    }

    Ok(())
});


fn pgp_encrypt_sign_optional(
    session: *mut Session,
    keylist: *mut StringListItem,
    ptext: *const c_char, psize: size_t,
    ctextp: *mut *mut c_char, csizep: *mut size_t,
    sign: bool)
    -> Result<()>
{
    tracer!(*crate::TRACE, "pgp_encrypt_sign_optional");

    let session = Session::as_mut(session);

    if ptext.is_null() {
        return Err(Error::IllegalValue(
            "ptext may not be NULL".into()));
    }
    let ptext = unsafe {
        slice::from_raw_parts(ptext as *const u8, psize)
    };

    unsafe {
        ctextp.as_mut().map(|p| *p = ptr::null_mut());
        csizep.as_mut().map(|p| *p = 0);
    }

    let password = session.curr_passphrase();
    let keystore = session.keystore();


    let keylist = StringList::to_rust(keylist, false);
    t!("{} recipients.", keylist.len());
    for (i, v) in keylist.iter().enumerate() {
        t!("  {}. {}", i, String::from_utf8_lossy(v.to_bytes()));
    }
    if sign {
        t!("First recipient will sign the message");
    }

    // Get the keys for the recipients.
    let mut recipient_keys = Vec::new();
    let mut signer_keypair = None;

    for (i, item) in keylist.iter().enumerate() {
        let fpr = wrap_err!(
            Fingerprint::from_hex(&String::from_utf8_lossy(item.to_bytes())),
            UnknownError,
            "Not a fingerprint")?;
        let (cert, _private) = keystore.cert_find(fpr, false)?;

        let vc = wrap_err!(
            cert.with_policy(crate::P, None),
            KeyUnsuitable,
            format!("{} rejected by policy", cert.fingerprint()))?;

        // Collect all of the keys that have the encryption for
        // transport capability.

        // Note: there might not be any valid encryption-capable
        // subkeys.  Normally this isn't a problem as we consider such
        // certificates to be "broken" (cf. _pgp_key_broken) and won't
        // use them.  But there is a time of check, time of use race,
        // which we ignore.
        let mut have_one = false;
        for ka in vc.keys().alive().revoked(false).for_transport_encryption() {
            recipient_keys.push(ka.key().clone());
            have_one = true;
        }
        if ! have_one {
            t!("warning: {} doesn't have any valid encryption-capable subkeys",
               vc.fingerprint());
        }

        // The the first recipient is the signer.
        if sign && i == 0 {
            let key =
                _pgp_get_decrypted_key_iter(
                    vc.keys().alive().revoked(false).for_signing().secret()
                        .map(|ka| ka.key()),
                    password.as_ref())?;

            let keypair = wrap_err!(
                key.into_keypair(),
                UnknownError,
                "Creating key pair from signing key")?;

            signer_keypair = Some(keypair);
        }
    }

    let recipients: Vec<Recipient> = recipient_keys
        .iter()
        .map(|key| Recipient::new(key.keyid(), key))
        .collect();

    let mut ctext = Vec::new();

    let message = Message::new(&mut ctext);

    let message = wrap_err!(
        Armorer::new(message).build(),
        UnknownError,
        "Setting up armorer")?;

    let mut message = wrap_err!(
        Encryptor::for_recipients(message, recipients).build(),
        UnknownError,
        "Setting up encryptor")?;

    if let Some(keypair) = signer_keypair {
        message = wrap_err!(
            Signer::new(message, keypair).build(),
            UnknownError,
            "Setting up signer")?;
    }

    let mut message = wrap_err!(
        LiteralWriter::new(message).build(),
        UnknownError,
        "Setting up literal writer")?;

    wrap_err!(
        message.write_all(ptext),
        UnknownError,
        "Encrypting message")?;

    wrap_err!(
        message.finalize(),
        UnknownError,
        "Finalizing message")?;

    // Add a trailing NUL.
    ctext.push(0);

    // We need to store it in a buffer backed by the libc allocator.
    unsafe {
        if let Some(ctextp) = ctextp.as_mut() {
            let buffer = malloc(ctext.len()) as *mut u8;
            if buffer.is_null() {
                return Err(Error::OutOfMemory("ctext".into(), ctext.len()));
            }
            slice::from_raw_parts_mut(buffer, ctext.len())
                .copy_from_slice(&ctext);
            *ctextp = buffer as *mut _;
        }
        csizep.as_mut().map(|p| {
            // Don't count the trailing NUL.
            *p = ctext.len() - 1
        });
    }

    Ok(())
}


// PEP_STATUS pgp_encrypt_only(
//     PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
//     size_t psize, char **ctext, size_t *csize)
ffi!(fn pgp_encrypt_only(session: *mut Session,
                         keylist: *mut StringListItem,
                         ptext: *const c_char, psize: size_t,
                         ctextp: *mut *mut c_char, csizep: *mut size_t)
    -> Result<()>
{
    pgp_encrypt_sign_optional(
        session, keylist, ptext, psize, ctextp, csizep, false)
});

// PEP_STATUS pgp_encrypt_and_sign(
//     PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
//     size_t psize, char **ctext, size_t *csize)
ffi!(fn pgp_encrypt_and_sign(session: *mut Session,
                             keylist: *mut StringListItem,
                             ptext: *const c_char, psize: size_t,
                             ctextp: *mut *mut c_char, csizep: *mut size_t)
    -> Result<()>
{
    pgp_encrypt_sign_optional(
        session, keylist, ptext, psize, ctextp, csizep, true)
});

// PEP_STATUS _pgp_generate_keypair(PEP_SESSION session, pEp_identity *identity, time_t when)
ffi!(fn _pgp_generate_keypair(session: *mut Session,
                              identity: *mut PepIdentity,
                              when: time_t)
    -> Result<()>
{
    let session = Session::as_mut(session);
    let identity = if let Some(i) = PepIdentity::as_mut(identity) {
        i
    } else {
        return Err(Error::IllegalValue(
            "identity must not be NULL".into()));
    };
    t!("identity: {:?}", identity);

    let is_group_identity
        = identity.identity_flag(PepIdentityFlags::GroupIdent);

    // NOTE: FOR NOW, NO PASSPHRASE-BASED KEYS WILL BE GENERATED FOR
    // GROUP ENCRYPTION.  VOLKER HAS A PLAN TO FIX THIS.
    let password = if is_group_identity {
        None
    } else if session.new_key_pass_enabled() {
        if let Some(password) = session.generation_passphrase() {
            Some(password)
        } else {
            return Err(Error::PassphraseForNewKeysRequired);
        }
    } else {
        None
    };
    t!("password protected: {}",
       if password.is_some() { "yes" } else { "no" });

    let address = identity.address()
        .ok_or_else(|| {
            Error::IllegalValue(
                "identity->address must be non-NULL".into())
        })?
        .to_str()
        .map_err(|err| {
            Error::IllegalValue(
                format!("identity->address must be UTF-8 encoded: {}",
                        err))
        })?;
    t!("identity.address: {}", address);

    let username = identity.username();
    let username = if let Some(username) = username {
        let username = username.to_str()
            .map_err(|err| {
                Error::IllegalValue(
                    format!("identity->username must be UTF-8 encoded: {}",
                            err))
            })?;
        if username == address {
            // Ignore the username if it is the same as the address.
            None
        } else {
            Some(username)
        }
    } else {
        None
    };
    t!("identity.username: {:?}", username);

    let userid = wrap_err!(
        UserID::from_unchecked_address(username, None, address)
            .or_else(|err| {
                if let Some(username) = username {
                    // Replace parentheses in input string with
                    // brackets.
                    let username = &username
                        .replace("(", "[")
                        .replace(")", "]")[..];
                    t!("Invalid username, trying '{}'", username);
                    UserID::from_unchecked_address(
                        Some(username),
                        None,
                        address)
                } else {
                    Err(err)
                }
            })
            .or_else(|err| {
                if let Some(username) = username {
                    // Replace everything but letters and numbers
                    // with _.
                    let username = &username.chars()
                        .map(|c| {
                            match c {
                                c @ '0'..='9' => c,
                                c @ 'a'..='z' => c,
                                c @ 'A'..='Z' => c,
                                _ => '_'
                            }
                        })
                        .collect::<String>()[..];
                    t!("Invalid username, trying '{}'", username);
                    UserID::from_unchecked_address(
                        Some(username),
                        None,
                        address)
                } else {
                    Err(err)
                }
            }),
        UnknownError,
        "UserID::from_unchecked_address")?;

    // Generate a key.
    let mut certb = CertBuilder::general_purpose(
        Some(session.cipher_suite().try_into().unwrap_or_default()),
        Some(userid));

    certb = certb.set_password(password);

    if when > 0 {
        certb = certb.set_creation_time(
            Some(UNIX_EPOCH + Duration::new(when as u64, 0)));
    }

    let (cert, _) = wrap_err!(
        certb.generate(),
        CannotCreateKey,
        "Generating a key pair")?;

    let fpr = cert.fingerprint();

    wrap_err!(
        session.keystore().cert_save(cert),
        CannotCreateKey,
        "Saving new key")?;

    identity.set_fingerprint(fpr);

    Ok(())
});

// PEP_STATUS pgp_generate_keypair(PEP_SESSION session, pEp_identity *identity)
#[no_mangle] pub extern "C"
fn pgp_generate_keypair(session: *mut Session,
                        identity: *mut PepIdentity)
    -> crate::ErrorCode
{
    _pgp_generate_keypair(session, identity, 0)
}

// PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr_raw)
ffi!(fn pgp_delete_keypair(session: *mut Session,
                           fpr: *const c_char)
    -> Result<()>
{
    let session = Session::as_mut(session);
    let keystore = session.keystore();

    if fpr.is_null() {
        return Err(Error::IllegalValue("fpr must not be NULL".into()));
    }
    let fpr = unsafe { CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    t!("Deleting {}", fpr);

    keystore.cert_delete(fpr)
});

// Imports the keyring.  If keydata contains more than one
// ascii-armored keyring, this only imports the first ascii-armored
// keyring.
fn import_keydata(session: &mut Session,
                  keydata: &[u8],
                  private_idents: &mut PepIdentityList,
                  imported_keys: &mut StringList,
                  changed_bitvec: &mut u64)
    -> Result<()>
{
    tracer!(*crate::TRACE, "import_keydata");

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
                t!("Can't import a {} signature", sig.typ());
                return Err(Error::NoKeyImported);
            }

            for issuer in sig.get_issuers().into_iter() {
                match keystore.cert_find_with_key(issuer.clone(), false) {
                    Err(err) => {
                        t!("Can't merge signature: \
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
                            t!("Revocation certificate not issued by {}: {}",
                               fpr, err);
                            continue;
                        }

                        match cert.insert_packets(sig.clone()) {
                            Err(err) => {
                                t!("Merging signature with {} failed: {}",
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
                                        t!("Saving updated certificate {} \
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

            t!("Failed to import revocation certificate allegedly issued by {:?}.",
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

                        t!("Importing certificate {}", fpr);
                        for ua in cert.userids() {
                            t!("  User ID: {}", ua.userid());
                        }

                        let is_tsk = cert.is_tsk();
                        let (ident, changed)
                            = session.keystore().cert_save(cert)?;
                        imported_keys.add(fpr.to_hex());
                        t!("Adding {} to imported_keys", fpr);
                        if let Some(ident) = ident {
                            if is_tsk {
                                t!("Adding {:?} to private_idents", ident);
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
            t!("Can't import a {} packet", packet.tag());
            Err(Error::NoKeyImported)
        }
    }
}

// Imports the keydata and returns a PepIdentity and whether
// the certificate is changed relative to the copy on disk.
//
// Whether the certificate is changed is a heuristic.  It may
// indicate that the certificate has changed when it hasn't (false
// positive), but it will never say that the certificate has not
// changed when it has (false negative).
//
// PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *keydata,
//                               size_t size, identity_list **private_idents,
//                               stringlist_t** imported_keys,
//                               uint64_t* changed_key_index)
ffi!(fn pgp_import_keydata(session: *mut Session,
                           keydata: *const c_char,
                           keydata_len: size_t,
                           identity_listp: *mut *mut PepIdentityListItem,
                           imported_keysp: *mut *mut StringListItem,
                           changed_key_indexp: *mut u64)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if imported_keysp.is_null() && ! changed_key_indexp.is_null() {
        return Err(Error::IllegalValue(
            "When changed_key_index is provided, \
             import_keys must also be provided."
                .into()));
    }

    if keydata.is_null() {
        return Err(Error::IllegalValue(
            "keydata may not be NULL".into()));
    }
    let keydata = unsafe {
        std::slice::from_raw_parts(keydata as *const u8, keydata_len)
    };
    // We add(!) to the existing lists.
    let mut identity_list = unsafe { identity_listp.as_mut() }
        .map(|p| PepIdentityList::to_rust(*p, false))
        .unwrap_or_else(|| PepIdentityList::empty());
    let mut imported_keys = unsafe { imported_keysp.as_mut() }
        .map(|p| StringList::to_rust(*p, false))
        .unwrap_or_else(|| StringList::empty());
    let mut changed_key_index: u64 = unsafe { changed_key_indexp.as_mut() }
        .map(|p| *p)
        .unwrap_or(0);

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

    t!("armor block offsets: {:?}", offsets);

    let retval = if offsets.len() == 0 {
        import_keydata(session,
                       keydata,
                       &mut identity_list,
                       &mut imported_keys,
                       &mut changed_key_index)
    } else if offsets.len() == 1 {
        import_keydata(session,
                       &keydata[offsets[0]..],
                       &mut identity_list,
                       &mut imported_keys,
                       &mut changed_key_index)
    } else {
        let mut retval = Error::KeyImported;

        offsets.push(keydata.len());
        for offsets in offsets.windows(2) {
            let keydata = &keydata[offsets[0]..offsets[1]];

            let curr_status = import_keydata(session,
                                             keydata,
                                             &mut identity_list,
                                             &mut imported_keys,
                                             &mut changed_key_index);

            // import_keydata should not return Ok; on success, it
            // should return KeyImported.
            let curr_status = match curr_status {
                Err(err) => err,
                Ok(()) => panic!("import_keydata returned Ok"),
            };

            if ErrorCode::from(&curr_status) != ErrorCode::from(&retval) {
                match curr_status {
                    Error::NoKeyImported
                    | Error::KeyNotFound(_)
                    | Error::UnknownError(_, _) => {
                        match retval {
                            Error::KeyImported => retval = Error::SomeKeysImported,
                            Error::UnknownError(_, _) => retval = curr_status,
                            _ => (),
                        }
                    }
                    Error::KeyImported => retval = Error::SomeKeysImported,
                    _ => (),
                }
            }
        }

        Err(retval)
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


// PEP_STATUS pgp_export_keydata(
//         PEP_SESSION session, const char *fpr, char **keydata, size_t *size,
//         bool secret)
ffi!(fn pgp_export_keydata(session: *mut Session,
                           fpr: *const c_char,
                           keydatap: *mut *mut c_char,
                           keydata_lenp: *mut size_t,
                           secret: bool)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if fpr.is_null() {
        return Err(Error::IllegalValue("fpr must not be NULL".into()));
    }
    let fpr = unsafe { CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    t!("({}, {})", fpr, if secret { "secret" } else { "public" });

    // If the caller asks for a secret key and we only have a
    // public key, then we return an error.
    let (cert, _private) = session.keystore().cert_find(fpr, secret)?;

    let mut keydata = Vec::new();
    if secret {
        wrap_err!(
            cert.as_tsk().armored().serialize(&mut keydata),
            UnknownError,
            format!("Serializing key: {}", cert.fingerprint()))?;
    } else {
        wrap_err!(
            cert.armored().serialize(&mut keydata),
            UnknownError,
            format!("Serializing certificate: {}", cert.fingerprint()))?;
    }

    // We need a NUL byte at the end.
    keydata.push(0);

    // We need to store it in a buffer backed by the libc allocator.
    unsafe {
        if let Some(keydatap) = keydatap.as_mut() {
            let buffer = malloc(keydata.len()) as *mut u8;
            if buffer.is_null() {
                return Err(Error::OutOfMemory("keydata".into(), keydata.len()));
            }
            slice::from_raw_parts_mut(buffer, keydata.len())
                .copy_from_slice(&keydata);
            *keydatap = buffer as *mut _;
        }
        keydata_lenp.as_mut().map(|p| {
            // Don't count the trailing NUL.
            *p = keydata.len() - 1
        });
    }

    Ok(())
});

// PEP_STATUS pgp_list_keyinfo(PEP_SESSION session,
//                             const char* pattern,
//                             stringpair_list_t** keyinfo_list)
stub!(pgp_list_keyinfo);

// PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
stub!(pgp_recv_key);

fn list_keys(session: *mut Session,
             pattern: *const c_char,
             keylistp: *mut *mut StringListItem,
             private_only: bool) -> Result<()>
{
    tracer!(*crate::TRACE, "list_keys");

    let session = Session::as_mut(session);

    if pattern.is_null() {
        return Err(Error::IllegalValue(
            "pattern may not be NULL".into()));
    }
    let pattern = unsafe { CStr::from_ptr(pattern) };
    // XXX: What should we do if pattern is not valid UTF-8?
    let pattern = pattern.to_string_lossy();

    let mut keylist = StringList::empty();

    match session.keystore().list_keys(&pattern, private_only) {
        Err(Error::KeyNotFound(_)) => {
            // If no keys are found, don't return an error, return the
            // empty set.
        }
        Err(err) => {
            return Err(err);
        }
        Ok(listing) => {
            // We return revoked keys.
            for (fpr, _, _) in listing {
                keylist.add(fpr.to_hex());
            }
        }
    }

    t!("Found {} certificates matching '{}'", keylist.len(), pattern);

    unsafe { keylistp.as_mut() }.map(|p| {
        *p = keylist.to_c();
    });

    Ok(())
}

// PEP_STATUS pgp_find_keys(
//     PEP_SESSION session, const char *pattern, stringlist_t **keylist)
ffi!(fn pgp_find_keys(session: *mut Session,
                      pattern: *const c_char,
                      keylistp: *mut *mut StringListItem)
    -> Result<()>
{
    list_keys(session, pattern, keylistp, false)
});

// PEP_STATUS pgp_find_private_keys(
//     PEP_SESSION session, const char *pattern, stringlist_t **keylist)
ffi!(fn pgp_find_private_keys(session: *mut Session,
                              pattern: *const c_char,
                              keylistp: *mut *mut StringListItem)
    -> Result<()>
{
    list_keys(session, pattern, keylistp, true)
});

// PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern)
stub!(pgp_send_key);

// PEP_STATUS pgp_renew_key(
//     PEP_SESSION session, const char *fpr, const timestamp *ts)
ffi!(fn pgp_renew_key(session: *mut Session,
                      fpr: *const c_char,
                      expiration: *const Timestamp)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if fpr.is_null() {
        return Err(Error::IllegalValue(
            "fpr may not be NULL".into()));
    }
    let fpr = unsafe { CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    let expiration = if let Some(expiration) = unsafe { expiration.as_ref() } {
        expiration
    } else {
        return Err(Error::IllegalValue("expiration must not be NULL".into()));
    };

    let password = session.curr_passphrase();
    let keystore = session.keystore();

    let expiration = Utc.ymd(1900 + expiration.tm_year,
                             1 + expiration.tm_mon as u32,
                             expiration.tm_mday as u32)
        .and_hms(expiration.tm_hour as u32,
                 expiration.tm_min as u32,
                 expiration.tm_sec as u32);
    let expiration: SystemTime = expiration.into();

    let (cert, _private) = keystore.cert_find(fpr, true)?;

    let creation_time = cert.primary_key().creation_time();
    if creation_time >= expiration {
        // The creation time is after the expiration time!
        return Err(Error::UnknownError(
            anyhow::anyhow!("creation time ({:?}) \
                             can't be after expiration time ({:?})",
                            creation_time, expiration),
            "invalid expiration time".into()));
    }

    let vc = wrap_err!(
        cert.with_policy(crate::P, None),
        KeyUnsuitable,
        format!("{} rejected by policy", cert.fingerprint()))?;

    let key =
        _pgp_get_decrypted_key_iter(
            vc.keys().revoked(false).for_certification().secret()
                .map(|ka| ka.key()),
            password.as_ref())?;

    let mut signer_keypair = wrap_err!(
        key.into_keypair(),
        UnknownError,
        "Creating key pair from certification key")?;

    // Set the expiration for all non-revoked keys.

    let mut self_sigs = Vec::new();
    for (i, ka) in vc.keys().revoked(false).enumerate() {
        // Arrange for a backsig, if needed.
        let mut self_sig = if i > 0 // subkey
            && (ka.for_certification()
                || ka.for_signing()
                || ka.for_authentication())
        {
            let subkey = wrap_err!(
                ka.key().clone().parts_into_secret(),
                UnknownError,
                "Can't extend signing-capable subkey's expiration: \
                 secret key material is not available")?;

            let subkey = _pgp_get_decrypted_key(subkey, password.as_ref())?;

            let mut subkey_keypair = wrap_err!(
                subkey.into_keypair(),
                UnknownError,
                "Creating key pair from subkey")?;

            wrap_err!(
                ka.set_expiration_time(
                    &mut signer_keypair,
                    Some(&mut subkey_keypair),
                    Some(expiration)),
                UnknownError,
                "setting expiration (generating self signature and backsig)")?
        } else {
            wrap_err!(
                ka.set_expiration_time(
                    &mut signer_keypair,
                    None,
                    Some(expiration)),
                UnknownError,
                "setting expiration (generating self signature)")?
        };

        self_sigs.append(&mut self_sig);
    }

    let cert = wrap_err!(
        cert.insert_packets(self_sigs),
        UnknownError,
        "inserting new self signatures")?;
    keystore.cert_save(cert)?;

    Ok(())
});

// PEP_STATUS pgp_revoke_key(
//     PEP_SESSION session, const char *fpr, const char *reason)
ffi!(fn pgp_revoke_key(session: *mut Session,
                       fpr: *const c_char,
                       reason: *const c_char)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if fpr.is_null() {
        return Err(Error::IllegalValue(
            "fpr may not be NULL".into()));
    }
    let fpr = unsafe { CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    let reason = unsafe {
        reason.as_ref()
            .map(|reason| CStr::from_ptr(reason).to_bytes())
            .unwrap_or(b"")
    };

    let password = session.curr_passphrase();
    let keystore = session.keystore();


    let (cert, _private) = keystore.cert_find(fpr, true)?;

    let vc = wrap_err!(
        cert.with_policy(crate::P, None),
        KeyUnsuitable,
        format!("{} rejected by policy", cert.fingerprint()))?;

    let key =
        _pgp_get_decrypted_key_iter(
            vc.keys().alive().revoked(false).for_certification().secret()
                .map(|ka| ka.key()),
            password.as_ref())?;

    let mut signer_keypair = wrap_err!(
        key.into_keypair(),
        UnknownError,
        "Creating key pair from certification key")?;

    let sig = wrap_err!(
        cert.revoke(&mut signer_keypair,
                    ReasonForRevocation::Unspecified,
                    reason),
        UnknownError,
        "generating revocation certificate")?;

    let cert = wrap_err!(
        cert.insert_packets(sig),
        UnknownError,
        "merging revocation certificate")?;

    assert!(matches!(
        cert.revocation_status(crate::P, None),
        RevocationStatus::Revoked(_)));

    keystore.cert_save(cert)?;

    Ok(())
});

// Check to see that key, at a minimum, even contains encryption and
// signing subkeys.
fn _pgp_key_broken(vc: &ValidCert) -> bool {
    let mut has_enc = false;
    let mut has_signing = false;

    for ka in vc.keys() {
        if ka.for_signing() {
            has_signing = true;
        }
        if ka.for_transport_encryption() || ka.for_storage_encryption() {
            has_enc = true;
        }

        if has_signing && has_enc {
            return false;
        }
    }

    return true;
}

fn _pgp_key_expired(vc: &ValidCert) -> bool
{
    tracer!(*crate::TRACE, "_pgp_key_expired");

    if ! vc.alive().is_ok() {
        return true;
    }

    // Check to see if the key is broken. Ideally, we'd do this in one
    // pass below, but givem the choice for how to check for expiry,
    // this is the simplest solutiom.
    if _pgp_key_broken(vc) {
        return false; // still isn't expired. is broken. there's a difference and a different check.
    }

    // Why is this an indicator of just an expired key and not a
    // broken one?  This will also reject keys that are not expired,
    // but rather missing subkeys.

    // Are there at least one certification subkey, one signing subkey
    // and one encryption subkey that are live?
    let mut can_encrypt = false;
    let mut can_sign = false;

    for ka in vc.keys().alive().revoked(false) {
        if ka.for_transport_encryption() || ka.for_storage_encryption() {
            can_encrypt = true;
        }
        if ka.for_signing() {
            can_sign = true;
        }

        if can_encrypt && can_sign {
            break;
        }
    }

    let expired = !(can_encrypt && can_sign);

    t!("Key can{} encrypt, can{} sign => {} expired",
       if can_encrypt { "" } else { "not" },
       if can_sign { "" } else { "not" },
       if expired { "" } else { "not" });

    return expired;
}

// PEP_STATUS pgp_key_expired(PEP_SESSION session, const char *fpr,
//                            const time_t when, bool *expired)
ffi!(fn pgp_key_expired(session: *mut Session,
                        fpr: *const c_char,
                        when: time_t,
                        expiredp: *mut bool)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if fpr.is_null() {
        return Err(Error::IllegalValue(
            "fpr may not be NULL".into()));
    }
    let fpr = unsafe { &CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    if when < 0 {
        // when is before UNIX EPOCH.  The key was not alive at
        // this time (the first keys were create around 1990).
        unsafe { expiredp.as_mut() }.map(|p| {
            *p = true;
        });
        return Ok(());
    }
    let when = SystemTime::UNIX_EPOCH + Duration::new(when as u64, 0);

    let (cert, _private) = session.keystore().cert_find(fpr.clone(), false)?;
    let vc = wrap_err!(
        cert.with_policy(crate::P, when),
        UnknownError,
        "Invalid certificate")?;

    let expired = _pgp_key_expired(&vc);

    unsafe { expiredp.as_mut() }.map(|p| {
        *p = expired;
    });

    t!("{} is {}expired as of {:?}",
       fpr,
       if expired { "" } else { "not " },
       when);

    Ok(())
});

fn _pgp_key_revoked(vc: &ValidCert) -> bool
{
    if let RevocationStatus::Revoked(_) = vc.revocation_status() {
        return true;
    }

    // Ok, at this point, we need to know if for signing or encryption
    // there is ONLY a revoked key available. If so, this key is also
    // considered revoked
    let mut has_non_revoked_sig_key = false;
    let mut has_revoked_sig_key = false;
    for ka in vc.keys().for_signing() {
        if let RevocationStatus::Revoked(_) = ka.revocation_status() {
            has_revoked_sig_key = true;
        } else {
            has_non_revoked_sig_key = true;
            break;
        }
    }

    if has_non_revoked_sig_key {
        let mut has_non_revoked_enc_key = false;
        let mut has_revoked_enc_key = false;

        for ka in vc.keys().for_storage_encryption().for_transport_encryption() {
            if let RevocationStatus::Revoked(_) = ka.revocation_status() {
                has_revoked_enc_key = true;
            } else {
                has_non_revoked_enc_key = true;
                break;
            }
        }

        if !has_non_revoked_enc_key { // this does NOT mean revoked. it MAY mean broken.
            if has_revoked_enc_key {
                return true;
            }
        }
    } else if has_revoked_sig_key {
        return true;
    }

    false
}

// PEP_STATUS pgp_key_revoked(PEP_SESSION session, const char *fpr, bool *revoked)
ffi!(fn pgp_key_revoked(session: *mut Session,
                        fpr: *const c_char,
                        revokedp: *mut bool)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if fpr.is_null() {
        return Err(Error::IllegalValue(
            "fpr may not be NULL".into()));
    }
    let fpr = unsafe { &CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    let (cert, _private) = session.keystore().cert_find(fpr.clone(), false)?;

    let vc = wrap_err!(
        cert.with_policy(crate::P, None),
        UnknownError,
        "Invalid certificate")?;

    let revoked = _pgp_key_revoked(&vc);

    unsafe { revokedp.as_mut() }.map(|p| {
        *p = revoked;
    });

    t!("{} is {}revoked",
       fpr,
       if revoked { "" } else { "not " });

    Ok(())
});

// PEP_STATUS pgp_get_key_rating(
//     PEP_SESSION session, const char *fpr, PEP_comm_type *comm_type)
// PEP_STATUS pgp_contains_priv_key(PEP_SESSION session, const char *fpr,
//                                  bool *has_private)
ffi!(fn pgp_get_key_rating(session: *mut Session, fpr: *const c_char,
                           comm_typep: *mut PepCommType)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if fpr.is_null() {
        return Err(Error::IllegalValue(
            "fpr may not be NULL".into()));
    }
    let fpr = unsafe { CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    if comm_typep.is_null() {
        return Err(Error::IllegalValue(
            "comm_type may not be NULL".into()));
    }
    let comm_type = |ct| {
        unsafe { comm_typep.as_mut() }.map(|p| {
            *p = ct;
        });
    };

    comm_type(PepCommType::Unknown);

    let (cert, _private) = session.keystore().cert_find(fpr.clone(), false)?;

    let vc = wrap_err!(
        cert.with_policy(crate::P, None),
        UnknownError,
        "Invalid certificate")?;

    comm_type(PepCommType::OpenPgpUnconfirmed);

    if let RevocationStatus::Revoked(_) = vc.revocation_status() {
        comm_type(PepCommType::KeyRevoked);
        return Ok(());
    }

    if _pgp_key_revoked(&vc) {
        comm_type(PepCommType::KeyRevoked);
        return Ok(());
    }

    if _pgp_key_broken(&vc) {
        comm_type(PepCommType::KeyB0rken);
        return Ok(());
    }

    // MUST guarantee the same behaviour.
    if _pgp_key_expired(&vc) {
        comm_type(PepCommType::KeyExpired);
        return Ok(());
    }

    let mut worst_enc = PepCommType::NoEncryption;
    let mut worst_sign = PepCommType::NoEncryption;

    for ka in vc.keys().alive().revoked(false) {
        let curr;

        use openpgp::types::PublicKeyAlgorithm::*;
        match ka.pk_algo() {
            #[allow(deprecated)]
            RSAEncryptSign | RSAEncrypt | RSASign
            | DSA | ElGamalEncrypt | ElGamalEncryptSign =>
            {
                let bits = ka.mpis().bits().unwrap_or(0);
                if bits < 1024 {
                    curr = PepCommType::KeyTooShort;
                } else if bits == 1024 {
                    curr = PepCommType::OpenPgpWeakUnconfirmed;
                } else {
                    curr = PepCommType::OpenPgpUnconfirmed;
                }
            }
            _ => {
                curr = PepCommType::OpenPgpUnconfirmed;
            }
        }

        if ka.for_transport_encryption() || ka.for_storage_encryption() {
            worst_enc = if worst_enc == PepCommType::NoEncryption {
                curr
            } else {
                cmp::min(worst_enc, curr)
            };
        }

        if ka.for_signing() {
            worst_sign = if worst_sign == PepCommType::NoEncryption {
                curr
            } else {
                cmp::min(worst_sign, curr)
            };
        }
    }

    // This may be redundant because of the broken check above; we
    // should revisit later.  But because this case was falling under
    // expired because of how that is written, this was probably never
    // hiit here

    t!("worse enc: {:?}, worst sig: {:?}", worst_enc, worst_sign);

    if worst_enc == PepCommType::NoEncryption
        || worst_sign == PepCommType::NoEncryption
    {
        comm_type(PepCommType::KeyB0rken);
    } else {
        comm_type(cmp::min(worst_enc, worst_sign));
    }

    t!("{}'s rating is {:?}",
       fpr, unsafe { comm_typep.as_ref() }.unwrap());

    Ok(())
});

// PEP_STATUS pgp_key_created(PEP_SESSION session, const char *fpr, time_t *created)
ffi!(fn pgp_key_created(session: *mut Session,
                        fpr: *const c_char,
                        createdp: *mut time_t)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if fpr.is_null() {
        return Err(Error::IllegalValue(
            "fpr may not be NULL".into()));
    }
    let fpr = unsafe { &CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    if createdp.is_null() {
        return Err(Error::IllegalValue(
            "createdp may not be NULL".into()));
    }

    let (cert, _private) = session.keystore().cert_find(fpr, false)?;

    let t = wrap_err!(
        cert.primary_key().creation_time().duration_since(UNIX_EPOCH),
        UnknownError,
        "Creation time out of range")?.as_secs();

    unsafe { createdp.as_mut() }.map(|p| {
        *p = t as time_t;
    });

    Ok(())
});

// PEP_STATUS pgp_binary(const char **path)
ffi!(fn pgp_binary(path: *mut *mut c_char) -> Result<()> {
    unsafe { path.as_mut() }.map(|p| *p = ptr::null_mut());
    Ok(())
});


// PEP_STATUS pgp_contains_priv_key(PEP_SESSION session, const char *fpr,
//                                  bool *has_private)
ffi!(fn pgp_contains_priv_key(session: *mut Session, fpr: *const c_char,
                              has_privatep: *mut bool)
    -> Result<()>
{
    let session = Session::as_mut(session);

    if fpr.is_null() {
        return Err(Error::IllegalValue(
            "fpr may not be NULL".into()));
    }
    let fpr = unsafe { CStr::from_ptr(fpr) };
    let fpr = wrap_err!(
        Fingerprint::from_hex(&String::from_utf8_lossy(fpr.to_bytes())),
        UnknownError,
        "Not a fingerprint")?;

    let has_private = match session.keystore().cert_find(fpr, true) {
        Ok(_) => true,
        Err(Error::KeyNotFound(_)) => false,
        Err(err) => return Err(err),
    };

    unsafe { has_privatep.as_mut() }.map(|p| {
        *p = has_private
    });

    Ok(())
});

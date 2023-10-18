use std::cmp;
use std::convert::TryInto;
use std::env;
use std::ffi::{
    CStr,
    //CString
};
use std::io::{
    Read,
    Write,
    Cursor,
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

#[allow(unused_imports)]
use anyhow::Context;

use libc::{
    c_char,
    c_uint,
    size_t,
    time_t,
};

use chrono::LocalResult;
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
	PacketParserResult,
	PacketParserBuilder,
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

use openpgp::armor::{
    Reader, 
    //Kind,
    ReaderMode,
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
use ffi::MM;

mod keystore;
use keystore::Keystore;

mod buffer;
use buffer::{
    rust_bytes_to_c_str_lossy,
    rust_bytes_to_ptr_and_len,
};


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
    let session = Session::as_mut(session)?;
    session.set_cipher_suite(suite)
});

// Given the pEp cipher suite indicator enum, returns whether the
// cipher suite is supported.
//
// Returns `StatusOk` if it is supported, and `CannotConfig` is not
// supported by the current cryptographic backend.
ffi!(fn pgp_cipher_suite_is_supported(session: *mut Session,
                                      suite: PepCipherSuite)
    -> Result<()>
{
    let _session = Session::as_mut(session)?;

    let suite: Result<openpgp::cert::CipherSuite> = suite.try_into();
    if let Err(_err) = suite {
        Err(Error::CannotConfig("cipher suite".into()))
    } else {
        Ok(())
    }
});

// Decrypts the key.
//
// On success, returns the decrypted key.
fn _pgp_get_decrypted_key(key: Key<key::SecretParts, key::UnspecifiedRole>,
                          pass: Option<&Password>)
    -> Result<Key<key::SecretParts, key::UnspecifiedRole>>
{
    trace!("_pgp_get_decrypted_key");

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
                trace!("Can't decrypt {}: no password configured", fpr);
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
                  malloc: ffi::Malloc,
                  free: ffi::Free,
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

    assert_eq!(magic, 0xDEADBEEF, "magic");

    assert!(session_size as usize >= size_of::<Session>());
    assert_eq!(session_cookie_offset as usize,
               offset_of!(Session, state),
               "session_cookie_offset");
    assert_eq!(session_curr_passphrase_offset as usize,
               offset_of!(Session, curr_passphrase),
               "session_curr_passphrase_offset");
    assert_eq!(session_new_key_pass_enable as usize,
               offset_of!(Session, new_key_pass_enabled),
               "session_new_key_pass_enable");
    assert_eq!(session_generation_passphrase_offset as usize,
               offset_of!(Session, generation_passphrase),
               "session_generation_passphrase_offset");
    assert_eq!(session_cipher_suite_offset as usize,
               offset_of!(Session, cipher_suite),
               "session_cipher_suite_offset");
    assert_eq!(pep_status_size as usize, size_of::<ErrorCode>(),
               "pep_status_size");
    assert_eq!(pep_comm_type_size as usize, size_of::<PepCommType>(),
               "pep_comm_type_size");
    assert_eq!(pep_enc_format_size as usize, size_of::<PepEncFormat>(),
               "pep_enc_format_size");
    assert_eq!(pep_identity_flags_size as usize, size_of::<PepIdentityFlags>(),
               "pep_identity_flags_size");
    assert_eq!(pep_cipher_suite_size as usize, size_of::<PepCipherSuite>(),
               "pep_cipher_suite_size");
    assert_eq!(string_list_item_size as usize, size_of::<StringListItem>(),
               "string_list_item_size");
    assert_eq!(pep_identity_size as usize, size_of::<PepIdentity>(),
               "pep_identity_size");
    assert_eq!(pep_identity_list_item_size as usize, size_of::<PepIdentityListItem>(),
               "pep_identity_list_item_size");
    assert_eq!(timestamp_size as usize, size_of::<Timestamp>(),
               "timestamp_size");
    // assert_eq!(stringpair_size as usize, size_of::<StringPair>(),
    //            "stringpair_size");
    // assert_eq!(stringpair_list_size as usize, size_of::<StringPairList>(),
    //            "stringpair_list_size");

    let session = Session::as_mut(session)?;

    if per_user_directory.is_null() {
        return Err(Error::IllegalValue(
            "per_user_directory may not be NULL".into()));
    }
    let per_user_directory = unsafe { CStr::from_ptr(per_user_directory) };

    #[cfg(not(windows))]
    let per_user_directory = {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        OsStr::from_bytes(per_user_directory.to_bytes())
    };
    #[cfg(windows)]
    let per_user_directory = {
        // The engine guarantees that it is UTF-8 encoded.
        //
        // https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/commit/2f0927554ac1b7ca10e27b19650b5158d97dfc3f/src/platform_windows.cpp#L177
        match per_user_directory.to_str() {
             Ok(s) => s,
             Err(err) =>
                 return Err(Error::IllegalValue(
                     format!("\
API violation: per_user_directory not UTF-8 encoded ({:?}: {})",
                             per_user_directory, err))),
         }
    };

    let ks = keystore::Keystore::init(Path::new(per_user_directory))?;
    session.init(MM { malloc, free }, ks);
    #[cfg(target_os = "android")] {
        initialize_android_log();
    }
    Ok(())
});

#[cfg(target_os = "android")]
fn initialize_android_log() {
    if cfg!(debug_assertions) {
        android_logger::init_once(
            android_logger::Config::default().with_max_level(::log::LevelFilter::Trace),
        );
    }
    error!("sequoia backend session initialized");
}

// void pgp_release(PEP_SESSION session, bool out_last)
ffi!(fn pgp_release(session: *mut Session, _out_last: bool) -> Result<()> {
    // In C, it is usually okay to call a destructor, like `free`,
    // with a `NULL` pointer: the function just does nothing.
    // Implement the same semantics.
    if ! session.is_null() {
        Session::as_mut(session)?.deinit();
    }
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
        let mm = session.mm();

        Helper {
            session: session,
            secret_keys_called: false,
            recipient_keylist: StringList::empty(mm),
            signer_keylist: StringList::empty(mm),
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
        trace!("Helper::check");

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

                            trace!("Good signature ({:02X}{:02X}) from {}",
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               primary_fpr);

                            self.good_checksums += 1;
                        }
                        Err(VerificationError::MalformedSignature { sig, error }) => {
                            trace!("Malformed signature ({:02X}{:02X}) \
                                allegedly from {:?}: {}",
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               sig.issuers().next(),
                               error);
                            self.malformed_signature += 1;
                        }
                        Err(VerificationError::MissingKey { sig }) => {
                            trace!("No key to check signature ({:02X}{:02X}) \
                                allegedly from {:?}",
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               sig.issuers().next());
                            self.missing_keys += 1;
                        }
                        Err(VerificationError::UnboundKey { sig, cert, error }) => {
                            // This happens if the key doesn't have a binding
                            // signature.

                            trace!("Certificate {} has no valid self-signature; \
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
                            trace!("Can't check signature ({:02X}{:02X}): \
                                key {} is bad: {}",
                               sig.digest_prefix()[0],
                               sig.digest_prefix()[1],
                               ka.cert().fingerprint(),
                               error);

                            // Check if the key or certificate is revoked.
                            if let RevocationStatus::Revoked(_)
                                = ka.revocation_status()
                            {
                                trace!("reason: key is revoked");
                                self.revoked_key += 1;
                            } else if let RevocationStatus::Revoked(_)
                                = ka.cert().revocation_status()
                            {
                                trace!("reason: cert is revoked");
                                self.revoked_key += 1;
                            }
                            // Check if the key or certificate is expired.
                            else if let Err(err) = ka.cert().alive() {
                                trace!("reason: cert is expired: {}", err);
                                self.expired_key += 1;
                            }
                            else if let Err(err) = ka.alive() {
                                // Key is expired.
                                trace!("reason: key is expired: {}", err);
                                self.expired_key += 1;
                            }
                            // Wrong key flags or something similar.
                            else {
                                trace!("reason: other");
                                self.bad_key += 1;
                            }
                        }
                        Err(VerificationError::BadSignature { sig, ka, error }) => {
                            trace!("Bad signature ({:02X}{:02X}) from {}: {}",
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
        trace!("Helper::decrypt");

        let password = self.session.curr_passphrase();
        let keystore = self.session.keystore();

        // Whether there are any wildcard recipients.
        let mut have_wildcards = false;

        // The certificate that decrypted the message.
        let mut decryption_identity = None;

        let mut missing_passphrase = false;
        let mut bad_passphrase = None;

        if self.secret_keys_called {
            return Err(anyhow::anyhow!(
                "Nested encryption containers not supported"));
        }
        self.secret_keys_called = true;

        trace!("{} PKESKs", pkesks.len());

        for pkesk in pkesks.iter() {
            let keyid = pkesk.recipient();
            if keyid.is_wildcard() {
                // Initially ignore wildcards.
                have_wildcards = true;
                continue;
            }
            let testy = &keyid.to_hex();
            trace!("Keystore::cert_find_ for {:?}", testy);
    
            trace!("Considering PKESK for {}", keyid);

            // Collect the recipients.  Note: we must return the
            // primary key's fingerprint.
            let (cert, private)
                = match keystore.cert_find_with_key(keyid.clone(), false)
            {
                Err(Error::KeyNotFound(_)) => continue,
                Err(err) => {
                    trace!("Error looking up {}: {}", keyid, err);
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
                    trace!("Inconsistent DB: cert {} doesn't contain a subkey with \
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
                        trace!("While decrypting {}: {}", fpr, err);
                        continue;
                    }
                };

                let mut keypair = match key.into_keypair() {
                    Ok(keypair) => keypair,
                    Err(err) => {
                        trace!("Creating keypair for {}: {}", fpr, err);
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
                        trace!("Failed to decrypt PKESK for {}", fpr);
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
                                trace!("decrypting {}: {}",
                                   ka.fingerprint(), err);
                                continue;
                            }
                        };

                        let mut keypair = match key.into_keypair() {
                            Ok(keypair) => keypair,
                            Err(err) => {
                                trace!("Creating keypair for {}: {}",
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
                                trace!("wildcard recipient appears to be {}",
                                   ka.fingerprint());

                                if decrypt (sym_algo, &sk) {
                                    decryption_identity
                                        = Some(tsk.fingerprint());
                                    self.recipient_keylist.add_unique(
                                        tsk.fingerprint().to_hex());
                                    self.decrypted = true;
                                    break;
                                } else {
                                    trace!("Failed to decrypt message \
                                        using ESK decrypted by {}",
                                       ka.fingerprint());
                                    continue;
                                }
                            }
                            None => {
                                trace!("Failed to decrypt PKESK for {}",
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

ffi!(fn pgp_get_fprs(session: *mut Session,
                               ctext: *const c_char, _csize: size_t,                               
                               keylistp: *mut *mut StringListItem)
    -> Result<()>
{
    let session = Session::as_mut(session)?;
    
    let mm = session.mm();

    // Convert *const c_char to CStr
    let slice = unsafe { CStr::from_ptr(ctext) };
    let message: &[u8] = slice.to_bytes();
    //let message = cstr.to_str();
    //let message: &[u8] = unsafe { std::slice::from_raw_parts_mut(ctext, _csize) };

    // Create an empty StringList
    let mut list = StringList::empty(mm);

    let mut pkesks: Vec<PKESK> = Vec::new();  // Accumulator for PKESKs.
    let mut packets: Vec<Packet> = Vec::new(); // Accumulator for packets.

    let mut ppr = PacketParserBuilder::from_bytes(message)
        .expect("NOT EOF").build().unwrap();

    while let PacketParserResult::Some(pp) = ppr {
        let (packet, ppr_) = pp.recurse().expect("Parsing message");
        ppr = ppr_;
        match packet {
            Packet::PKESK(p) => pkesks.push(p),
            _ => packets.push(packet),
        }
    }

    if let PacketParserResult::EOF(eof) = ppr {
        let is_message = eof.is_message();
        if is_message.is_ok() {
            for pkesk in pkesks.iter() {
                list.add(pkesk.recipient().to_hex());
            }
        }
    }

    unsafe { *keylistp = list.to_c() };

    return Err(Error::StatusOk);
});

// PEP_STATUS pgp_decrypt_and_verify(
//     PEP_SESSION session, const char *ctext, size_t csize,
//     const char *dsigtext, size_t dsigsize,
//     char **ptext, size_t *psize, stringlist_t **keylist,
//     char** filename_ptr)
ffi!(fn pgp_decrypt_and_verify(session: *mut Session,
                               ctext: *const c_char, csize: size_t,
                               dsigtext: *const c_char, _dsigsize: size_t,
                               ptextp: *mut *mut c_char, psizep: *mut size_t,
                               keylistp: *mut *mut StringListItem,
                               filename_ptr: *mut *mut c_char)
    -> Result<()>
{
    let session = Session::as_mut(session)?;
    let mm = session.mm();
    let malloc = mm.malloc;

    let ctext = unsafe { check_slice!(ctext, csize) };

    // XXX: We don't handle detached signatures over encrypted
    // messages (and never have).
    if ! dsigtext.is_null() {
        return Err(Error::IllegalValue(
            "detached signatures over encrypted data are not supported".into()));
    }

    let ptextp = unsafe { check_mut!(ptextp) };
    *ptextp = ptr::null_mut();
    let psizep = unsafe { check_mut!(psizep) };
    *psizep = 0;

    let keylistp = unsafe { check_mut!(keylistp) };

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
        let buffer = malloc(content.len()) as *mut u8;
        if buffer.is_null() {
            return Err(Error::OutOfMemory(
                "content".into(), content.len()));
        }
        slice::from_raw_parts_mut(buffer, content.len())
            .copy_from_slice(&content);

        *ptextp = buffer as *mut _;

        // Don't count the trailing NUL.
        *psizep = content.len() - 1;
    }

    if h.signer_keylist.len() == 0 {
        h.signer_keylist.add("");
    }
    h.signer_keylist.append(&mut h.recipient_keylist);

    *keylistp = mem::replace(&mut h.signer_keylist, StringList::empty(mm)).to_c();

    if ! filename_ptr.is_null() {
        if let Some(p) = unsafe { filename_ptr.as_mut() } {
            if let Some(filename) = h.filename.as_ref() {
                *p = rust_bytes_to_c_str_lossy(mm, filename)?;
            } else {
                *p = ptr::null_mut();
            }
        };
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
    let session = Session::as_mut(session)?;
    let mm = session.mm();

    if size == 0 || sig_size == 0 {
        return Err(Error::DecryptWrongFormat);
    }

    let text = unsafe { check_slice!(text, size) };
    let signature = unsafe { check_slice!(signature, sig_size) };

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

        trace!("Text to verify: {} bytes with {} crlfs, {} bare crs and {} bare lfs",
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
        *p = mem::replace(&mut h.signer_keylist, StringList::empty(mm)).to_c();
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
    let session = Session::as_mut(session)?;
    let mm = session.mm();

    let fpr = unsafe { check_fpr!(fpr) };
    let ptext = unsafe { check_slice!(ptext, psize) };

    let stextp = unsafe {  check_mut!(stextp) };
    *stextp = ptr::null_mut();
    let ssizep = unsafe {  check_mut!(ssizep) };
    *ssizep = 0;

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

    rust_bytes_to_ptr_and_len(mm, stext, stextp, ssizep)?;

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
    trace!("pgp_encrypt_sign_optional");

    let session = Session::as_mut(session)?;
    let mm = session.mm();

    let ptext = unsafe { check_slice!(ptext, psize) };

    let ctextp = unsafe {  check_mut!(ctextp) };
    *ctextp = ptr::null_mut();
    let csizep = unsafe {  check_mut!(csizep) };
    *csizep = 0;

    let password = session.curr_passphrase();
    let keystore = session.keystore();


    let keylist = StringList::to_rust(mm, keylist, false);
    trace!("{} recipients.", keylist.len());
    for (i, v) in keylist.iter().enumerate() {
        trace!("  {}. {}", i, String::from_utf8_lossy(v.to_bytes()));
    }
    if sign {
        trace!("First recipient will sign the message");
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
            trace!("warning: {} doesn't have any valid encryption-capable subkeys",
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

    rust_bytes_to_ptr_and_len(mm, ctext, ctextp, csizep)?;

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
    let session = Session::as_mut(session)?;
    let mm = session.mm();

    let identity = PepIdentity::as_mut(identity)?;
    trace!("identity: {:?}", identity);

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
    trace!("password protected: {}",
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
    trace!("identity.address: {}", address);

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
    trace!("identity.username: {:?}", username);

    let userid = wrap_err!(
        UserID::from_unchecked_address(username, None, address)
            .or_else(|err| {
                if let Some(username) = username {
                    // Replace parentheses in input string with
                    // brackets.
                    let username = &username
                        .replace("(", "[")
                        .replace(")", "]")[..];
                    trace!("Invalid username, trying '{}'", username);
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
                    trace!("Invalid username, trying '{}'", username);
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

    identity.set_fingerprint(mm, fpr);

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
    let session = Session::as_mut(session)?;
    let keystore = session.keystore();

    let fpr = unsafe { check_fpr!(fpr) };
    trace!("Deleting {}", fpr);

    keystore.cert_delete(fpr)
});

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

    trace!("armor block offsets: {:?}", offsets);

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
        let mut retval = Error::KeyImported;

        offsets.push(keydata.len());
        for offsets in offsets.windows(2) {
            let keydata = &keydata[offsets[0]..offsets[1]];

            let curr_status = import_keydata_strict(session,
                                             keydata,
                                             identity_key,
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
    trace!("import_keydata");

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
                trace!("Can't import a {} signature", sig.typ());
                return Err(Error::NoKeyImported);
            }

            for issuer in sig.get_issuers().into_iter() {
                match keystore.cert_find_with_key(issuer.clone(), false) {
                    Err(err) => {
                        trace!("Can't merge signature: \
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
                            trace!("Revocation certificate not issued by {}: {}",
                               fpr, err);
                            continue;
                        }

                        match cert.insert_packets(sig.clone()) {
                            Err(err) => {
                                trace!("Merging signature with {} failed: {}",
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
                                        trace!("Saving updated certificate {} \
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

            trace!("Failed to import revocation certificate allegedly issued by {:?}.",
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

                        trace!("Importing certificate {}", fpr);
                        let mut contained = false;
                        for ua in cert.userids() {
                            trace!("  User ID: {}", ua.userid());
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
                        trace!("Adding {} to imported_keys", fpr);
                        if let Some(ident) = ident {
                            if is_tsk {
                                trace!("Adding {:?} to private_idents", ident);
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
            trace!("Can't import a {} packet", packet.tag());
            Err(Error::NoKeyImported)
        }
    }
}


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
    trace!("import_keydata");

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
                trace!("Can't import a {} signature", sig.typ());
                return Err(Error::NoKeyImported);
            }

            for issuer in sig.get_issuers().into_iter() {
                match keystore.cert_find_with_key(issuer.clone(), false) {
                    Err(err) => {
                        trace!("Can't merge signature: \
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
                            trace!("Revocation certificate not issued by {}: {}",
                               fpr, err);
                            continue;
                        }

                        match cert.insert_packets(sig.clone()) {
                            Err(err) => {
                                trace!("Merging signature with {} failed: {}",
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
                                        trace!("Saving updated certificate {} \
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

            trace!("Failed to import revocation certificate allegedly issued by {:?}.",
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

                        trace!("Importing certificate {}", fpr);
                        for ua in cert.userids() {
                            trace!("  User ID: {}", ua.userid());
                        }

                        let is_tsk = cert.is_tsk();
                        let (ident, changed)
                            = session.keystore().cert_save(cert)?;
                        imported_keys.add(fpr.to_hex());
                        trace!("Adding {} to imported_keys", fpr);
                        if let Some(ident) = ident {
                            if is_tsk {
                                trace!("Adding {:?} to private_idents", ident);
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
            trace!("Can't import a {} packet", packet.tag());
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

    trace!("armor block offsets: {:?}", offsets);

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
    let session = Session::as_mut(session)?;
    let mm = session.mm();

    let fpr = unsafe { check_fpr!(fpr) };
    trace!("({}, {})", fpr, if secret { "secret" } else { "public" });

    let keydatap = unsafe { check_mut!(keydatap) };
    let keydata_lenp = unsafe { check_mut!(keydata_lenp) };

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

    rust_bytes_to_ptr_and_len(mm, keydata, keydatap, keydata_lenp)?;

    Ok(())
});

// XXX: The engine does not use this function directly
// (OpenPGP_list_keyinfo is a thin wrapper) and there are no unit
// tests that exercise it.  Once there are unit tests, we can add an
// implementation.
//
// PEP_STATUS pgp_list_keyinfo(PEP_SESSION session,
//                             const char* pattern,
//                             stringpair_list_t** keyinfo_list)
stub!(pgp_list_keyinfo);

// The sequoia backend has never implemented this function, and the
// engine does not currently use it.
//
// PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
stub!(pgp_recv_key);

fn list_keys(session: *mut Session,
             pattern: *const c_char,
             keylistp: *mut *mut StringListItem,
             private_only: bool) -> Result<()>
{
    trace!("list_keys");

    let session = Session::as_mut(session)?;
    let mm = session.mm();

    let pattern = unsafe { check_cstr!(pattern) };
    // XXX: What should we do if pattern is not valid UTF-8?
    let pattern = pattern.to_string_lossy();

    let keylistp = unsafe { check_mut!(keylistp) };

    let mut keylist = StringList::empty(mm);

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

    trace!("Found {} certificates matching '{}'", keylist.len(), pattern);

    *keylistp = keylist.to_c();

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

// The sequoia backend has never implemented this function, and the
// engine does not currently use it.
//
// PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern)
stub!(pgp_send_key);

// PEP_STATUS pgp_renew_key(
//     PEP_SESSION session, const char *fpr, const timestamp *ts)
ffi!(fn pgp_renew_key(session: *mut Session,
                      fpr: *const c_char,
                      expiration: *const Timestamp)
    -> Result<()>
{
    let session = Session::as_mut(session)?;

    let fpr = unsafe { check_fpr!(fpr) };
    let expiration = unsafe { check_ptr!(expiration) };

    let password = session.curr_passphrase();
    let keystore = session.keystore();

    let expiration = Utc
        .with_ymd_and_hms(1900 + expiration.tm_year,
                          1 + expiration.tm_mon as u32,
                          expiration.tm_mday as u32,
                          expiration.tm_hour as u32,
                          expiration.tm_min as u32,
                          expiration.tm_sec as u32);
    let expiration = if let LocalResult::Single(t) = expiration {
        SystemTime::from(t)
    } else {
        return Err(Error::UnknownError(
            anyhow::anyhow!("invalid expiration time ({:?})",
                            expiration),
            "invalid expiration time".into()));
    };

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
    let session = Session::as_mut(session)?;

    let fpr = unsafe { check_fpr!(fpr) };
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
    trace!("_pgp_key_expired");

    if ! vc.alive().is_ok() {
        return true;
    }

    // Check to see if the key is broken. Ideally, we'd do this in one
    // pass below, but given the choice for how to check for expiry,
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

    trace!("Key can{} encrypt, can{} sign => {} expired",
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
    let session = Session::as_mut(session)?;

    let fpr = unsafe { check_fpr!(fpr) };
    let expiredp = unsafe { check_mut!(expiredp) };

    if when < 0 {
        // when is before UNIX EPOCH.  The key was not alive at
        // this time (the first keys were create around 1990).
        *expiredp = true;
        return Ok(());
    }
    let when = SystemTime::UNIX_EPOCH + Duration::new(when as u64, 0);

    let (cert, _private) = session.keystore().cert_find(fpr.clone(), false)?;
    let vc = wrap_err!(
        cert.with_policy(crate::P, when),
        UnknownError,
        "Invalid certificate")?;

    let expired = _pgp_key_expired(&vc);

    *expiredp = expired;

    trace!("{} is {}expired as of {:?}",
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
    let session = Session::as_mut(session)?;

    let fpr = unsafe { check_fpr!(fpr) };
    let revokedp = unsafe { check_mut!(revokedp) };

    let (cert, _private) = session.keystore().cert_find(fpr.clone(), false)?;

    let vc = wrap_err!(
        cert.with_policy(crate::P, None),
        UnknownError,
        "Invalid certificate")?;

    let revoked = _pgp_key_revoked(&vc);

    *revokedp = revoked;

    trace!("{} is {}revoked",
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
    let session = Session::as_mut(session)?;

    let fpr = unsafe { check_fpr!(fpr) };
    let comm_typep = unsafe { check_mut!(comm_typep) };
    let mut comm_type = |ct| *comm_typep = ct;

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

    trace!("worse enc: {:?}, worst sig: {:?}", worst_enc, worst_sign);

    if worst_enc == PepCommType::NoEncryption
        || worst_sign == PepCommType::NoEncryption
    {
        comm_type(PepCommType::KeyB0rken);
    } else {
        comm_type(cmp::min(worst_enc, worst_sign));
    }

    trace!("{}'s rating is {:?}", fpr, *comm_typep);

    Ok(())
});

// PEP_STATUS pgp_key_created(PEP_SESSION session, const char *fpr, time_t *created)
ffi!(fn pgp_key_created(session: *mut Session,
                        fpr: *const c_char,
                        createdp: *mut time_t)
    -> Result<()>
{
    let session = Session::as_mut(session)?;

    let fpr = unsafe { check_fpr!(fpr) };
    let createdp = unsafe { check_mut!(createdp) };

    let (cert, _private) = session.keystore().cert_find(fpr, false)?;

    let t = wrap_err!(
        cert.primary_key().creation_time().duration_since(UNIX_EPOCH),
        UnknownError,
        "Creation time out of range")?.as_secs();

    *createdp = t as time_t;

    Ok(())
});

// PEP_STATUS pgp_binary(const char **path)
ffi!(fn pgp_binary(path: *mut *mut c_char) -> Result<()> {
    let path = unsafe { check_mut!(path) };
    *path = ptr::null_mut();
    Ok(())
});


// PEP_STATUS pgp_contains_priv_key(PEP_SESSION session, const char *fpr,
//                                  bool *has_private)
ffi!(fn pgp_contains_priv_key(session: *mut Session, fpr: *const c_char,
                              has_privatep: *mut bool)
    -> Result<()>
{
    let session = Session::as_mut(session)?;

    let fpr = unsafe { check_fpr!(fpr) };
    let has_privatep = unsafe { check_mut!(has_privatep) };

    let has_private = match session.keystore().cert_find(fpr, true) {
        Ok(_) => true,
        Err(Error::KeyNotFound(_)) => false,
        Err(err) => return Err(err),
    };

    *has_privatep = has_private;

    Ok(())
});

// PEP_STATUS pgp_random(char *buffer, size_t len)
ffi!(fn pgp_random(buffer: *mut c_char, len: size_t) -> Result<()> {
    let buffer = unsafe { check_slice_mut!(buffer, len) };
    openpgp::crypto::random(buffer);
    Ok(())
});

#[test]
fn test_random() {
    fn rand(i: usize) -> Vec<u8> {
        let mut buffer = vec![0u8; i];
        let result = pgp_random(buffer.as_mut_ptr() as *mut c_char, i);
        assert_eq!(result, 0, "pgp_random does not fail");
        buffer
    }

    for _ in 0..32 {
        // Get a bunch of bytes, sum them and figure out the average.
        let mut total = 0u64;
        let mut ones_count = 0u64;
        let mut samples = 0;
        for i in 0..128 {
            let buffer = rand(i);
            for e in buffer.into_iter() {
                total += e as u64;
                ones_count += (e as u8).count_ones() as u64;
                samples += 1;
            }
        }

        // On average we expect: total / samples to be 127.5.  Fail if it is
        // very unlikely (probability is left as an exercise for the
        // reader).
        assert!(samples > 0);
        let average = total / samples;
        eprintln!("{} / {} = {}", total, samples, average);
        assert!(128 - 8 < average && average < 128 + 8,
                "{} is extremely unlikely, your random number generator \
                 is broken",
                average);

        // On average, we should have 4 ones.
        let average_ones = ones_count / samples;
        eprintln!("ones count: {} / {} = {}",
                  ones_count, samples, average_ones);
        assert!(3 * samples <= ones_count && ones_count <= 5 * samples,
                "Average number of ones ({}) is extremely unlikely, \
                 your random number generator is broken",
                average_ones);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pep::Session;

    // $ sq --force key generate --cannot-authenticate \
    //   --expires never --userid '<alice@example.org>' \
    //   --export alice.pgp
    const ALICE_PGP: &'static str = "\
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: 64E7 981D 4220 C6D2 6638  EA7C B72F C47E 011B C764
Comment: <alice@example.org>

xVgEZDcXhRYJKwYBBAHaRw8BAQdAu8SZs5zqYLLBaMpfbIuRg9CDuQNnkxGqCEiv
MnD0czYAAQD2c2gL/jPZzZHbBQ2OHycdNOep79BLfs6ZBYiTodrukBDvwsALBB8W
CgB9BYJkNxeFAwsJBwkQty/EfgEbx2RHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMu
c2VxdW9pYS1wZ3Aub3Jn37FPCmBUoG7ZfDm0Q7haM6zbXc/00GediXbjruMVCU8D
FQoIApsBAh4BFiEEZOeYHUIgxtJmOOp8ty/EfgEbx2QAAKL8AQD3bT5GYlfah/jx
agUUPAU9awR17PJiF6qWZjhk0wX5GgEAyn0OjvpkCh8IUVXpgtmuN8NoBHXvLrPH
FPpmBRhuEQfNEzxhbGljZUBleGFtcGxlLm9yZz7CwA4EExYKAIAFgmQ3F4UDCwkH
CRC3L8R+ARvHZEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5v
cmfHWWYTVAdC9hBB3QvxZv+gKmr8p8yP48nf/4pMJHCbeQMVCggCmQECmwECHgEW
IQRk55gdQiDG0mY46ny3L8R+ARvHZAAAkPcA/06QXtr0odpnQTQAzbgnDHCTisPv
TeWhbP8Bu6dPSIjPAP9aZPn+s+Pdc52SEHBOQyM5dyWpbzvgLgwzNCetez6vDcdY
BGQ3F4UWCSsGAQQB2kcPAQEHQFda1LIxdqccxiIgIbHXral59VRIPqrBnCSUckTe
lZsSAAD/f7zaMPxIrEVkSkevdsdg5Om0Cgyz+SF8f9/763kPWF4SHMLAvwQYFgoB
MQWCZDcXhQkQty/EfgEbx2RHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9p
YS1wZ3Aub3Jn7pAplEnQhQvvgDihCw52kKa/JT50MTuZPkDY5bpsVhMCmwK+oAQZ
FgoAbwWCZDcXhQkQ2W9Jvvf+shBHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2Vx
dW9pYS1wZ3Aub3JnOmJvUfEy2ymUu3MyS+J92P2nuaBYjpJ2L6hcuf8Bm+gWIQQV
Suent38vsP649abZb0m+9/6yEAAApsYA/0Pdfn61X/u1GEVhCc0bKkBVYHwlXEJa
nQ+9KBVaJFWnAQCh5bNyeV+8MU9odXZWxa8sg1VeDkFCTppWTsZTH9UHBRYhBGTn
mB1CIMbSZjjqfLcvxH4BG8dkAABsNAEA9SQeJIPp9SMFJY2nCcclv0u/KxfZTBOJ
1jfMU8LrJZAA/34fNxcn99iv23yIv1QnZtBogP5cfcxxhnaHlVPnaDAMx10EZDcX
hRIKKwYBBAGXVQEFAQEHQLgFZFFGd+IWWAehV4i7b23SLLsxlaWsacPSkFswfl59
AwEIBwAA/1Wj3K1G1S95h+0jhugeYnj1LZLWO4PiaiiSBCN3IxNoD8rCwAAEGBYK
AHIFgmQ3F4UJELcvxH4BG8dkRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVv
aWEtcGdwLm9yZxtd7Kn2Jmj5NYfdhBVEL2qLvRZAvnfp5oveXeradLAhApsMFiEE
ZOeYHUIgxtJmOOp8ty/EfgEbx2QAAMDtAQC5fuVHyLfl1SqncTZaZkdaoSEqHdZA
4RICLYzXmmut2gD/U5k61iRwqBWiepJ1IBNQKJvq4j0CWr0LaUk4FtGi6go=
=qYY6
-----END PGP PRIVATE KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: 64E7 981D 4220 C6D2 6638  EA7C B72F C47E 011B C764
Comment: <12alic231e@231example.org>

xVgEZDcXhRYJKwYBBAHaRw8BAQdAu8SZs5zqYLLBaMpfbIuRg9CDuQNnkxGqCEiv
MnD0czYAAQD2c2gL/jPZzZHbBQ2OHycdNOep79BLfs6ZBYiTodrukBDvwsALBB8W
CgB9BYJkNxeFAwsJBwkQty/EfgEbx2RHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMu
c2VxdW9pYS1wZ3Aub3Jn37FPCmBUoG7ZfDm0Q7haM6zbXc/00GediXbjruMVCU8D
FQoIApsBAh4BFiEEZOeYHUIgxtJmOOp8ty/EfgEbx2QAAKL8AQD3bT5GYlfah/jx
agUUPAU9awR17PJiF6qWZjhk0wX5GgEAyn0OjvpkCh8IUVXpgtmuN8NoBHXvLrPH
FPpmBRhuEQfNEzxhbGljZUBleGFtcGxlLm9yZz7CwA4EExYKAIAFgmQ3F4UDCwkH
CRC3L8R+ARvHZEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5v
cmfHWWYTVAdC9hBB3QvxZv+gKmr8p8yP48nf/4pMJHCbeQMVCggCmQECmwECHgEW
IQRk55gdQiDG0mY46ny3L8R+ARvHZAAAkPcA/06QXtr0odpnQTQAzbgnDHCTisPv
TeWhbP8Bu6dPSIjPAP9aZPn+s+Pdc52SEHBOQyM5dyWpbzvgLgwzNCetez6vDcdY
BGQ3F4UWCSsGAQQB2kcPAQEHQFda1LIxdqccxiIgIbHXral59VRIPqrBnCSUckTe
lZsSAAD/f7zaMPxIrEVkSkevdsdg5Om0Cgyz+SF8f9/763kPWF4SHMLAvwQYFgoB
MQWCZDcXhQkQty/EfgEbx2RHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9p
YS1wZ3Aub3Jn7pAplEnQhQvvgDihCw52kKa/JT50MTuZPkDY5bpsVhMCmwK+oAQZ
FgoAbwWCZDcXhQkQ2W9Jvvf+shBHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2Vx
dW9pYS1wZ3Aub3JnOmJvUfEy2ymUu3MyS+J92P2nuaBYjpJ2L6hcuf8Bm+gWIQQV
Suent38vsP649abZb0m+9/6yEAAApsYA/0Pdfn61X/u1GEVhCc0bKkBVYHwlXEJa
nQ+9KBVaJFWnAQCh5bNyeV+8MU9odXZWxa8sg1VeDkFCTppWTsZTH9UHBRYhBGTn
mB1CIMbSZjjqfLcvxH4BG8dkAABsNAEA9SQeJIPp9SMFJY2nCcclv0u/KxfZTBOJ
1jfMU8LrJZAA/34fNxcn99iv23yIv1QnZtBogP5cfcxxhnaHlVPnaDAMx10EZDcX
hRIKKwYBBAGXVQEFAQEHQLgFZFFGd+IWWAehV4i7b23SLLsxlaWsacPSkFswfl59
AwEIBwAA/1Wj3K1G1S95h+0jhugeYnj1LZLWO4PiaiiSBCN3IxNoD8rCwAAEGBYK
AHIFgmQ3F4UJELcvxH4BG8dkRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVv
aWEtcGdwLm9yZxtd7Kn2Jmj5NYfdhBVEL2qLvRZAvnfp5oveXeradLAhApsMFiEE
ZOeYHUIgxtJmOOp8ty/EfgEbx2QAAMDtAQC5fuVHyLfl1SqncTZaZkdaoSEqHdZA
4RICLYzXmmut2gD/U5k61iRwqBWiepJ1IBNQKJvq4j0CWr0LaUk4FtGi6go=
=qYY6
-----END PGP PRIVATE KEY BLOCK-----

";

    // $ echo hi, pep | sq encrypt --recipient-file alice.pgp --signer-file alice.pgp > msg.pgp
    // $ sq decrypt --recipient-file alice.pgp --dump-session-key msg.pgp
    // Session key: 09B40F05C8F12C7FF6F409698E2358C221654CDC7E300872686FEF1E16EF2385
    // Encrypted using AES-256
    // Compressed using ZIP
    // No key to check checksum from 154AE7A7B77F2FB0FEB8F5A6D96F49BEF7FEB210
    // hi, pep
    // 1 unknown checksum.
    // $ sq packet dump --session-key 09B40F05C8F12C7FF6F409698E2358C221654CDC7E300872686FEF1E16EF2385 msg.pgp
    // Public-Key Encrypted Session Key Packet, new CTB, 94 bytes
    //     Version: 3
    //     Recipient: 003F542BE1540CD4
    //     Pk algo: ECDH
    //   
    // Sym. Encrypted and Integrity Protected Data Packet, new CTB, 300 bytes
    // │   Version: 1
    // │   Session key: 09B40F05C8F12C7FF6F409698E2358C221654CDC7E300872686FEF1E16EF2385
    // │   Symmetric algo: AES-256
    // │   Decryption successful
    // │ 
    // ├── Compressed Data Packet, new CTB, 256 bytes
    // │   │   Algorithm: ZIP
    // │   │ 
    // │   ├── One-Pass Signature Packet, new CTB, 13 bytes
    // │   │       Version: 3
    // │   │       Type: Binary
    // │   │       Pk algo: EdDSA
    // │   │       Hash algo: SHA512
    // │   │       Issuer: D96F49BEF7FEB210
    // │   │       Last: true
    // │   │     
    // │   ├── Literal Data Packet, new CTB, 14 bytes
    // │   │       Format: Binary data
    // │   │       Content: "hi, pep\n"
    // │   │     
    // │   └── Signature Packet, new CTB, 212 bytes
    // │           Version: 4
    // │           Type: Binary
    // │           Pk algo: EdDSA
    // │           Hash algo: SHA512
    // │           Hashed area:
    // │             Signature creation time: 2023-04-12 20:42:56 UTC (critical)
    // │             Issuer: D96F49BEF7FEB210
    // │             Notation: salt@notations.sequoia-pgp.org
    // │               00000000  a3 9e a8 6a 74 da a0 e6  8a 92 9d 06 8a 08 ad c6
    // │               00000010  68 35 48 0a a8 f4 79 cf  2f 4e 58 94 95 93 42 31
    // │             Issuer Fingerprint: 154AE7A7B77F2FB0FEB8F5A6D96F49BEF7FEB210
    // │             Intended Recipient: 64E7981D4220C6D26638EA7CB72FC47E011BC764
    // │           Digest prefix: 843B
    // │           Level: 0 (signature over data)
    // │         
    // └── Modification Detection Code Packet, new CTB, 20 bytes
    //         Digest: 430056320490BE00DD9695E9DA5964207E54844B
    //         Computed digest: 430056320490BE00DD9695E9DA5964207E54844B
    const CTEXT: &'static str = "\
-----BEGIN PGP MESSAGE-----

wV4DAD9UK+FUDNQSAQdAjozAEPDG+bvHV3YjHuBcJMhPfltHaK83R6kSyvIYSHUw
4k+spf7kJJ73EMrhgzlf92Ems0RZXTeCDOKKDFAP1yfXP1ZIX3WVHraMsOg3zQSc
0sBsAVbTDJEvN8Y94sDQtZkj7gObqTyyQZAe+oj2ZXxY+b+uGJ+9sAP26mdubfZ+
HyduxJC2nlImUwC/TMInblDyJNUiOJz5i9Wa73I8A0EkGFsdWbXQ5RkK82oQx8Bi
UYr+5DzpYhuKgqgEA46KdQv9L92sUzv/tyRaLH3i6sSmzioWDuSGPxBf6sGrywWc
tCgdoM9Lnwuhbv60Qobm1MfLMCwwkbXsy0rH6Pel5kWPnBrNWEi3hNhzMGeDKD9S
izKTrCcA1NbpFL7nndShmIlRFZ5q+XNdyWB0STFaPV5uzfCnxXpNrz7m4EXOFSZP
k4tPxebef5BpUqRxdEhHQab24bTKrI1cWa9pJdpWQrssEPE7y7pNB83p/I+fKqYv
7ykni6KBcL+Bcyf6d3xx
=PALz
-----END PGP MESSAGE-----
";
    const EXPIRED_MSG: &'static str = "\
    -----BEGIN PGP MESSAGE-----

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
l/Z6+iUK0OopAbQ=
=DDIW
-----END PGP MESSAGE-----
";
    const MSG: &'static str = "hi, pep\n";

    #[test]
    fn decrypt() -> Result<()> {
        // This uses an in-memory keystore.
        let session = Session::new();

        let rc = pgp_import_keydata(
            session,
            ALICE_PGP.as_ptr() as *const c_char, ALICE_PGP.len(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut());
        assert_eq!(rc, Error::KeyImported.into());

        let mut plaintext: *mut c_char = std::ptr::null_mut();
        let mut plaintext_len: size_t = 0;

        let mut keylist: *mut StringListItem = std::ptr::null_mut();

        let rc = pgp_decrypt_and_verify(
            session,
            CTEXT.as_ptr() as *const c_char, CTEXT.len(),
            std::ptr::null(), 0, // dsigtext, dsigsize
            &mut plaintext, &mut plaintext_len as *mut _,
            &mut keylist as *mut *mut _,
            std::ptr::null_mut(), // filename_ptr
        );

        // If this returns Error::MalformedMessage, it probably means
        // that decompression is not enabled.
        assert_eq!(rc, Error::DecryptedAndVerified.into());

        let ptext = unsafe { check_slice!(plaintext, plaintext_len) };
        assert_eq!(ptext, MSG.as_bytes());

        // Clean up.
        unsafe { Box::from_raw(session) };

        Ok(())
    }
    #[test]
    fn decrypt_expired_msg() -> Result<()> {
        // This uses an in-memory keystore.
        let session = Session::new();

        let rc = pgp_import_keydata(
            session,
            ALICE_PGP.as_ptr() as *const c_char, ALICE_PGP.len(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut());
        assert_eq!(rc, Error::KeyImported.into());

        let mut plaintext: *mut c_char = std::ptr::null_mut();
        let mut plaintext_len: size_t = 0;

        let mut keylist: *mut StringListItem = std::ptr::null_mut();

        let rc = pgp_decrypt_and_verify(
            session,
            EXPIRED_MSG.as_ptr() as *const c_char, EXPIRED_MSG.len(),
            std::ptr::null(), 0, // dsigtext, dsigsize
            &mut plaintext, &mut plaintext_len as *mut _,
            &mut keylist as *mut *mut _,
            std::ptr::null_mut(), // filename_ptr
        );

        // If this returns Error::MalformedMessage, it probably means
        // that decompression is not enabled.
        assert_eq!(rc, 0x0405);

        // let ptext = unsafe { check_slice!(plaintext, plaintext_len) };
        // let s = String::from_utf8_lossy(ptext);
    
        // println!("well: {} then", s);
        //assert_eq!(ptext, MSG.as_bytes());

        // Clean up.
        unsafe { Box::from_raw(session) };

        Ok(())
    }

}

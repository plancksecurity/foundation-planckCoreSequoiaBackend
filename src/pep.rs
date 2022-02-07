use std::ops::BitAnd;
use std::convert::TryFrom;

#[cfg(not(windows))]
use libc::tm;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

mod session;
pub use session::Session;
mod identity;
pub use identity::{
    PepIdentityTemplate,
    PepIdentity,
    PepIdentityListItem,
    PepIdentityList,
};

mod stringlist;
pub use stringlist::{
    StringListItem,
    StringList,
    StringListIterMut,
    StringListIter,
};

// Transforms an error from some error type to the pep::Error.
macro_rules! wrap_err {
    ($e:expr, $err:ident, $msg:expr) => {
        $e.map_err(|err| {
            eprintln!("Error: {}: {}\n{:?}",
                      err, $msg, backtrace::Backtrace::new());
            crate::pep::Error::$err(
                anyhow::Error::from(err).into(),
                String::from($msg))
        })
    }
}

// We use Error rather than anyhow's error so that we force the
// function to convert the error into a form that we can easily pass
// back to the engine.
pub type Result<T> = std::result::Result<T, Error>;

// The pEp engine's error type.
pub type ErrorCode = i32;

#[enumber::into]
// XXX: This should be ErrorCode, but we can't use type aliases here :/.
#[repr(i32)]
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
#[allow(unused)]
pub enum Error {
    #[error("Success")]
    StatusOk = 0,
    #[error("Initializing the crypto library failed: {0}")]
    InitCryptoLibInitFailed(String) = 0x0111,

    // PEP_INIT_CANNOT_LOAD_CRYPTO_LIB                 = 0x0110,
    // PEP_INIT_CRYPTO_LIB_INIT_FAILED                 = 0x0111,
    // PEP_INIT_NO_CRYPTO_HOME                         = 0x0112,
    // PEP_INIT_NETPGP_INIT_FAILED                     = 0x0113,
    // PEP_INIT_CANNOT_DETERMINE_CRYPTO_VERSION        = 0x0114,
    // PEP_INIT_UNSUPPORTED_CRYPTO_VERSION             = 0x0115,
    // PEP_INIT_CANNOT_CONFIG_CRYPTO_AGENT             = 0x0116,
    //
    // PEP_INIT_SQLITE3_WITHOUT_MUTEX                  = 0x0120,

    #[error("Opening the database failed: {1}")]
    InitCannotOpenDB(#[source] anyhow::Error, String) = 0x0121,

    // PEP_INIT_CANNOT_OPEN_SYSTEM_DB                  = 0x0122,
    // PEP_INIT_DB_DOWNGRADE_VIOLATION                 = 0x0123,

    #[error("Database error: {1}")]
    UnknownDbError(#[source] anyhow::Error, String) = 0x01ff,

    #[error("Key {0} not present in database")]
    KeyNotFound(KeyHandle) = 0x0201,
    // PEP_KEY_HAS_AMBIG_NAME                          = 0x0202,

    #[error("Getting key: {1}")]
    GetKeyFailed(#[source] anyhow::Error, String) = 0x0203,

    // PEP_CANNOT_EXPORT_KEY                           = 0x0204,
    // PEP_CANNOT_EDIT_KEY                             = 0x0205,
    #[error("Key unsuitable: {0}")]
    KeyUnsuitable(#[source] anyhow::Error, String) = 0x0206,

    // PEP_MALFORMED_KEY_RESET_MSG                     = 0x0210,
    // PEP_KEY_NOT_RESET                               = 0x0211,
    #[error("Cannot delete key: {0}")]
    CannotDeleteKey(#[source] anyhow::Error, String) = 0x0212,
    #[error("Imported key")]
    KeyImported = 0x0220,
    #[error("No key imported")]
    NoKeyImported = 0x0221,
    // PEP_KEY_IMPORT_STATUS_UNKNOWN                   = 0x0222,
    #[error("Some keys imported")]
    SomeKeysImported = 0x0223,

    // PEP_CANNOT_FIND_IDENTITY                        = 0x0301,
    // PEP_CANNOT_SET_PERSON                           = 0x0381,
    // PEP_CANNOT_SET_PGP_KEYPAIR                      = 0x0382,
    // PEP_CANNOT_SET_IDENTITY                         = 0x0383,
    // PEP_CANNOT_SET_TRUST                            = 0x0384,
    // PEP_KEY_BLACKLISTED                             = 0x0385,
    // PEP_CANNOT_FIND_PERSON                          = 0x0386,
    // PEP_CANNOT_SET_PEP_VERSION                      = 0X0387,
    //
    // PEP_CANNOT_FIND_ALIAS                           = 0x0391,
    // PEP_CANNOT_SET_ALIAS                            = 0x0392,
    // PEP_NO_OWN_USERID_FOUND                         = 0x0393,
    //
    #[error("Message not encrypted and not verified")]
    Unencrypted = 0x0400,
    #[error("Message not encrypted, but verified")]
    Verified = 0x0401,
    #[error("Decrypted message")]
    Decrypted = 0x0402,
    #[error("Decrypted and verified message")]
    DecryptedAndVerified = 0x0403,
    #[error("Decrypted failed: wrong format")]
    DecryptWrongFormat = 0x0404,
    #[error("Decrypted failed: no key")]
    DecryptNoKey(#[source] anyhow::Error) = 0x0405,
    #[error("Decrypted failed: signature does not match")]
    DecryptSignatureDoesNotMatch = 0x0406,
    #[error("Verification failed: no key")]
    VerifyNoKey(#[source] anyhow::Error) = 0x0407,
    // PEP_VERIFIED_AND_TRUSTED                        = 0x0408,
    // PEP_CANNOT_REENCRYPT                            = 0x0409,
    #[error("Signer's key is revoked")]
    VerifySignerKeyRevoked = 0x040a,
    #[error("Cannot decrypt: {0}")]
    CannotDecryptUnknown(String) = 0x04ff,
    //
    //
    // PEP_TRUSTWORD_NOT_FOUND                         = 0x0501,
    // PEP_TRUSTWORDS_FPR_WRONG_LENGTH                 = 0x0502,
    // PEP_TRUSTWORDS_DUPLICATE_FPR                    = 0x0503,
    //
    #[error("Cannot create key")]
    CannotCreateKey(#[source] anyhow::Error, String) = 0x0601,
    // PEP_CANNOT_SEND_KEY                             = 0x0602,
    //
    // PEP_PHRASE_NOT_FOUND                            = 0x0701,
    //
    // PEP_SEND_FUNCTION_NOT_REGISTERED                = 0x0801,
    // PEP_CONTRAINTS_VIOLATED                         = 0x0802,
    // PEP_CANNOT_ENCODE                               = 0x0803,
    //
    // PEP_SYNC_NO_NOTIFY_CALLBACK                     = 0x0901,
    // PEP_SYNC_ILLEGAL_MESSAGE                        = 0x0902,
    // PEP_SYNC_NO_INJECT_CALLBACK                     = 0x0903,
    // PEP_SYNC_NO_CHANNEL                             = 0x0904,
    // PEP_SYNC_CANNOT_ENCRYPT                         = 0x0905,
    // PEP_SYNC_NO_MESSAGE_SEND_CALLBACK               = 0x0906,
    // PEP_SYNC_CANNOT_START                           = 0x0907,
    //
    // PEP_CANNOT_INCREASE_SEQUENCE                    = 0x0971,
    //
    // PEP_STATEMACHINE_ERROR                          = 0x0980,
    // PEP_NO_TRUST                                    = 0x0981,
    // PEP_STATEMACHINE_INVALID_STATE                  = 0x0982,
    // PEP_STATEMACHINE_INVALID_EVENT                  = 0x0983,
    // PEP_STATEMACHINE_INVALID_CONDITION              = 0x0984,
    // PEP_STATEMACHINE_INVALID_ACTION                 = 0x0985,
    // PEP_STATEMACHINE_INHIBITED_EVENT                = 0x0986,
    // PEP_STATEMACHINE_CANNOT_SEND                    = 0x0987,
    //
    #[error("Passphrase required")]
    PassphraseRequired = 0x0a00,
    #[error("Bad passphrase")]
    WrongPassphrase(#[source] anyhow::Error, String) = 0x0a01,
    #[error("Passphrase required for new keys")]
    PassphraseForNewKeysRequired = 0x0a02,
    //
    // PEP_CANNOT_CREATE_GROUP                         = 0x0b00,
    // PEP_CANNOT_FIND_GROUP_ENTRY                     = 0x0b01,
    // PEP_GROUP_EXISTS                                = 0x0b02,
    // PEP_GROUP_NOT_FOUND                             = 0x0b03,
    // PEP_CANNOT_ENABLE_GROUP                         = 0x0b04,
    // PEP_CANNOT_DISABLE_GROUP                        = 0x0b05,
    // PEP_CANNOT_ADD_GROUP_MEMBER                     = 0x0b06,
    // PEP_CANNOT_DEACTIVATE_GROUP_MEMBER              = 0x0b07,
    // PEP_NO_MEMBERSHIP_STATUS_FOUND                  = 0x0b08,
    // PEP_CANNOT_LEAVE_GROUP                          = 0x0b09,
    // PEP_CANNOT_JOIN_GROUP                           = 0x0b0a,
    // PEP_CANNOT_RETRIEVE_MEMBERSHIP_INFO             = 0x0b0b,
    //
    // PEP_DISTRIBUTION_ILLEGAL_MESSAGE                = 0x1002,
    // PEP_STORAGE_ILLEGAL_MESSAGE                     = 0x1102,
    //
    // PEP_COMMIT_FAILED                               = 0xff01,
    // PEP_MESSAGE_CONSUME                             = 0xff02,
    // PEP_MESSAGE_IGNORE                              = 0xff03,
    #[error("Invalid configuration: {0}")]
    CannotConfig(String) = 0xff04,
    //
    // PEP_RECORD_NOT_FOUND                            = -6,
    // PEP_CANNOT_CREATE_TEMP_FILE                     = -5,
    #[error("Illegal value: {0}")]
    IllegalValue(String) = -4,

    // PEP_BUFFER_TOO_SMALL                            = -3,
    #[error("Out of memory: {1} bytes for {0}")]
    OutOfMemory(String, usize) = -2,
    #[error("Unknown error: {1}")]
    UnknownError(#[source] anyhow::Error, String) = -1,

    // PEP_VERSION_MISMATCH                            = -7,
}

// See pEpEngine/src/timestamp.h
//
//   https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/branch/master/src/timestamp.h
#[cfg(not(windows))]
pub type Timestamp = tm;

#[cfg(windows)]
use libc::{c_int, c_long};
#[cfg(windows)]
#[repr(C)]
// for time values all functions are using POSIX struct tm
pub struct Timestamp {
    pub tm_sec: c_int,
    pub tm_min: c_int,
    pub tm_hour: c_int,
    pub tm_mday: c_int,
    pub tm_mon: c_int,
    pub tm_year: c_int,
    pub tm_wday: c_int,
    pub tm_yday: c_int,
    pub tm_isdst: c_int,
    pub tm_gmtoff: c_long, // offset from GMT in seconds
}

// See pEpEngine/src/pEpEngine.h:PEP_comm_format.
//
//   https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/branch/master/src/pEpEngine.h#L697
#[repr(C)]
#[allow(unused)]
#[derive(PartialOrd, Ord, PartialEq, Eq, Copy, Clone, Debug)]
pub enum PepCommType {
    Unknown = 0,

    // range 0x01 to 0x09: no encryption, 0x0a to 0x0e: nothing reasonable

    NoEncryption = 0x01,                // generic
    NoEncryptedChannel = 0x02,
    KeyNotFound = 0x03,
    KeyExpired = 0x04,
    KeyRevoked = 0x05,
    KeyB0rken = 0x06,
    KeyExpiredButConfirmed = 0x07, // NOT with confirmed bit. Just retaining info here in case of renewal.
    MyKeyNotIncluded = 0x09,

    SecurityByObscurity = 0x0a,
    B0rkenCrypto = 0x0b,
    KeyTooShort = 0x0c,

    Compromised = 0x0e,                  // known compromised connection
    Mistrusted = 0x0f,                   // known mistrusted key

    // range 0x10 to 0x3f: unconfirmed encryption

    UnconfirmedEncryption = 0x10,       // generic
    OpenPgpWeakUnconfirmed = 0x11,     // RSA 1024 is weak

    ToBeChecked = 0x20,                // generic
    SMimeUnconfirmed = 0x21,
    CmsUnconfirmed = 0x22,

    StrongButUnconfirmed = 0x30,       // generic
    OpenPgpUnconfirmed = 0x38,          // key at least 2048 bit RSA or EC
    OtrUnconfirmed = 0x3a,

    // range 0x40 to 0x7f: unconfirmed encryption and anonymization

    UnconfirmedEncAnon = 0x40,         // generic
    PepUnconfirmed = 0x7f,

    Confirmed = 0x80,                    // this bit decides if trust is confirmed

    // range 0x81 to 0x8f: reserved
    // range 0x90 to 0xbf: confirmed encryption

    ConfirmedEncryption = 0x90,         // generic
    OpenPgpWeak = 0x91,                 // RSA 1024 is weak (unused)

    ToBeCheckedConfirmed = 0xa0,      // generic
    SMime = 0xa1,
    Cms = 0xa2,

    StrongEncryption = 0xb0,            // generic
    OpenPgp = 0xb8,                      // key at least 2048 bit RSA or EC
    Otr = 0xba,

    // range 0xc0 to 0xff: confirmed encryption and anonymization

    ConfirmedEncAnon = 0xc0,           // generic
    Pep = 0xff
}

// See pEpEngine/src/pEpEngine.h:PEP_enc_format.
//
//   https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/branch/master/src/pEpEngine.h#L179
#[repr(C)]
#[allow(unused)]
pub enum PepEncFormat {
    None = 0,                       // message is not encrypted
    Pieces = 1,                     // inline PGP + PGP extensions, was removed
    // Inline = 1,                     // still there
    SMime = 2,                      // RFC5751
    PgpMime = 3,                    // RFC3156
    Pep = 4,                        // pEp encryption format
    PgpMimeOutlook1 = 5,            // Message B0rken by Outlook type 1
    InlineEA = 6,
    Auto = 255                      // figure out automatically where possible
}

// See pEpEngine/src/pEpEngine.h:identity_flags.
//
//   https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/branch/master/src/pEpEngine.h#L765
#[repr(C)]
#[allow(unused)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PepIdentityFlags {
    // the first octet flags are app defined settings:

    // don't use this identity for sync
    NotForSync = 0x0001,
    // identity of list of persons
    List = 0x0002,

    // the second octet flags are calculated:

    // identity of a device group member
    DeviceGroup = 0x0100,
    // identity is associated with an org (i.e. NOT a private account
    // - could be company email)
    OrgIdent = 0x0200,
    // identity is a group identity (e.g. mailing list) - N.B. not
    // related to device group!
    GroupIdent = 0x0400,
}


impl BitAnd for PepIdentityFlags {
    type Output = usize;

    fn bitand(self, rhs: Self) -> Self::Output {
        (self as usize) & (rhs as usize)
    }
}

impl PepIdentityFlags {
    /// Returns whether the specified flag is set.
    pub fn is_set(&self, flag: PepIdentityFlags) -> bool {
        let flag = flag as usize;
        assert_eq!(flag.count_ones(), 1);
        ((*self as usize) & flag) != 0
    }
}

// See pEpEngine/src/pEpEngine.h:PEP_CIPHER_SUITE.
//
//   https://gitea.pep.foundation/pEp.foundation/pEpEngine/src/branch/master/src/pEpEngine.h#L395
#[repr(C)]
#[allow(unused)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PepCipherSuite {
    Default = 0,
    Cv25519 = 1,
    P256 = 2,
    P384 = 3,
    P521 = 4,
    Rsa2K = 5,
    Rsa3K = 6,
    Rsa4K = 7,
    Rsa8K = 8,
}

impl Default for PepCipherSuite {
    fn default() -> Self {
        PepCipherSuite::Default
    }
}

impl TryFrom<PepCipherSuite> for openpgp::cert::CipherSuite {
    type Error = Error;

    fn try_from(cs: PepCipherSuite) -> Result<openpgp::cert::CipherSuite> {
        use openpgp::cert::CipherSuite::*;
        match cs {
            PepCipherSuite::Default => Ok(RSA2k),
            PepCipherSuite::Cv25519 => Ok(Cv25519),
            PepCipherSuite::P256 => Ok(P256),
            PepCipherSuite::P384 => Ok(P384),
            PepCipherSuite::P521 => Ok(P521),
            PepCipherSuite::Rsa2K => Ok(RSA2k),
            PepCipherSuite::Rsa3K => Ok(RSA3k),
            PepCipherSuite::Rsa4K => Ok(RSA4k),
            _ => Err(Error::IllegalValue(
                format!("Unknown cipher suite: {}", cs as usize)))
        }
    }
}

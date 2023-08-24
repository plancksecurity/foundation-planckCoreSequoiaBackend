use std::cmp;
#[cfg(not(windows))]
use std::env;
use std::path::Path;
use std::path::PathBuf;

use rusqlite::{
    CachedStatement,
    Connection,
    OpenFlags,
    OptionalExtension,
    params,
    Row,
};

use lru::LruCache;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Fingerprint,
    KeyHandle,
    KeyID,
    packet::UserID,
    parse::Parse,
    serialize::Serialize,
    types::HashAlgorithm,
    types::RevocationStatus,
};

use crate::Result;
use crate::Error;
use crate::constants::{
    KEYS_DB,
    BUSY_WAIT_TIME,
};
use crate::pep::PepIdentityTemplate;

// Pick the fastest hash function from the SHA2 family for the
// architecture's word size.  On 64-bit architectures, SHA512 is
// almost twice as fast, but on 32-bit ones, SHA256 is faster.
#[cfg(target_pointer_width = "64")]
const CACHE_HASH: HashAlgorithm = HashAlgorithm::SHA512;
#[cfg(not(target_pointer_width = "64"))]
const CACHE_HASH: HashAlgorithm = HashAlgorithm::SHA256;

// The number of entries in the cache.  Do not make this too big since
// we iterate over the cache to purge stale entries.
const CERT_CACHE_ENTRIES: std::num::NonZeroUsize
    = unsafe { std::num::NonZeroUsize::new_unchecked(32) };

type CertCache = LruCache<Vec<u8>, Cert>;

pub struct Keystore {
    conn: rusqlite::Connection,
    // The certificate cache.
    //
    // This cache maps:
    //
    //   HASH(keydata) -> Cert
    //
    // That is, it is keyed by the hash of the keydata as read from
    // the keys DB, *not* by the certificate's fingerprint.  This
    // means that if we update a certificate we don't have to worry
    // about invalidating the cache, which is error prone.  This
    // probably costs us a few cycles, but that's a price worth paying
    // for not having to worry about cache invalidation.
    cert_cache: CertCache,
}

pub fn fingerprint_to_keyid(fpr: Fingerprint) -> KeyID {
    let bytes = fpr.as_bytes();
    // XXX: Take the last 8 bytes.  This is wrong for V5 keys where
    // the first 8 bytes correspond to the keyid.
    let bytes = &bytes[cmp::max(8, bytes.len()) - 8..];
    KeyID::from_bytes(bytes)
}

// Generates a convenience method that returns a prepared statement
// for the specified sql.  If preparing the statement results in an
// error, the error is converted to out native error type.
macro_rules! sql_stmt {
    ($name:ident, $sql:expr) => {
        fn $name(conn: &Connection) -> Result<CachedStatement<'_>> {
            let mut name: &str = stringify!($name);
            if name.ends_with("_stmt") {
                name = &name[..name.len() - "_stmt".len()];
            }
            wrap_err!(
                conn.prepare_cached(
                    $sql),
                UnknownDbError,
                format!("preparing {} query", name))
        }
    }
}

impl Keystore {
    // Compares two User IDs.
    //
    // Extracts the email address or URI stored in each User ID and
    // compares them.  A User ID that does not contain an email
    // address or URI is sorted earlier than one that does.
    //
    // This is used as the collation function.
    fn email_cmp(a: &str, b: &str) -> std::cmp::Ordering {
        let a_userid = UserID::from(a);
        let b_userid = UserID::from(b);

        let a_email = a_userid
            .email_normalized()
            .or_else(|_| a_userid.uri())
            .ok();
        let b_email = b_userid
            .email_normalized()
            .or_else(|_| b_userid.uri())
            .ok();

        match (a_email, b_email) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(&b)
        }
    }

    /// Initializes the key store.
    ///
    /// This opens the keys.db and initializes it, if necessary.
    pub fn init<P>(dir: P) -> Result<Self>
        where P: AsRef<Path>
    {
        Self::init_(Some(dir.as_ref()))
    }

    /// Initializes an in-memory key store.
    ///
    /// This is used for the unit tests.
    #[cfg(test)]
    pub(crate) fn init_in_memory() -> Result<Self> {
        Self::init_(None)
    }

    fn init_(home: Option<&Path>) -> Result<Self> {
        let mut keys_db = PathBuf::new();

        let conn = if let Some(home) = home {
            keys_db.push(home);

            #[cfg(not(windows))]
            if cfg!(debug_assertions) {
                if let Ok(pep_home) = env::var("PEP_HOME") {
                    keys_db = PathBuf::from(pep_home);
                }
            }

            for n in KEYS_DB {
                keys_db.push(n);
            }

            wrap_err!(
                Connection::open_with_flags(
                    &keys_db,
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                        | OpenFlags::SQLITE_OPEN_CREATE
                        | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE),
                InitCannotOpenDB,
                format!("Opening keys DB ('{}')", keys_db.display()))?
        } else {
            // Create an in-memory DB.
            wrap_err!(
                Connection::open_in_memory(),
                InitCannotOpenDB,
                "Creating in-memory keys DB")?
        };

        wrap_err!(
            conn.execute_batch("PRAGMA secure_delete=true;
                                PRAGMA foreign_keys=true;
                                PRAGMA locking_mode=NORMAL;
                                PRAGMA journal_mode=WAL;"),
            InitCannotOpenDB,
            format!("Setting pragmas on keys DB ('{}')",
                    keys_db.display()))?;

        wrap_err!(
            conn.busy_timeout(BUSY_WAIT_TIME),
            InitCannotOpenDB,
            format!("Setting busy time ('{}')", keys_db.display()))?;

        wrap_err!(
            conn.create_collation("EMAIL", Self::email_cmp),
            InitCannotOpenDB,
            format!("Registering EMAIL collation function"))?;

        wrap_err!(
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS keys (
                    primary_key TEXT UNIQUE PRIMARY KEY,
                    secret BOOLEAN,
                    tpk BLOB
                 );
                 CREATE INDEX IF NOT EXISTS keys_index
                   ON keys (primary_key, secret)"),
            InitCannotOpenDB,
            format!("Creating keys table ('{}')",
                    keys_db.display()))?;

        wrap_err!(
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS subkeys (
                   subkey TEXT NOT NULL,
                   primary_key TEXT NOT NULL,
                   UNIQUE(subkey, primary_key),
                   FOREIGN KEY (primary_key)
                       REFERENCES keys(primary_key)
                     ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS subkeys_index
                   ON subkeys (subkey, primary_key)"),
            InitCannotOpenDB,
            format!("Creating subkeys table ('{}')",
                    keys_db.display()))?;

        wrap_err!(
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS userids (
                    userid TEXT NOT NULL COLLATE EMAIL,
                    primary_key TEXT NOT NULL,
                    UNIQUE(userid, primary_key),
                    FOREIGN KEY (primary_key)
                        REFERENCES keys(primary_key)
                      ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS userids_index
                   ON userids (userid COLLATE EMAIL, primary_key)"),
            InitCannotOpenDB,
            format!("Creating userids table ('{}')",
                    keys_db.display()))?;

        Ok(Keystore {
            conn,
            cert_cache: LruCache::new(CERT_CACHE_ENTRIES),
        })
    }

    // Returns a prepared statement for finding a certificate by
    // primary key fingerprint.
    sql_stmt!(cert_find_stmt,
              "SELECT tpk, secret FROM keys WHERE primary_key == ?");

    // Returns a prepared statement for finding a key by primary key
    // fingerprint.
    sql_stmt!(tsk_find_stmt,
              "SELECT tpk, secret FROM keys
                 WHERE primary_key == ? and secret == 1");

    // Returns a prepared statement for finding a certificate that
    // contains a key with the specified key id.  That is, this
    // matches on the primary key's key ID as well as any subkeys' key
    // ID.
    sql_stmt!(cert_find_with_key_stmt,
              "SELECT tpk, secret FROM subkeys
                LEFT JOIN keys
                 ON subkeys.primary_key == keys.primary_key
                WHERE subkey == ?");

    // Returns a prepared statement for finding a certificate with
    // secret key material that contains a key (with or without secret
    // key material) with the specified key id.  That is, this matches
    // on the primary key's key ID as well as any subkeys' key ID.
    sql_stmt!(tsk_find_with_key_stmt,
              "SELECT tpk, secret FROM subkeys
                LEFT JOIN keys
                 ON subkeys.primary_key == keys.primary_key
                WHERE subkey == ? and keys.secret == 1");

    // Returns a prepared statement for finding a certificate with the
    // specified email address.
    sql_stmt!(cert_find_by_email_stmt,
              "SELECT tpk, secret FROM userids
                LEFT JOIN keys
                 ON userids.primary_key == keys.primary_key
                WHERE userid == ?");

    // Returns a prepared statement for finding a key with the
    // specified email address.
    sql_stmt!(tsk_find_by_email_stmt,
              "SELECT tpk, secret FROM userids
                LEFT JOIN keys
                 ON userids.primary_key == keys.primary_key
               WHERE userid == ? and keys.secret == 1");

    // Returns a prepared statement for returning all certificates in
    // the database.
    sql_stmt!(cert_all_stmt,
              "select tpk, secret from keys");

    // Returns a prepared statement for returning all certificates in
    // the database, which contain secret key material.
    sql_stmt!(tsk_all_stmt,
              "select tpk, secret from keys where secret = 1");

    // Returns a prepared statement for updating the keys table.
    sql_stmt!(cert_save_insert_primary_stmt,
              "INSERT OR REPLACE INTO keys (primary_key, secret, tpk)
                VALUES (?, ?, ?)");

    // Returns a prepared statement for updating the subkeys table.
    sql_stmt!(cert_save_insert_subkeys_stmt,
              "INSERT OR REPLACE INTO subkeys (subkey, primary_key)
                VALUES (?, ?)");

    // Returns a prepared statement for updating the userids table.
    sql_stmt!(cert_save_insert_userids_stmt,
              "INSERT OR REPLACE INTO userids (userid, primary_key)
                VALUES (?, ?)");

    // Returns a prepared statement for deleting a certificate.
    //
    // Note: due to the use of foreign keys, when a key is removed
    // from the keys table, the subkeys and userids tables are also
    // automatically update.
    sql_stmt!(cert_delete_stmt,
              "DELETE FROM keys WHERE primary_key = ?");

    // The callback used by functions returning a certificate and
    // whether the certificate contains any secret key material.
    fn key_load(row: &Row) -> rusqlite::Result<(Vec<u8>, bool)> {
        let cert = row.get(0)?;
        let secret_key_material = row.get(1)?;
        Ok((cert, secret_key_material))
    }

    // Caches a parsed certificate.
    //
    // This causes the keydata to be associated with the supplied
    // certificate.
    fn cache_cert(cache: &mut CertCache, bytes: &[u8], cert: Cert) {
        tracer!(*crate::TRACE, "Keystore::cache_cert");

        let mut hash = CACHE_HASH.context().expect("hash must be implemented");
        hash.update(bytes);

        let mut digest = Vec::new();
        digest.resize(hash.digest_size(), 0);
        let _ = hash.digest(&mut digest);

        if let Some(cert_in_cache) = cache.peek(&digest) {
            // It's already in the cache.
            assert_eq!(&cert, cert_in_cache);
            return;
        }

        // Purge any stale entries.
        let fpr = cert.fingerprint();
        let purge = cache
            .iter()
            .map(|(digest, cert)| (digest, cert.fingerprint()))
            .filter(|(_digest, other)| &fpr == other)
            .map(|(digest, _)| digest)
            .cloned()
            .collect::<Vec<Vec<u8>>>();
        if purge.len() > 0 {
            t!("Purging {} stale entries that also map to {}",
               purge.len(), fpr);
        }
        for stale_digest in purge {
            cache.pop(&stale_digest);
        }

        // Add the new entry to the cache.
        cache.put(digest, cert);
    }

    // Looks up keydata in the certificate cache.
    //
    // If the keydata is in the certificate cache, returns the
    // certificate.  Otherwise, parses the keydata, adds the
    // certificate to the cache, and returns the certificate.
    fn parse_cert(cache: &mut CertCache, bytes: &[u8]) -> Result<Cert> {
        tracer!(*crate::TRACE, "Keystore::parse_cert");

        let mut hash = CACHE_HASH.context().expect("hash must be implemented");
        hash.update(bytes);

        let mut digest = Vec::new();
        digest.resize(hash.digest_size(), 0);

        let _ = hash.digest(&mut digest);

        let cache_entries = cache.len();

        if let Some(cert) = cache.get(&digest) {
            t!("Looking up {} in cache (w/{} of {} entries) -> hit!",
               cert.fingerprint(),
               cache_entries, CERT_CACHE_ENTRIES);

            Ok(cert.clone())
        } else {
            let cert = wrap_err!(
                Cert::from_bytes(bytes),
                GetKeyFailed,
                format!("Parsing certificate"))?;

            t!("Looking up {} in cache (w/{} of {} entries) -> miss!",
               cert.fingerprint(),
               cache_entries, CERT_CACHE_ENTRIES);

            cache.put(digest, cert.clone());
            Ok(cert)
        }
    }

    fn cert_find_(conn: &Connection, fpr: Fingerprint, private_only: bool,
                  cert_cache: &mut CertCache)
        -> Result<(Cert, bool)>
    {
        tracer!(*crate::TRACE, "Keystore::cert_find_");

        let r = wrap_err!(
            if private_only {
                Self::tsk_find_stmt(conn)?
                    .query_row(&[ &fpr.to_hex() ], Self::key_load)
            } else {
                Self::cert_find_stmt(conn)?
                    .query_row(&[ &fpr.to_hex() ], Self::key_load)
            }.optional(),
            UnknownDbError,
            "executing query")?;

        if let Some((keydata, secret_key_material)) = r {
            t!("Got {} bytes of certificate data", keydata.len());
            let cert = Self::parse_cert(cert_cache, &keydata)?;
            Ok((cert, secret_key_material))
        } else {
            Err(Error::KeyNotFound(fpr.into()))
        }
    }

    /// Looks up the specified certificate by fingerprint.
    ///
    /// This only considers the certificate's fingerprint (i.e., the
    /// primary key's fingerprint), not any subkeys.
    ///
    /// If `private_only` is true, then only certificates are returned
    /// that include some secret key material.
    pub fn cert_find(&mut self, fpr: Fingerprint, private_only: bool)
        -> Result<(Cert, bool)>
    {
        Self::cert_find_(&self.conn, fpr, private_only, &mut self.cert_cache)
    }

    /// Returns the certificate that includes a key identified by the
    /// keyid.
    ///
    /// This function matches on both primary keys and subkeys!  There
    /// can be multiple certificates for a given keyid.  This can
    /// occur if a key is bound to multiple certificates.  Also, it is
    /// possible to collide key ids.  If there are multiple keys for a
    /// given key id, this just returns one of them.
    ///
    /// XXX: It would be better to return all of them and have the
    /// caller try each in turn.
    pub fn cert_find_with_key<H>(&mut self, kh: H, private_only: bool)
        -> Result<(Cert, bool)>
        where H: Into<KeyHandle>
    {
        let kh = kh.into();
        let keyid = match kh.clone() {
            KeyHandle::KeyID(keyid) => keyid,
            KeyHandle::Fingerprint(fpr) => fingerprint_to_keyid(fpr),
        };

        let mut stmt = if private_only {
            Self::tsk_find_with_key_stmt(&self.conn)?
        } else {
            Self::cert_find_with_key_stmt(&self.conn)?
        };

        let row = wrap_err!(
            stmt.query_row(&[ &keyid.to_hex() ], Self::key_load).optional(),
            UnknownDbError,
            "executing query")?;

        if let Some((keydata, secret_key_material)) = row {
            let cert = Self::parse_cert(&mut self.cert_cache, &keydata)?;
            Ok((cert, secret_key_material))
        } else {
            Err(Error::KeyNotFound(kh))
        }
    }

    /// Returns all the certificates.
    ///
    /// If private_only is set, then only keys with private key
    /// material are returned.
    pub fn cert_all(&mut self, private_only: bool)
        -> Result<Vec<(Cert, bool)>>
    {
        let mut results: Vec<(Cert, bool)> = Vec::new();

        let mut stmt = if private_only {
            Self::tsk_all_stmt(&self.conn)?
        } else {
            Self::cert_all_stmt(&self.conn)?
        };

        let rows = wrap_err!(
            stmt.query_map([], Self::key_load),
            UnknownDbError,
            "executing query")?;

        for row in rows {
            let (keydata, private) = wrap_err!(
                row,
                UnknownError,
                "parsing result")?;
            let cert = Self::parse_cert(&mut self.cert_cache, &keydata)?;
            results.push((cert, private));
        };

        Ok(results)
    }

    /// Returns certificates that include a User ID matching the
    /// pattern.
    ///
    /// If private_only is set, then only keys with private key
    /// material are returned.
    pub fn cert_find_by_email(&mut self, pattern: &str, private_only: bool)
        -> Result<Vec<(Cert, bool)>>
    {
        let mut results: Vec<(Cert, bool)> = Vec::new();

        let mut stmt = if private_only {
            Self::tsk_find_by_email_stmt(&self.conn)?
        } else {
            Self::cert_find_by_email_stmt(&self.conn)?
        };

        let rows = wrap_err!(
            stmt.query_map(&[ pattern ], Self::key_load),
            UnknownDbError,
            "executing query")?;

        for row in rows {
            let (keydata, private) = wrap_err!(
                row,
                UnknownError,
                "parsing result")?;
            let cert = Self::parse_cert(&mut self.cert_cache, &keydata)?;
            results.push((cert, private));
        };

        Ok(results)
    }

    /// Saves the certificate to the database.
    ///
    /// If the certificate is already present, it is merged with the
    /// saved copy.
    ///
    /// If the certificate includes private key material, returns a
    /// PepIdentity.  This also returns whether the certificate is
    /// changed relative to the copy on disk.  (If there was no copy,
    /// then this returns true.)
    ///
    /// Whether the certificate has changed is a heuristic.  It may
    /// indicate that the certificate has changed when it hasn't
    /// (false positive), but it will never say that the certificate
    /// has not changed when it has (false negative).
    pub fn cert_save(&mut self, mut cert: Cert)
        -> Result<(Option<PepIdentityTemplate>, bool)>
    {
       // cert.set_expiration_time(policy, t, primary_signer, expiration);
        tracer!(*crate::TRACE, "Keystore::cert_save");

        let fpr = cert.fingerprint();
        t!("Saving {}", fpr);

        let tx = wrap_err!(
            self.conn.transaction(),
            UnknownDbError,
            "starting transaction"
        )?;

        // Merge any existing data into the existing certificate.
        let current = match Self::cert_find_(&tx, fpr.clone(), false,
                                             &mut self.cert_cache)
        {
            Ok((current, _)) => Some(current),
            Err(Error::KeyNotFound(_)) => None,
            Err(err) => return Err(err),
        };

        let changed = if let Some(ref current) = current {
            // We want to compare current and cert.  Eq only considers
            // the data that is serialized.  For a Cert, any secret
            // key material is not serialized so it is not considered,
            // but we want to consider secret key material.  So, we
            // need to be a bit smarter.
            //
            // XXX: Starting in Sequoia 1.4 we will be able to do:
            // cert.as_tsk() == other.as_tsk().
            match (current.is_tsk(), cert.is_tsk()) {
                (true, true) =>
                    current.clone().into_packets().collect::<Vec<_>>()
                      != cert.clone().into_packets().collect::<Vec<_>>(),
                (true, false) => true,
                (false, true) => true,
                (false, false) => current != &cert,
            }
        } else {
            // If we go from nothing to something, consider it a
            // change.
            true
        };
        t!("changed: {}", changed);

        if changed {
            if let Some(current) = current {
                cert = wrap_err!(
                    cert.merge_public_and_secret(current),
                    UnknownDbError,
                    "Merging certificate with existing certificate")?;
            }
        } else {
            // If we have private key material, then we need to return
            // a pep identity.  Otherwise, we can shortcircuit.
            if ! cert.is_tsk() {
                return Ok((None, changed));
            }
        }

        let mut keydata = Vec::new();
        wrap_err!(
            cert.as_tsk().serialize(&mut keydata),
            UnknownDbError,
            "Serializing certificate")?;
        t!("Serializing {} bytes ({:X})",
           keydata.len(),
           {
               use std::collections::hash_map::DefaultHasher;
               use std::hash::Hasher;

               let mut hasher = DefaultHasher::new();

               hasher.write(&keydata);
               hasher.finish()
           });

        // Save the certificate.
        if changed {
            let mut stmt = Self::cert_save_insert_primary_stmt(&tx)?;
            wrap_err!(
                stmt.execute(params![fpr.to_hex(), cert.is_tsk(), &keydata]),
                UnknownDbError,
                "Executing cert save insert primary")?;
        }

        let mut ident = None;

        if let Ok(vc) = cert.with_policy(crate::P, None) {
            // Update the subkey table.
            if changed {
                let mut stmt = Self::cert_save_insert_subkeys_stmt(&tx)?;
                for (i, ka) in vc.keys().enumerate() {
                    t!("  {}key: {} ({} secret key material)",
                       if i == 0 { "primary " } else { "sub" },
                       ka.keyid(),
                       if ka.has_secret() { "has" } else { "no" });
                    wrap_err!(
                        stmt.execute(
                            params![ka.keyid().to_hex(), fpr.to_hex()]),
                        UnknownDbError,
                        "Executing cert save insert subkeys")?;
                }
            }

            // Update the userid table.
            {
                let mut stmt = Self::cert_save_insert_userids_stmt(&tx)?;

                for ua in vc.userids() {
                    let uid = if let Ok(Some(email)) = ua.email_normalized() {
                        email
                    } else if let Ok(Some(uri)) = ua.uri() {
                        uri
                    } else {
                        continue;
                    };
                    t!("  User ID: {}", uid);

                    if changed {
                        wrap_err!(
                            stmt.execute(params![uid, fpr.to_hex()]),
                            UnknownDbError,
                            "Executing cert save insert userids")?;
                    }

                    if ident.is_none() && vc.is_tsk() {
                        ident = Some(PepIdentityTemplate::new(
                            &uid, fpr.clone(), ua.name().unwrap_or(None)));
                    }
                }
            }
        }

        wrap_err!(
            tx.commit(),
            UnknownDbError,
            "committing transaction"
        )?;

        // Cache the updated certificate.  It will likely be used in
        // the near future.
        Self::cache_cert(&mut self.cert_cache, &keydata, cert);

        t!("saved");

        Ok((ident, changed))
    }

    /// Deletes the specified certificate from the database.
    pub fn cert_delete(&mut self, fpr: Fingerprint) -> Result<()> {
        let changes = wrap_err!(
            Self::cert_delete_stmt(&self.conn)?
                .execute(params![ fpr.to_hex() ]),
            CannotDeleteKey,
            format!("Deleting {}", fpr))?;

        if changes == 0 {
            Err(Error::KeyNotFound(fpr.into()))
        } else {
            Ok(())
        }
    }

    /// list keys whose uids contain the input pattern or whose
    /// fingerprints match a fingerprint contained in the pattern
    ///
    /// Returns the revocation status and primary user id (if the
    /// certificate is not revoked and there is one).  If a
    /// certificate is not valid according to the policy, it is still
    /// returned, and it is marked as revoked.
    pub fn list_keys(&mut self, pattern: &str, private_only: bool)
        -> Result<Vec<(Fingerprint, Option<UserID>, bool)>>
    {
        tracer!(*crate::TRACE, "Keystore::list_keys");
        t!("pattern: {}, private only: {}", pattern, private_only);

        let mut certs: Vec<(Fingerprint, Option<UserID>, bool)> = Vec::new();
        let mut add_key = |cert: &Cert| {
            match cert.with_policy(crate::P, None) {
                Ok(vc) => {
                    let revoked = matches!(vc.revocation_status(),
                                           RevocationStatus::Revoked(_));

                    let userid = if revoked {
                        vc
                            .primary_userid()
                            .map(|userid| userid.userid().clone())
                            .ok()
                    } else {
                        None
                    };

                    certs.push((cert.fingerprint(), userid, revoked));
                }
                Err(err) => {
                    t!("warning: certificate {}: \
                        rejected by policy: {}",
                       cert.fingerprint(), err);
                    certs.push((cert.fingerprint(), None, true));
                }
            }
        };

        // Trim any leading space.  This also makes it easier to recognize
        // a string that is only whitespace.
        let pattern = pattern.trim_start();

        if pattern.chars().any(|c| c == '@' || c == ':') {
            // Looks like a mailbox or URI.
            self.cert_find_by_email(pattern, private_only)?
                .into_iter()
                .for_each(|(cert, _private)| add_key(&cert));

            if certs.len() == 0 {
                // If match failed, check to see if we've got a dotted
                // address in the pattern.  If so, try again without
                // dots.
                match (pattern.find("."), pattern.find("@")) {
                    (Some(dotpos), Some(atpos)) if dotpos < atpos =>
                    {
                        t!("Retrying list_keys with undotted pattern");

                        // Return a string which, if the input string
                        // is in the form of a user.name@address email
                        // string, contains copy of the email address
                        // string with the username undotted, and
                        // otherwise, contains a copy of the whole
                        // string, undotted.
                        let left = &pattern[..atpos];
                        let right = &pattern[atpos..];

                        let mut pattern = String::from(left).replace(".", "");
                        pattern.push_str(right);

                        return self.list_keys(&pattern, private_only);
                    }
                    _ => (),
                }
            }
        } else if pattern.len() >= 16
            && pattern.chars()
                .all(|c| {
                    match c {
                          '0' | '1' | '2' | '3' | '4'
                        | '5' | '6' | '7' | '8' | '9'
                        | 'a' | 'b' | 'c' | 'd' | 'e' | 'f'
                        | 'A' | 'B' | 'C' | 'D' | 'E' | 'F'
                        | ' ' => {
                            true
                        }
                        _ => false,
                    }
                })
        {
            // Only hex characters and spaces and a fair amount of
            // them.  This is probably a fingerprint.  Note: the pep
            // engine never looks keys up by keyid, so we don't handle
            // them.
            let fpr = Fingerprint::from_hex(pattern).expect("valid fingerprint");
            let (cert, _private) = self.cert_find_with_key(fpr, private_only)?;
            add_key(&cert);
        } else if pattern.len() == 0 {
            // Empty string.  Return everything.
            self.cert_all(private_only)?
                .into_iter()
                .for_each(|(cert, _private)| add_key(&cert));
        } else {
            // Do not throw an error; return the empty set (i.e.,
            // pattern matches nothing).
            t!("unsupported pattern '{}'", pattern);
        }

        t!("{} matches", certs.len());
        Ok(certs)
    }
}

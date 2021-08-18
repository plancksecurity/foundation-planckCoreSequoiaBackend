// Maximum busy wait time.
pub const BUSY_WAIT_TIME: std::time::Duration = std::time::Duration::from_secs(5);

// The location of the keys DB relative to the user's home directory.
pub const KEYS_DB: &[ &str ] = &[ ".pEp", "keys.db" ];


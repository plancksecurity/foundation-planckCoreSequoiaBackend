#[allow(unused_macros)]
macro_rules! log {
    // log!(target: "my_target", Level::Info, key1 = 42, key2 = true; "a {} event", "log");
    (target: $target:expr, $lvl:expr, $($key:tt = $value:expr),+; $($arg:tt)+) => ({
        if cfg!(debug_assertions) {
            ::log::log!(target: $target, lvl: $lvl, $($key = $value),+; $($arg)+)
        }
    });

    // log!(target: "my_target", Level::Info, "a {} event", "log");
    (target: $target:expr, $lvl:expr, $($arg:tt)+) => ({
        if cfg!(debug_assertions) {
            ::log::log!(target: $target, lvl: $lvl, $($arg)+)
        }
    });

    // log!(Level::Info, "a log event")
    ($lvl:expr, $($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::log!($lvl, $($arg)+)
        }
    );
}

#[allow(unused_macros)]
macro_rules! error {
    // error!(target: "my_target", key1 = 42, key2 = true; "a {} event", "log")
    // error!(target: "my_target", "a {} event", "log")
    (target: $target:expr, $($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::error!(target: $target, $($arg)+)
        }
    );

    // error!("a {} event", "log")
    ($($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::error!($($arg)+)
        }
    )
}

#[allow(unused_macros)]
macro_rules! warn {
    // warn!(target: "my_target", key1 = 42, key2 = true; "a {} event", "log")
    // warn!(target: "my_target", "a {} event", "log")
    (target: $target:expr, $($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::warn!(target: $target, $($arg)+)
        }
    );

    // warn!("a {} event", "log")
    ($($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::warn!($($arg)+)
        }
    )
}

#[allow(unused_macros)]
macro_rules! info {
    // info!(target: "my_target", key1 = 42, key2 = true; "a {} event", "log")
    // info!(target: "my_target", "a {} event", "log")
    (target: $target:expr, $($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::info!(target: $target, $($arg)+)
        }
    );

    // info!("a {} event", "log")
    ($($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::info!($($arg)+)
        }
    )
}

#[allow(unused_macros)]
macro_rules! debug {
    // debug!(target: "my_target", key1 = 42, key2 = true; "a {} event", "log")
    // debug!(target: "my_target", "a {} event", "log")
    (target: $target:expr, $($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::debug!(target: $($arg)+)
        }
    );

    // debug!("a {} event", "log")
    ($($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::debug!($($arg)+)
        }
    )
}

#[allow(unused_macros)]
macro_rules! trace {
    // trace!(target: "my_target", key1 = 42, key2 = true; "a {} event", "log")
    // trace!(target: "my_target", "a {} event", "log")
    (target: $target:expr, $($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::trace!(target: $target, $($arg)+)
        }
    );

    // trace!("a {} event", "log")
    ($($arg:tt)+) => (
        if cfg!(debug_assertions) {
            ::log::trace!($($arg)+)
        }
    )
}

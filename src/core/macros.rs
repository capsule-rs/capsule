#![macro_use]

/// Exits a function early with an `Error` if the condition is not satisfied.
///
/// # Example
///
/// ```
/// ensure!(vec.len() > 0, EmptyVecError::new());
/// ```
///
/// is equivalent to
///
/// ```
/// if !(vec.len() > 0) {
///     return Err(EmptyVecError::new().into());
/// }
/// ```
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err($e.into());
        }
    };
}

macro_rules! error {
    (cond: $cond:expr, $($arg:tt)+) => (
        if $cond {
            error!($($arg)+);
        }
    );
    ($($arg:tt)+) => (
        ::log::error!($($arg)+);
    )
}

macro_rules! warn {
    (cond: $cond:expr, $($arg:tt)+) => (
        if $cond {
            warn!($($arg)+);
        }
    );
    ($($arg:tt)+) => (
        ::log::warn!($($arg)+);
    )
}

macro_rules! info {
    (cond: $cond:expr, $($arg:tt)+) => (
        if $cond {
            info!($($arg)+);
        }
    );
    ($($arg:tt)+) => (
        ::log::info!($($arg)+);
    )
}

macro_rules! debug {
    (cond: $cond:expr, $($arg:tt)+) => (
        if $cond {
            debug!($($arg)+);
        }
    );
    ($($arg:tt)+) => (
        ::log::debug!($($arg)+);
    )
}

macro_rules! trace {
    (cond: $cond:expr, $($arg:tt)+) => (
        if $cond {
            trace!($($arg)+);
        }
    );
    ($($arg:tt)+) => (
        ::log::trace!($($arg)+);
    )
}

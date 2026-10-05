//! Runtime adapter layer.
//!
//! Adapters own the real socket and the real clock. They translate the core's
//! universe-level state changes into actual I/O - resolving interfaces,
//! deriving multicast groups, and performing joins/leaves and sends - and
//! expose an ergonomic async API.
//!
//! The [`tokio`] driver is the first such adapter; the module also holds the
//! shared networking helpers and the adapter error type. The [`embassy`] driver
//! is the second, a no_std adapter for the embassy async runtime.

// The shared helpers, the adapter error type and the tokio driver are all
// `std` (`HashMap`/`io::Result`/socket2) throughout, so they stay `std`-gated.
// The embassy driver is a separate no_std adapter that shares none of them.
#[cfg(feature = "std")]
mod error;
#[cfg(feature = "std")]
mod net;
#[cfg(feature = "tokio")]
mod sending;

#[cfg(feature = "std")]
pub use error::AdapterError;
#[cfg(feature = "std")]
pub use net::{MulticastInterface, ToMulticastInterfaces};

#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "embassy")]
pub mod embassy;

/// The key, if any, a receiver adapter opens secured packets with. A unit
/// placeholder when the `secure` feature is off, so adapters have one code path.
#[cfg(feature = "secure")]
pub(crate) type RxSecurity = Option<crate::secure::SecurityKey>;
#[cfg(not(feature = "secure"))]
pub(crate) type RxSecurity = ();

/// Prepares a received datagram in `buf[..len]` for parsing, returning the
/// length of the standard packet to parse or `None` to drop it. With a key set,
/// only packets that open with that key are kept (opened in place); otherwise
/// the datagram passes through untouched.
#[cfg_attr(not(feature = "secure"), allow(clippy::unnecessary_wraps))]
pub(crate) fn unseal(security: &RxSecurity, buf: &mut [u8], len: usize) -> Option<usize> {
    #[cfg(feature = "secure")]
    if let Some(key) = security {
        return crate::secure::open(key, buf, len);
    }
    let _ = (security, buf);
    Some(len)
}

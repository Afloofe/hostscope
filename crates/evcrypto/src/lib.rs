#![forbid(unsafe_code)]

use core::fmt;

pub mod composed;
pub mod manifest;
pub mod x509;
pub mod policy;
pub mod receipt;
pub mod secret;
pub mod ticket;

pub mod seal;

pub mod envelope;

#[cfg(feature = "hpke-vendor")]
pub mod vendor;

#[cfg(not(any(feature = "hpke-vendor", feature = "hpke-composed")))]
compile_error!(
    "no HPKE feature selected: enable `hpke-composed` (default) or `hpke-vendor`. \
     The evidence path seals with `composed` either way; `hpke-vendor` adds the oracle."
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {

    InvalidPeerKey,

    AuthenticationFailed,

    Internal(&'static str),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidPeerKey => {
                f.write_str("invalid or small-order key")
            }
            CryptoError::AuthenticationFailed => f.write_str(
                "authentication failed: the ciphertext, its bound header, or the key is not what was sealed",
            ),
            CryptoError::Internal(what) => write!(f, "internal cryptographic error: {what}"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = core::result::Result<T, CryptoError>;

pub const ACTIVE_HPKE: &str = "composed(x25519-dalek+hkdf+aes-gcm)";

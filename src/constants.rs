//! Common constants such as buffer sizes for keys and signatures.

/// The length of a ed25519 `Signature`, in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// The length of a ed25519ph `PrivateKey`, in bytes.
pub const PRIVATE_KEY_LENGTH: usize = 32;

/// The length of an ed25519ph `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The max of the ed25519ph context, in bytes.
pub const CONTEXT_MAX_LENGTH: usize = 255;

/// Signifies an issue with the signature or public key.
pub const SIGNATURE_ERROR : i32 = 101;

/// The provided context exceeds the maximum allowed length.
pub const CONTEXT_LENGTH_ERROR: i32 = 201;

/// An unknown error.
pub const UNKNOWN_ERROR : i32 = -1;
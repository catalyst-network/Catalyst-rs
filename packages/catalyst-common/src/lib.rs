#![recursion_limit = "1024"]

extern crate catalyst_protocol_sdk_rust;
extern crate ed25519_dalek;

pub use catalyst_protocol_sdk_rust::prelude::*;
pub use catalyst_protocol_sdk_rust::Cryptography::ErrorCode;
pub(crate) use ed25519_dalek::{Keypair, PublicKey, SecretKey};

pub mod constants;
pub mod std_signature;
pub mod keys;

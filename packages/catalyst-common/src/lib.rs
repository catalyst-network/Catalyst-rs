#![recursion_limit = "1024"]

extern crate catalyst_protocol_sdk_rust;
extern crate ed25519_dalek;
extern crate rand;

pub use catalyst_protocol_sdk_rust::prelude::*;
pub use catalyst_protocol_sdk_rust::Cryptography::{ErrorCode, SignatureBatch};
pub(crate) use ed25519_dalek::{Keypair, PublicKey, SecretKey};

pub mod batch;
pub mod constants;
pub mod extensions;
pub mod keys;
pub mod std_signature;

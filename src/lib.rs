#![recursion_limit = "1024"]

extern crate catalyst_protocol_sdk_rust;
extern crate ed25519_dalek;
extern crate libc;
extern crate rand;

pub use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Sha512};
pub(crate) use catalyst_protocol_sdk_rust::prelude::*;
pub use curve25519_dalek::digest::Digest; //remember to remove this

pub mod constants;
pub mod ffi;
pub mod keys;
pub mod std_signature;
mod batch;
mod extensions;

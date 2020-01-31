#![recursion_limit = "1024"]

extern crate catalyst_protocol_sdk_rust;
extern crate ed25519_dalek;
extern crate libc;
extern crate rand;

pub use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};

pub mod constants;
pub mod ffi;
pub mod keys;
pub mod std_signature;

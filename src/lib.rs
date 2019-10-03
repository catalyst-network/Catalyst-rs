#![recursion_limit = "1024"]
#![feature(test)]

extern crate ed25519_dalek;
extern crate rand;
extern crate libc;
#[macro_use] extern crate failure;
#[macro_use] extern crate log;

pub use ed25519_dalek::{SecretKey, PublicKey, Signature, Keypair};

pub mod std_signature;
pub mod constants;
pub mod ffi;
pub mod keys;
mod errors;
mod helpers;

#![recursion_limit = "1024"]
// Copyright (c) 2019 Catalyst Network
//
// This file is part of Rust.Cryptography.FFI <https://github.com/catalyst-network/catalyst-ffi>
//
// Rust.Cryptography.FFI is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.
//
// Rust.Cryptography.FFI is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Rust.Cryptography.FFI. If not, see <https://www.gnu.org/licenses/>.

extern crate ed25519_dalek;
extern crate rand;
extern crate libc;
#[macro_use] extern crate failure;
#[macro_use] extern crate log;

pub use ed25519_dalek::{SecretKey, PublicKey, Signature, Keypair};

pub mod std_signature;
pub mod constants;
mod bulletproofs;
mod ffi;
mod errors;
mod keys;
mod helpers;
mod extensions;

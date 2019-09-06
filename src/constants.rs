#![feature(const_fn)]
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

//! Common constants such as buffer sizes for keys and signatures.

/// The length of a ed25519 `Signature`, in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// The length of a ed25519 `PrivateKey`, in bytes.
pub const PRIVATE_KEY_LENGTH: usize = 32;

/// The length of an ed25519 `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

pub const CONTEXT_MAX_LENGTH: usize = 255;

pub const BULLETPROOF_N: usize = 64;

//see if we can state this in terms of BULLETPROOF_N
pub const BULLETPROOF_SIZE: usize = 672;

pub const BULLETPROOF_BLINDING_LENGTH: usize = 32;

//const fn bulletproof_size_from_n(n: usize) -> i32 {
    //(9_f64+2_f64*((n as f64).log2())*32_f64) as i32
//}

//pub const BULLETPROOF_SIZE_EXPERIMENTAL: i32 = bulletproof_size_from_n(BULLETPROOF_N);


pub const SIGNATURE_ERROR : i32 = 101;

pub const CONTEXT_LENGTH_ERROR: i32 = 201;

pub const UNKNOWN_ERROR : i32 = -1;
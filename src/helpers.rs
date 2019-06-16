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

//! Provides helper functions.
use std::result;
use crate::std_signature;
use crate::keys;
use crate::constants;

type Result<T> = result::Result<T, failure::Error>;

pub fn get_signature_result_with_error() -> Result<bool> {
    let mut invalid_signature : [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
    invalid_signature[63] = 32;
    let mut private_key : [u8;32] = [0;32];
    let mut public_key : [u8;32] = [0;32];
    keys::generate_key(&mut private_key);
    keys::publickey_from_private(&mut public_key, &mut private_key);
    let message = String::from("Message text");
    std_signature::verify(&invalid_signature, &public_key, message.as_ptr(), message.len())
}
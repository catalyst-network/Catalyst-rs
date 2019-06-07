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

//! The foreign function interface which exposes this library to non-Rust 
//! languages.

use std::ptr;
use std::slice;
use libc::{c_char, c_int};
use crate::errors;
use crate::keys;
use crate::std_signature;
use crate::constants;

/// Calculate the number of bytes in the last error's error message **not**
/// including any trailing `null` characters.
#[no_mangle]
pub extern "C" fn last_error_length() -> c_int {
    errors::LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(ref err) => err.to_string().len() as c_int + 1,
        None => 0,
    })
}

/// Write the most recent error message into a caller-provided buffer as a UTF-8
/// string, returning the number of bytes written.
///
/// # Note
///
/// This writes a **UTF-8** string into the buffer. Windows users may need to
/// convert it to a UTF-16 "unicode" afterwards.
///
/// If there are no recent errors then this returns `0` (because we wrote 0
/// bytes). `-1` is returned if there are any errors, for example when passed a
/// null pointer or a buffer of insufficient size.
#[no_mangle]
pub unsafe extern "C" fn last_error_message(buffer: *mut c_char, length: c_int) -> c_int {
    if buffer.is_null() {
        warn!("Null pointer passed into last_error_message() as the buffer");
        return -1;
    }

    let last_error = match errors::take_last_error() {
        Some(err) => err,
        None => return 0,
    };

    let error_message = last_error.to_string();
    println!("{}", error_message);

    let buffer = slice::from_raw_parts_mut(buffer as *mut u8, length as usize);

    if error_message.len() >= buffer.len() {
        warn!("Buffer provided for writing the last error message is too small.");
        warn!(
            "Expected at least {} bytes but got {}",
            error_message.len() + 1,
            buffer.len()
        );
        return -1;
    }

    ptr::copy_nonoverlapping(
        error_message.as_ptr(),
        buffer.as_mut_ptr(),
        error_message.len(),
    );

    error_message.len() as c_int
}

/// Verifies that an ed25519 signature corresponds to the provided public key and message. Returns 0 if sucessful, otherwise returns an error code.
#[no_mangle]
pub extern "C" fn std_verify(signature: & [u8;constants::SIGNATURE_LENGTH], publickey: &[u8;constants::PUBLIC_KEY_LENGTH], message: *const u8, message_length: usize) -> c_int {
   let _res = match std_signature::verify(signature, publickey, message, message_length){
        Err(err) => {
            let error_code = errors::get_error_code(&err);
            errors::update_last_error(err);
            return error_code;
        }
        Ok(()) => {return 0;}
    };
}

/// Creates a signature from private key and message. Returns 0 if sucessful, otherwise returns an error code.
#[no_mangle]
pub extern "C" fn std_sign(out_signature: &mut [u8;constants::SIGNATURE_LENGTH], private_key: &[u8;constants::PRIVATE_KEY_LENGTH], message: *const u8, message_length: usize) -> c_int {
   let _res = match std_signature::sign(out_signature, private_key, message, message_length){
        Err(err) => {
            let error_code = errors::get_error_code(&err);
            errors::update_last_error(err);
            return error_code;
        }
        Ok(()) => {return 0;}
    };
}

/// Returns correponding public key, given a private key. Returns 0 if sucessful, otherwise returns an error code.
#[no_mangle]
pub extern "C" fn publickey_from_private(out_publickey: &mut [u8;constants::PUBLIC_KEY_LENGTH],private_key: &[u8;constants::PRIVATE_KEY_LENGTH]) -> c_int {
    let _res = match keys::publickey_from_private(out_publickey, private_key){
        Err(err) => {
            let error_code = errors::get_error_code(&err);
            errors::update_last_error(err);
            return error_code;
        }
        Ok(()) => {return 0;}
    };
}

/// Randomly generated private key. Returns 0 if sucessful, otherwise returns an error code.
#[no_mangle]
pub extern "C" fn generate_key(out_key: &mut [u8;constants::PRIVATE_KEY_LENGTH]) -> c_int {
    let _res = match keys::generate_key(out_key){
        Err(err) => {
            let error_code = errors::get_error_code(&err);
            errors::update_last_error(err);
            return error_code;
        }
        Ok(()) => {return 0;}
    };
}


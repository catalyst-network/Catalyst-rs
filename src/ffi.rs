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
    errors::last_error_length()
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

/// Verifies that an ed25519 signature corresponds to the provided public key, message, and context. Returns 0 if no error encountered, otherwise returns an error code. Sets value of is_verified based of verification outcome.
#[no_mangle]
pub extern "C" fn std_verify(signature: & [u8;constants::SIGNATURE_LENGTH], 
                             publickey: &[u8;constants::PUBLIC_KEY_LENGTH], 
                             message: *const u8, 
                             message_length: usize,
                             context: *const u8, 
                             context_length: usize,  
                             is_verified: &mut [u8;1]) -> c_int {
    let result = std_signature::unwrap_and_verify(signature, publickey, message, message_length, context, context_length);
    result
        .map(|b: bool| {is_verified[0] = b as u8; ()})
        .ffi_return_code()
}

/// Creates a signature from private key and message. Returns 0 if no error encountered, otherwise returns an error code.
#[no_mangle]
pub extern "C" fn std_sign(out_signature: &mut [u8;constants::SIGNATURE_LENGTH], 
                           private_key: &[u8;constants::PRIVATE_KEY_LENGTH], 
                           message: *const u8, 
                           message_length: usize,
                           context: *const u8, 
                           context_length: usize) -> c_int {
    let result = std_signature::unwrap_and_sign(out_signature, private_key, message, message_length, context, context_length);
    result.ffi_return_code()
}

/// Returns correponding public key, given a private key. Returns 0 if sucessful, otherwise returns an error code.
#[no_mangle]
pub extern "C" fn publickey_from_private(out_publickey: &mut [u8;constants::PUBLIC_KEY_LENGTH],private_key: &[u8;constants::PRIVATE_KEY_LENGTH]) -> c_int {
    let result = keys::publickey_from_private(out_publickey, private_key);
    result.ffi_return_code()
}

/// Randomly generated private key. Returns 0 if sucessful, otherwise returns an error code.
#[no_mangle]
pub extern "C" fn generate_key(out_key: &mut [u8;constants::PRIVATE_KEY_LENGTH]) -> c_int {
    keys::generate_key(out_key).ffi_return_code()
}

/// Checks that the bytes provided represent a valid public key. Returns 0 if successful, otherwise returns error code.
#[no_mangle]
pub extern "C" fn validate_public_key(public_key: &[u8;constants::PUBLIC_KEY_LENGTH]) -> c_int{
    keys::validate_public(&public_key).ffi_return_code()
}

///Returns private key length in bytes
#[no_mangle]
pub extern "C" fn get_private_key_length() -> c_int{
    constants::PRIVATE_KEY_LENGTH as i32
}

///Returns public key length in bytes
#[no_mangle]
pub extern "C" fn get_public_key_length() -> c_int{
    constants::PUBLIC_KEY_LENGTH as i32
}

///Returns signature length in bytes
#[no_mangle]
pub extern "C" fn get_signature_length() -> c_int{
    constants::SIGNATURE_LENGTH as i32
}

///Returns max context length in bytes
#[no_mangle]
pub extern "C" fn get_max_context_length() -> c_int{
    constants::CONTEXT_MAX_LENGTH as i32
}

#[doc(hidden)]
pub trait ResultEx{
    fn ffi_return_code(self) -> c_int;
}

#[doc(hidden)]
impl ResultEx for Result<(),failure::Error> {
    fn ffi_return_code(self) -> c_int{
        match self{
            Err(err) => {
                let error_code = errors::get_error_code(&err);
                errors::update_last_error(err);
                return error_code;
            }
            Ok(_t) => {
                return 0
            }
        }; 
    } 
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::tests;
    
    #[test]
    fn can_throw_context_length_error(){
        
        let initial_sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];
        let mut out_sig: [u8;constants::SIGNATURE_LENGTH] = Clone::clone(&initial_sig);
        
        let context : Vec<u8> = (0..256).map(|_| { rand::random::<u8>() }).collect();
        println!("********* context length is: {}", context.len());

        let mut key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        assert!(keys::generate_key(&mut key).is_ok());
        let message = String::from("You are a sacrifice article that I cut up rough now");
        let error_code = std_sign(&mut out_sig, &key, message.as_ptr(), message.len(), context.as_ptr(), context.len());
        assert_eq!(error_code, constants::CONTEXT_LENGTH_ERROR);
    }

    #[test]
    fn can_throw_signature_error(){
        let bad_result = tests::get_signature_result_with_error();
        let err = bad_result.unwrap_err();
        let error_code = errors::get_error_code(&err);
        assert_eq!(error_code, constants::SIGNATURE_ERROR)
    }
}

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

//! functionality for querying the most recent error and retrieving error codes based on an error type.

use std::cell::RefCell;
use crate::constants;
use std::fmt;
use failure::Fail;
use log::{warn, error};


#[derive(Fail, Debug)]
pub struct ContextLengthError;

impl fmt::Display for ContextLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "The context length should be less than {} bytes.", constants::CONTEXT_MAX_LENGTH)
    }
}

thread_local!{
    pub static LAST_ERROR: RefCell<Option<Box<failure::Error>>> = RefCell::new(None);
}

/// Store the most recent error.
pub fn update_last_error(err: failure::Error) {

    error!("Setting LAST_ERROR: {}", err);
    {
        // Print a pseudo-backtrace for this error, following back each error's
        // cause until we reach the root error.
        let mut prev = err.as_fail();
        while let Some(next) = prev.cause() {
            warn!("Caused by: {}", &next.to_string());
            prev = next;
        }
    }
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(Box::new(err));
    });
}

/// Retrieve the most recent error, clearing it in the process.
pub(crate) fn take_last_error() -> Option<Box<failure::Error>> {
    LAST_ERROR.with(|prev| prev.borrow_mut().take())
}

/// Retrieve error code corresponding to error type.
pub(crate) fn get_error_code(err : &failure::Error ) -> i32 {
    println!("{}", err.as_fail());
    if let Some(_) = err.downcast_ref::<ed25519_dalek::SignatureError>() {
        return constants::SIGNATURE_ERROR;
    }
    if let Some(_) = err.downcast_ref::<ContextLengthError>() {
        return constants::CONTEXT_LENGTH_ERROR;
    }
    else {return constants::UNKNOWN_ERROR;}
}

/// Retrieve length of most recent error string.
pub(crate) fn last_error_length() -> i32 {
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(ref err) => err.to_string().len() as i32 + 1,
        None => 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::tests;

    #[test]
    fn can_update_latest_error(){
        let error_length = last_error_length();
        let bad_result = tests::get_signature_result_with_error();
        let err = bad_result.unwrap_err();
        update_last_error(err);
        assert_ne!(error_length, last_error_length())
    }
}

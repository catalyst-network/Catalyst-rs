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

thread_local!{
    pub static LAST_ERROR: RefCell<Option<Box<failure::Error>>> = RefCell::new(None);
}

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
pub fn take_last_error() -> Option<Box<failure::Error>> {
    LAST_ERROR.with(|prev| prev.borrow_mut().take())
}

/// Retrieve error code corresponding to error type.
pub fn get_error_code(err : &failure::Error ) -> i32 {
    if let Some(_) = err.downcast_ref::<ed25519_dalek::SignatureError>() {
        return constants::SIGNATURE_ERROR;
    }
    else {return -1;}
}


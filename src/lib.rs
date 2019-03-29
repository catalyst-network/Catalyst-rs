/**
* Copyright (c) 2019 Catalyst Network
*
* This file is part of Catalyst.FFI <https://github.com/catalyst-network/catalyst-ffi>
*
* Catalyst.Node is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
* 
* Catalyst.Node is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with Catalyst.Node. If not, see <https://www.gnu.org/licenses/>.
*/

use rand::thread_rng;
extern crate ed25519_dalek;
use ed25519_dalek::SecretKey;
use std::slice;

use std::str;


#[no_mangle]
pub extern "C" fn generate_key(out_key: &mut [u8;32]) {
    let mut csprng = thread_rng();
    let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    out_key.copy_from_slice(&secret_key.to_bytes());
}

#[no_mangle]
pub extern "C" fn std_sign(out_signature: &mut [u8;64], private_key: &[u8;32], message: *const u8, message_length: usize){
   
   let message_array = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };
    //let message_string : String = String::from_utf8(message_array.Res);
   //println!("{}",&message_string);
}







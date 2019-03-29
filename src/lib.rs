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


extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::*;
use rand::thread_rng;
use std::slice;

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
    let secret_key: SecretKey = SecretKey::from_bytes(private_key).unwrap();
    let expanded_secret: ExpandedSecretKey = (&secret_key).into();
    let public_key: PublicKey = (&expanded_secret).into();
    let keypair: Keypair  = Keypair{ secret: secret_key, public: public_key };
    let signature: Signature = keypair.sign(message_array);
    out_signature.copy_from_slice(&signature.to_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_key(){
        let initial_key: [u8;32] = [0;32];
        let mut out_key: [u8;32] = Clone::clone(&initial_key);
        //let mut out_key: [u8;32] = [0;32];
        generate_key(&mut out_key);
        assert_ne!(out_key,initial_key, "key bytes should have been changed by generate_key function")
    }

    #[test]
    fn test_std_sign_verify(){
        let initial_sig: [u8;64] = [0;64];
        let mut out_sig: [u8;64] = Clone::clone(&initial_sig);

        let mut key: [u8;32] = [0;32];
        generate_key(&mut key);
        let message = String::from("You are a sacrifice article that I cut up rough now");
        std_sign(&mut out_sig, &key, message.as_ptr(), message.len());
    }
}







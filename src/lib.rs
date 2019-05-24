#![recursion_limit = "1024"]
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
extern crate libc;
extern crate failure;
#[macro_use] extern crate log;


pub mod ffi;

use ed25519_dalek::*;
use rand::thread_rng;
use std::slice;
use std::result;
use libc::{c_int};

use crate::ffi::*;

type Result<T> = result::Result<T, failure::Error>;

#[no_mangle]
pub extern "C" fn verify_with_errors(signature: & [u8;64], publickey: &[u8;32], message: *const u8, message_length: usize) -> c_int {
   let _res = match std_verify(signature, publickey, message, message_length){
        Err(e) => {
            update_last_error(e);
            return last_error_length();
                    }
        Ok(()) => {return 0;}
    };
}

#[no_mangle]
pub extern "C" fn sign_with_errors(out_signature: &mut [u8;64], private_key: &[u8;32], message: *const u8, message_length: usize) -> c_int {
   let _res = match std_sign(out_signature, private_key, message, message_length){
        Err(e) => {
            update_last_error(e);
            return last_error_length();
                    }
        Ok(()) => {return 0;}
    };
}

#[no_mangle]
pub extern "C" fn generate_key(out_key: &mut [u8;32]) {
    let mut csprng = thread_rng();
    let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    out_key.copy_from_slice(&secret_key.to_bytes());
}

#[no_mangle]
pub extern "C" fn std_sign(out_signature: &mut [u8;64], private_key: &[u8;32], message: *const u8, message_length: usize) -> Result<()>{
   let message_array = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };
    let secret_key: SecretKey = SecretKey::from_bytes(private_key)?;
    let public_key: PublicKey = (&secret_key).into();
    let keypair: Keypair  = Keypair{ secret: secret_key, public: public_key };
    let signature: Signature = keypair.sign(message_array);
    out_signature.copy_from_slice(&signature.to_bytes());
    Ok(())
}

fn std_verify(signature: & [u8;64], publickey: &[u8;32], message: *const u8, message_length: usize) -> Result<()>{
   let message_array = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };
    let public_key: PublicKey = PublicKey::from_bytes(publickey)?;
    let signature: Signature = Signature::from_bytes(signature)?;
    public_key.verify(message_array, &signature)?;
    Ok(())
}

#[no_mangle]
pub extern "C" fn publickey_from_private(out_publickey: &mut [u8;32],private_key: &[u8;32]){
    let secret_key: SecretKey = SecretKey::from_bytes(private_key).expect("failed to create private key");
    let public_key: PublicKey = (&secret_key).into();
    out_publickey.copy_from_slice(&public_key.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_key(){
        let initial_key: [u8;32] = [0;32];
        let mut out_key: [u8;32] = Clone::clone(&initial_key);
        assert_eq!(out_key,initial_key, "arrays should be the same");
        generate_key(&mut out_key);
        assert_ne!(out_key,initial_key, "key bytes should have been changed by generate_key function");
    }

    #[test]
    fn test_publickey_from_private(){
        let mut privatekey: [u8;32] = [0;32];
        generate_key(&mut privatekey);
        let mut out_publickey: [u8;32] = [0;32];
        publickey_from_private(&mut out_publickey, &privatekey);
        let secret_key: SecretKey = SecretKey::from_bytes(&privatekey).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        assert_eq!(out_publickey, public_key.to_bytes());
    }
/*
    #[test]
    fn test_std_sign_verify(){
        let initial_sig: [u8;64] = [0;64];
        let mut out_sig: [u8;64] = Clone::clone(&initial_sig);

        let mut key: [u8;32] = [0;32];
        generate_key(&mut key);
        let message = String::from("You are a sacrifice article that I cut up rough now");
        std_sign(&mut out_sig, &key, message.as_ptr(), message.len());

        let secret_key: SecretKey = SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        let is_verified: bool = std_verify(&out_sig, &PublicKey::to_bytes(&public_key),message.as_ptr(), message.len());
        assert!(is_verified);
    }
    */
/*
    #[test]
    fn test_std_sign_verify_fails(){
        let mut out_sig: [u8;64] = [0;64];
        let message = String::from("You are a sacrifice article that I cut up rough now");
        let message2 = String::from("Mr. speaker, we are for the big");
        let mut key: [u8;32] = [0;32];
        generate_key(&mut key);

        std_sign(&mut out_sig, &key, message.as_ptr(), message.len());

        let secret_key: SecretKey = SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        let is_verified: bool = std_verify(&out_sig, &PublicKey::to_bytes(&public_key),message2.as_ptr(), message2.len());
        assert!(!is_verified);
    }
    */

    #[test]
    fn test_std_sign_verify_errors_fails(){
        let mut out_sig: [u8;64] = [0;64];
        let message = String::from("You are a sacrifice article that I cut up rough now");
        let message2 = String::from("Mr. speaker, we are for the big");
        let mut key: [u8;32] = [0;32];
        generate_key(&mut key);

        sign_with_errors(&mut out_sig, &key, message.as_ptr(), message.len());

        let secret_key: SecretKey = SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        let x: c_int = verify_with_errors(&out_sig, &PublicKey::to_bytes(&public_key),message2.as_ptr(), message2.len());
        println!("{}",x);
        
        assert!(x!=0);
    }



}

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
extern crate failure;
#[macro_use] extern crate log;


mod ffi;
mod constants;
mod errors;
mod std_signature;


use ed25519_dalek::*;
use rand::thread_rng;
use std::slice;
use std::result;
use libc::{c_int};

type Result<T> = result::Result<T, failure::Error>;




#[no_mangle]
pub extern "C" fn publickey_from_private(out_publickey: &mut [u8;constants::PUBLIC_KEY_LENGTH],private_key: &[u8;constants::PRIVATE_KEY_LENGTH]){
    let secret_key: SecretKey = SecretKey::from_bytes(private_key).expect("failed to create private key");
    let public_key: PublicKey = (&secret_key).into();
    out_publickey.copy_from_slice(&public_key.to_bytes())
}

#[no_mangle]
pub extern "C" fn generate_key(out_key: &mut [u8;constants::PRIVATE_KEY_LENGTH]) {
    let mut csprng = thread_rng();
    let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    out_key.copy_from_slice(&secret_key.to_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_key(){
        let initial_key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        let mut out_key: [u8;constants::PRIVATE_KEY_LENGTH] = Clone::clone(&initial_key);
        assert_eq!(out_key,initial_key, "arrays should be the same");
        generate_key(&mut out_key);
        assert_ne!(out_key,initial_key, "key bytes should have been changed by generate_key function");
    }

    #[test]
    fn test_publickey_from_private(){
        let mut privatekey: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        generate_key(&mut privatekey);
        let mut out_publickey: [u8;constants::PUBLIC_KEY_LENGTH] = [0;constants::PUBLIC_KEY_LENGTH];
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
        let mut out_sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];
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

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

//! ed25519 signatures and verification.

use ed25519_dalek::*;
use std::slice;
use std::result;
use crate::constants;
use crate::keys;
use failure;

type Result<T> = result::Result<T, failure::Error>;

pub fn verify(signature: & [u8;constants::SIGNATURE_LENGTH], publickey: &[u8;constants::PUBLIC_KEY_LENGTH], message: *const u8, message_length: usize) -> Result<bool>{
   let message_array = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };
    let public_key: PublicKey = PublicKey::from_bytes(publickey)?;
    let signature: Signature = Signature::from_bytes(signature)?;
    Ok(public_key.verify(message_array, &signature).is_ok())
}

pub fn sign(out_signature: &mut [u8;constants::SIGNATURE_LENGTH], private_key: &[u8;constants::PRIVATE_KEY_LENGTH], message: *const u8, message_length: usize) -> Result<()>{
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

pub fn sign_with_context(out_signature: &mut [u8;constants::SIGNATURE_LENGTH], 
                         private_key: &[u8;constants::PRIVATE_KEY_LENGTH], 
                         message: *const u8, 
                         message_length: usize, 
                         context: *const u8, 
                         context_length: usize) 
                         -> Result<()>{
   let message_array = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };

    let context_array = unsafe {
        assert!(!context.is_null());
        slice::from_raw_parts(context, context_length)
    };

    if context_array.len() > 255 {
        bail!("Ahh")
    }

    let secret_key: SecretKey = SecretKey::from_bytes(private_key)?;
    let public_key: PublicKey = (&secret_key).into();
    let keypair: Keypair  = Keypair{ secret: secret_key, public: public_key };
    let mut prehashed: Sha512 = Sha512::new();
    prehashed.input(message_array);
    let signature: Signature = keypair.sign_prehashed(prehashed, Some(context_array));
    out_signature.copy_from_slice(&signature.to_bytes());
    Ok(())
}

pub fn verify_with_context(signature: & [u8;constants::SIGNATURE_LENGTH], 
                           publickey: &[u8;constants::PUBLIC_KEY_LENGTH], 
                           message: *const u8, 
                           message_length: usize,
                           context: *const u8, 
                           context_length: usize) 
                           -> Result<bool>{
   let message_array = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };

    let context_array = unsafe {
        assert!(!context.is_null());
        slice::from_raw_parts(context, context_length)
    };



    let public_key: PublicKey = PublicKey::from_bytes(publickey)?;
    let signature: Signature = Signature::from_bytes(signature)?;
    let mut prehashed: Sha512 = Sha512::new();
    prehashed.input(message_array);
    Ok(public_key.verify_prehashed(prehashed, Some(context_array), &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify(){
        let initial_sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];
        let mut out_sig: [u8;constants::SIGNATURE_LENGTH] = Clone::clone(&initial_sig);

        let mut key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        assert!(keys::generate_key(&mut key).is_ok());
        let message = String::from("You are a sacrifice article that I cut up rough now");
        assert!(sign(&mut out_sig, &key, message.as_ptr(), message.len()).is_ok());

        let secret_key: SecretKey = SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        assert_eq!(verify(&out_sig, &PublicKey::to_bytes(&public_key),message.as_ptr(), message.len()).unwrap(), true);
    }

    #[test]
    fn test_sign_verify_with_context(){
        let initial_sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];
        let mut out_sig: [u8;constants::SIGNATURE_LENGTH] = Clone::clone(&initial_sig);

        let mut key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        assert!(keys::generate_key(&mut key).is_ok());
        let message = String::from("You are a sacrifice article that I cut up rough now");
        let context = String::from("TThis is a free online calculator which counts the number of characters or letters in a text, useful for your tweets on Twitter, as well as a multitude of other applications. Whether it is Snapchat, Twitter, Facebook, Yelp or just a note to co-workers or business officials, the number of actual characters matters. ");
        assert!(sign_with_context(&mut out_sig, &key, message.as_ptr(), message.len(), context.as_ptr(), context.len()).is_ok());

        let secret_key: SecretKey = SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        assert_eq!(verify_with_context(&out_sig, &PublicKey::to_bytes(&public_key),message.as_ptr(), message.len(), context.as_ptr(), context.len()).unwrap(), true);
    }

    #[test]
    fn test_sign_verify_fails(){
        let mut out_sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];
        let message = String::from("You are a sacrifice article that I cut up rough now");
        let message2 = String::from("Mr. speaker, we are for the big");
        let mut key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        assert!(keys::generate_key(&mut key).is_ok());

        assert!(sign(&mut out_sig, &key, message.as_ptr(), message.len()).is_ok());

        let secret_key: SecretKey = SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        assert!(verify(&out_sig, &PublicKey::to_bytes(&public_key),message.as_ptr(), message.len()).is_ok());
        assert_eq!(verify(&out_sig, &PublicKey::to_bytes(&public_key),message2.as_ptr(), message2.len()).unwrap(),false);
    }




}

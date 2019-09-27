//! Ed25519ph signatures and verification.

use std::slice;
use std::result;
use failure;
use crate::constants;
use crate::errors;
use ed25519_dalek::{Sha512, Digest};
use super::{SecretKey, PublicKey, Signature, Keypair};

type Result<T> = result::Result<T, failure::Error>;

pub(crate) fn unwrap_and_sign(out_signature: &mut [u8;constants::SIGNATURE_LENGTH],
                         private_key: &[u8;constants::PRIVATE_KEY_LENGTH], 
                         message: *const u8, 
                         message_length: usize, 
                         context: *const u8, 
                         context_length: usize) 
                         -> Result<()>{
   let message = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };

    let context = unsafe {
        assert!(!context.is_null());
        slice::from_raw_parts(context, context_length)
    };

    if context.len() > constants::CONTEXT_MAX_LENGTH {
        Err(errors::ContextLengthError)?;
    }

    let secret_key: SecretKey = SecretKey::from_bytes(private_key)?;
    let public_key: PublicKey = (&secret_key).into();

    let signature = sign(secret_key, public_key, message, Some(context))?;

    out_signature.copy_from_slice(&signature.to_bytes());
    Ok(())
}
/// Creates an ed25519ph signature from private key, context and message.
pub fn sign(secret: SecretKey, public: PublicKey, message: &[u8], context: Option<&'static [u8]>)
-> Result<Signature> {
    let keypair: Keypair = Keypair { secret, public };
    let mut prehashed: Sha512 = Sha512::new();
    prehashed.input(message);
    Ok(keypair.sign_prehashed(prehashed, context))
}

pub(crate) fn unwrap_and_verify(signature: & [u8;constants::SIGNATURE_LENGTH],
                           publickey: &[u8;constants::PUBLIC_KEY_LENGTH], 
                           message: *const u8, 
                           message_length: usize,
                           context: *const u8, 
                           context_length: usize) 
                           -> Result<bool>{
   let message = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };

    let context = unsafe {
        assert!(!context.is_null());
        slice::from_raw_parts(context, context_length)
    };

    let public_key: PublicKey = PublicKey::from_bytes(publickey)?;
    let signature: Signature = Signature::from_bytes(signature)?;

    verify(signature, public_key, message, Some(context))
    
}

/// Verifies that an ed25519ph signature corresponds to the provided public key, message, and context.
pub fn verify(signature: Signature, public: PublicKey, message: &[u8], context: Option<&'static [u8]>)
-> Result<bool> {
    let mut prehashed: Sha512 = Sha512::new();
    prehashed.input(message);
    Ok(public.verify_prehashed(prehashed, context, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;

    #[test]
    fn can_sign_message_and_verify_signature(){
        let initial_sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];
        let mut out_sig: [u8;constants::SIGNATURE_LENGTH] = Clone::clone(&initial_sig);

        let mut key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        assert!(keys::generate_key(&mut key).is_ok());
        let message = String::from("You are a sacrifice article that I cut up rough now");
        let context = String::from("Context 1 2 3");
        assert!(unwrap_and_sign(&mut out_sig, &key, message.as_ptr(), message.len(), context.as_ptr(), context.len()).is_ok());

        let secret_key: SecretKey = SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        assert_eq!(unwrap_and_verify(&out_sig, &PublicKey::to_bytes(&public_key),message.as_ptr(), message.len(), context.as_ptr(), context.len()).unwrap(), true);
    }

    #[test]
    fn can_sign_message_and_verify_signature_with_empty_context(){
        let initial_sig: [u8;constants::SIGNATURE_LENGTH] = [0;constants::SIGNATURE_LENGTH];
        let mut out_sig: [u8;constants::SIGNATURE_LENGTH] = Clone::clone(&initial_sig);

        let mut key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        assert!(keys::generate_key(&mut key).is_ok());
        let message = String::from("You are a sacrifice article that I cut up rough now");
        let context = String::from("");
        assert!(unwrap_and_sign(&mut out_sig, &key, message.as_ptr(), message.len(), context.as_ptr(), context.len()).is_ok());

        let secret_key: SecretKey = SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        assert_eq!(unwrap_and_verify(&out_sig, &PublicKey::to_bytes(&public_key),message.as_ptr(), message.len(), context.as_ptr(), context.len()).unwrap(), true);
    }
}

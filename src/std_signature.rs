
use ed25519_dalek::*;
use rand::thread_rng;
use std::slice;
use std::result;
use crate::constants;

type Result<T> = result::Result<T, failure::Error>;

pub fn verify(signature: & [u8;constants::SIGNATURE_LENGTH], publickey: &[u8;constants::PUBLIC_KEY_LENGTH], message: *const u8, message_length: usize) -> Result<()>{
   let message_array = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };
    let public_key: PublicKey = PublicKey::from_bytes(publickey)?;
    let signature: Signature = Signature::from_bytes(signature)?;
    public_key.verify(message_array, &signature)?;
    Ok(())
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
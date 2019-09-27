//! ed25519 keys

use rand::thread_rng;
use ed25519_dalek::{PublicKey,SecretKey};
use crate::constants;
use std::result;

pub type Result<T> = result::Result<T, failure::Error>;

pub fn publickey_from_private(out_publickey: &mut [u8;constants::PUBLIC_KEY_LENGTH], private_key: &[u8;constants::PRIVATE_KEY_LENGTH]) -> Result<()> {
    let secret_key: SecretKey = SecretKey::from_bytes(private_key)?;
    let public_key: PublicKey = (&secret_key).into();
    out_publickey.copy_from_slice(&public_key.to_bytes());
    Ok(())
}

pub fn generate_key(out_key: &mut [u8;constants::PRIVATE_KEY_LENGTH]) -> Result<()> {
    let mut csprng = thread_rng();
    let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    out_key.copy_from_slice(&secret_key.to_bytes());
    Ok(())
}

pub fn validate_public(public_key: &[u8;constants::PUBLIC_KEY_LENGTH]) -> Result<()>{
    PublicKey::from_bytes(public_key)?;
    Ok(())
}

pub fn validate_private(private_key: &[u8; constants::PRIVATE_KEY_LENGTH]) -> Result<()>{
    SecretKey::from_bytes(private_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn can_generate_private_key(){
        let initial_key: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        let mut out_key: [u8;constants::PRIVATE_KEY_LENGTH] = Clone::clone(&initial_key);
        assert_eq!(out_key,initial_key, "arrays should be the same");
        assert!(generate_key(&mut out_key).is_ok());
        assert_ne!(out_key,initial_key, "key bytes should have been changed by generate_key function");
    }

    #[test]
    fn can_get_public_key_from_private_key(){
        let mut privatekey: [u8;constants::PRIVATE_KEY_LENGTH] = [0;constants::PRIVATE_KEY_LENGTH];
        assert!(generate_key(&mut privatekey).is_ok());
        let mut out_publickey: [u8;constants::PUBLIC_KEY_LENGTH] = [0;constants::PUBLIC_KEY_LENGTH];
        assert!(publickey_from_private(&mut out_publickey, &privatekey).is_ok());
        let secret_key: SecretKey = SecretKey::from_bytes(&privatekey).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        assert_eq!(out_publickey, public_key.to_bytes());
    }
}


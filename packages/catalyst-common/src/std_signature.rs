//! Ed25519ph signatures and verification.

use super::{Keypair, PublicKey, SecretKey, Signature};
use crate::constants;
pub use catalyst_protocol_sdk_rust::prelude::*;
pub use catalyst_protocol_sdk_rust::Cryptography::ErrorCode;
use ed25519_dalek::{Digest, Sha512};
use std::slice;

pub(crate) fn unwrap_and_sign(
    out_signature: &mut [u8; constants::SIGNATURE_LENGTH],
    out_public_key: &mut [u8; constants::PUBLIC_KEY_LENGTH],
    private_key: &[u8; constants::PRIVATE_KEY_LENGTH],
    message: *const u8,
    message_length: usize,
    context: *const u8,
    context_length: usize,
) -> i32 {
    let message = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };

    let context = unsafe {
        assert!(!context.is_null());
        slice::from_raw_parts(context, context_length)
    };

    if context.len() > constants::CONTEXT_MAX_LENGTH {
        return ErrorCode::INVALID_CONTEXT_LENGTH.value();
    }

    let private_key = match SecretKey::from_bytes(private_key) {
        Ok(private_key) => private_key,
        Err(_) => return ErrorCode::INVALID_PRIVATE_KEY.value(),
    };
    let public_key: PublicKey = (&private_key).into();
    out_public_key.copy_from_slice(&public_key.to_bytes());

    let signature = sign(private_key, public_key, message, Some(context));

    out_signature.copy_from_slice(&signature.to_bytes());
    ErrorCode::NO_ERROR.value()
}

pub(crate) fn unwrap_and_verify(
    signature: &[u8; constants::SIGNATURE_LENGTH],
    publickey: &[u8; constants::PUBLIC_KEY_LENGTH],
    message: *const u8,
    message_length: usize,
    context: *const u8,
    context_length: usize,
) -> i32 {
    let message = unsafe {
        assert!(!message.is_null());
        slice::from_raw_parts(message, message_length)
    };

    let context = unsafe {
        assert!(!context.is_null());
        slice::from_raw_parts(context, context_length)
    };

    let public_key = match PublicKey::from_bytes(publickey) {
        Ok(public_key) => public_key,
        Err(_) => return ErrorCode::INVALID_PUBLIC_KEY.value(),
    };
    let signature = match Signature::from_bytes(signature) {
        Ok(signature) => signature,
        Err(_) => return ErrorCode::INVALID_SIGNATURE.value(),
    };

    verify(signature, public_key, message, Some(context))
}

/// Verifies that an ed25519ph signature corresponds to the provided public key, message, and context.
pub fn verify(
    signature: Signature,
    public: PublicKey,
    message: &[u8],
    context: Option<&'static [u8]>,
) -> i32 {
    let mut prehashed: Sha512 = Sha512::new();
    prehashed.input(message);
    match public.verify_prehashed(prehashed, context, &signature) {
        Ok(_) => ErrorCode::NO_ERROR.value(),
        Err(_) => ErrorCode::SIGNATURE_VERIFICATION_FAILURE.value(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;

    #[test]
    fn can_sign_message_and_verify_signature() {
        let initial_sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut out_sig: [u8; constants::SIGNATURE_LENGTH] = Clone::clone(&initial_sig);

        let mut out_public_key: [u8; constants::PRIVATE_KEY_LENGTH] =
            [0; constants::PUBLIC_KEY_LENGTH];

        let mut key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];
        keys::generate_key(&mut key);

        let message = String::from("You are a sacrifice article that I cut up rough now");
        let context = String::from("Context 1 2 3");
        unwrap_and_sign(
            &mut out_sig,
            &mut out_public_key,
            &key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );

        let secret_key: SecretKey =
            SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        assert_eq!(
            unwrap_and_verify(
                &out_sig,
                &PublicKey::to_bytes(&public_key),
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len()
            ),
            ErrorCode::NO_ERROR.value()
        );
    }

    #[test]
    fn can_sign_message_and_verify_signature_with_empty_context() {
        let initial_sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut out_sig: [u8; constants::SIGNATURE_LENGTH] = Clone::clone(&initial_sig);

        let mut out_public_key: [u8; constants::PRIVATE_KEY_LENGTH] =
            [0; constants::PUBLIC_KEY_LENGTH];

        let mut key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];
        assert_eq!(keys::generate_key(&mut key), ErrorCode::NO_ERROR.value());
        let message = String::from("You are a sacrifice article that I cut up rough now");
        let context = String::from("");
        assert_eq!(
            unwrap_and_sign(
                &mut out_sig,
                &mut out_public_key,
                &key,
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len()
            ),
            ErrorCode::NO_ERROR.value()
        );

        let secret_key: SecretKey =
            SecretKey::from_bytes(&key).expect("failed to create private key");
        let public_key: PublicKey = (&secret_key).into();
        assert_eq!(
            unwrap_and_verify(
                &out_sig,
                &PublicKey::to_bytes(&public_key),
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len()
            ),
            ErrorCode::NO_ERROR.value()
        );
    }
}

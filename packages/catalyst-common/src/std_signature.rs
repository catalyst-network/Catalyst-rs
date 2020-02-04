use super::*;
use ed25519_dalek::{Digest, Sha512, Signature};

#[inline]
pub fn sign(
    signature: &mut [u8; constants::SIGNATURE_LENGTH],
    public_key: &mut [u8; constants::PUBLIC_KEY_LENGTH],
    private_key: &[u8; constants::PRIVATE_KEY_LENGTH],
    message: &[u8],
    context: &'static [u8],
) -> i32 {
    let private_key = match SecretKey::from_bytes(private_key) {
        Ok(private_key) => private_key,
        Err(_) => return ErrorCode::INVALID_PRIVATE_KEY.value(),
    };
    let public = PublicKey::from(&private_key);
    let keypair: Keypair = Keypair {
        secret: private_key,
        public,
    };
    
    if context.len() > constants::CONTEXT_MAX_LENGTH {
        return ErrorCode::INVALID_CONTEXT_LENGTH.value();
    }

    let mut prehashed: Sha512 = Sha512::new();
    prehashed.input(message);
    let sig = keypair
        .sign_prehashed(prehashed, Some(context))
        .to_bytes();

    signature.copy_from_slice(&sig);
    public_key.copy_from_slice(&public.to_bytes());

    ErrorCode::NO_ERROR.value()
}

#[inline]
pub fn verify(
    signature: &[u8],
    public_key: &[u8],
    message: &[u8],
    context: &'static [u8],
) -> i32 {
    let public_key = match PublicKey::from_bytes(public_key) {
        Ok(public_key) => public_key,
        Err(_) => return ErrorCode::INVALID_PUBLIC_KEY.value(),
    };
    let signature = match Signature::from_bytes(signature) {
        Ok(signature) => signature,
        Err(_) => return ErrorCode::INVALID_SIGNATURE.value(),
    };
    let mut prehashed: Sha512 = Sha512::new();
    prehashed.input(message);

    match public_key.verify_prehashed(prehashed, Some(context), &signature) {
        Ok(_) => ErrorCode::NO_ERROR.value(),
        Err(_) => ErrorCode::SIGNATURE_VERIFICATION_FAILURE.value(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_signature() {
        let mut sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut public_key: [u8; constants::PUBLIC_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
        let private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];
        let message = b"message";
        let context = b"context";
        let result = sign(&mut sig, &mut public_key, &private_key, message, context);
        assert_eq!(result, ErrorCode::NO_ERROR.value());
    }

    #[test]
    fn can_sign_message_and_verify_signature() {
        let mut sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut public_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
        let private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];

        let message = b"You are a sacrifice article that I cut up rough now";
        let context = b"Context 1 2 3";
        sign(
            &mut sig,
            &mut public_key,
            &private_key,
            message,
            context,
        );

        assert_eq!(
            verify(
                &sig,
                &public_key,
                message,
                context,
            ),
            ErrorCode::NO_ERROR.value()
        );
    }

    #[test]
    fn can_sign_message_and_verify_signature_with_empty_context() {
        let mut sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut public_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
        let private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];

        let message = b"You are a sacrifice article that I cut up rough now";
        let context = b"";
        assert_eq!(
            sign(
                &mut sig,
                &mut public_key,
                &private_key,
                message,
                context,
            ),
            ErrorCode::NO_ERROR.value()
        );

        assert_eq!(
            verify(
                &sig,
                &public_key,
                message,
                context,
            ),
            ErrorCode::NO_ERROR.value()
        );
    }
}


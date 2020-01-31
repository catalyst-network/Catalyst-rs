use super::*;
use std::slice;

pub fn sign_sig_and_public_key(
    signature: &mut [u8; constants::SIGNATURE_LENGTH],
    public_key: &mut [u8; constants::PUBLIC_KEY_LENGTH],
    private_key: &[u8; constants::PRIVATE_KEY_LENGTH],
    message: &[u8],
    context: &[u8],
    context_length: usize,
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

    let context = unsafe { slice::from_raw_parts(context.as_ptr(), context_length) };
    if context.len() > 255 || context.len() != context_length {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_signature() {
        let mut sig: [u8; 64] = [0; 64];
        let mut public: [u8; 32] = [0; 32];
        let private: [u8; 32] = [0; 32];
        let message = b"message";
        let context = b"context";
        let result = sign_sig_and_public_key(&mut sig, &mut public, &private, message, context, context.len());
        assert_eq!(result, ErrorCode::NO_ERROR.value());
    }
}


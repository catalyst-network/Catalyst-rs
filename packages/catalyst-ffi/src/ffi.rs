//! The foreign function interface which exposes this library to non-Rust
//! languages. Error codes returned are as defined in protocol protobuffs https://github.com/catalyst-network/protocol-protobuffs/blob/develop/src/Cryptography.proto

use super::*;
use libc::c_int;
use std::slice;
use rand::Rng;
use rand::{CryptoRng, RngCore};

/// Verifies that an ed25519 signature corresponds to the provided public key, message, and context. Returns 0 if no error encountered, otherwise returns an error code. Sets value of is_verified based of verification outcome.
#[no_mangle]
pub extern "C" fn std_verify(
    signature: &[u8; constants::SIGNATURE_LENGTH],
    publickey: &[u8; constants::PUBLIC_KEY_LENGTH],
    message: *const u8,
    message_length: usize,
    context: *const u8,
    context_length: usize,
) -> c_int {
    let message = unsafe { slice::from_raw_parts(message, message_length) };
    let context = unsafe { slice::from_raw_parts(context, context_length) };
    std_signature::verify(signature, publickey, message, context)
}

/// Creates a signature from private key and message.
#[no_mangle]
pub extern "C" fn std_sign(
    out_signature: &mut [u8; constants::SIGNATURE_LENGTH],
    out_public_key: &mut [u8; constants::PUBLIC_KEY_LENGTH],
    private_key: &[u8; constants::PRIVATE_KEY_LENGTH],
    message: *const u8,
    message_length: usize,
    context: *const u8,
    context_length: usize,
) -> c_int {
    let message = unsafe { slice::from_raw_parts(message, message_length) };
    let context = unsafe { slice::from_raw_parts(context, context_length) };
    std_signature::sign(out_signature, out_public_key, private_key, message, context)
}

/// Calculates corresponding public key, given a private key.
#[no_mangle]
pub extern "C" fn publickey_from_private(
    out_publickey: &mut [u8; constants::PUBLIC_KEY_LENGTH],
    private_key: &[u8; constants::PRIVATE_KEY_LENGTH],
) -> c_int {
    keys::publickey_from_private(out_publickey, private_key)
}

#[no_mangle]
pub extern "C" fn batch_verify(bytes: &[u8]) -> c_int{
    let mut batch_sigs = SignatureBatch::new();
    batch_sigs.merge_from_bytes(bytes);
    batch::unwrap_and_verify_batch(&mut batch_sigs)
}

/// Randomly generated private key.
#[no_mangle]
pub extern "C" fn generate_private_key(out_key: &mut [u8; constants::PRIVATE_KEY_LENGTH]) -> c_int {
    keys::generate_private_key(out_key, OsRng{})
}

///Returns private key length in bytes
#[no_mangle]
pub extern "C" fn get_private_key_length() -> c_int {
    constants::PRIVATE_KEY_LENGTH as i32
}

///Returns public key length in bytes
#[no_mangle]
pub extern "C" fn get_public_key_length() -> c_int {
    constants::PUBLIC_KEY_LENGTH as i32
}

///Returns signature length in bytes
#[no_mangle]
pub extern "C" fn get_signature_length() -> c_int {
    constants::SIGNATURE_LENGTH as i32
}

///Returns max context length in bytes
#[no_mangle]
pub extern "C" fn get_max_context_length() -> c_int {
    constants::CONTEXT_MAX_LENGTH as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn can_create_signature() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];
        let message = b"message";
        let context = b"context";
        let result = std_sign(
            &mut sig,
            &mut public_key,
            &private_key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );
        assert_eq!(result, ErrorCode::NO_ERROR.value());
    }

    #[test]
    fn can_sign_message_and_verify_signature() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];

        let message = b"message";
        let context = b"Context 1 2 3";
        std_sign(
            &mut sig,
            &mut public_key,
            &private_key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );

        assert_eq!(
            std_verify(
                &sig,
                &public_key,
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len(),
            ),
            ErrorCode::NO_ERROR.value()
        );
    }

    #[test]
    fn verification_fails_for_incorrect_context() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];

        let message = b"message";
        let context1 = b"Context 1 2 3";
        let context2 = b"Context 1 2 3 4";
        std_sign(
            &mut sig,
            &mut public_key,
            &private_key,
            message.as_ptr(),
            message.len(),
            context1.as_ptr(),
            context1.len(),
        );
        let verified = std_verify(
            &sig,
            &public_key,
            message.as_ptr(),
            message.len(),
            context2.as_ptr(),
            context2.len(),
        );
        assert_eq!(verified, ErrorCode::SIGNATURE_VERIFICATION_FAILURE.value())
    }

    #[test]
    fn signing_fails_for_context_length_exceeding_maximum() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];

        let message = b"message";
        let context = b"2hPB7lVGQHENtQLcfOoTnEjBHO5jg0zgyQYyrKHOxywDrDDfmyg0z9M9Q0hRRfPUV4fWvRGR9l48a3cXmFqBPneErN5GwzD28E3cLhDRNAdaNEpelPRDzN4w2dGaNWc4Jrc7TlVEbC5JQdfMgmtPkakmF3mPCU1YUFQArFUbQFQdFLHL2PByvyzdHaStkSgZbCz0zb9jCBO0vwx4J6YXvXFoc9urYREcR7uiFEVcrf6L2C2uUVOtWQUHRQyIRtmx";
        let result = std_sign(
            &mut sig,
            &mut public_key,
            &private_key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );

        assert_eq!(result, ErrorCode::INVALID_CONTEXT_LENGTH.value())
    }

    #[test]
    fn verification_fails_for_invalid_public_key() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];

        let message = b"message";
        let context = b"Context 1 2 3";
        std_sign(
            &mut sig,
            &mut public_key,
            &private_key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );
        public_key[constants::PUBLIC_KEY_LENGTH - 1] =
            public_key[constants::PUBLIC_KEY_LENGTH - 1].wrapping_add(1u8);
        let verified = std_verify(
            &sig,
            &public_key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );
        assert_eq!(verified, ErrorCode::INVALID_PUBLIC_KEY.value())
    }

    #[test]
    fn can_validate_using_known_test_vector() {
        let sig = <[u8; constants::SIGNATURE_LENGTH]>::from_hex("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406").unwrap();
        let public_key = <[u8; constants::PRIVATE_KEY_LENGTH]>::from_hex(
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        )
        .unwrap();
        let mut message = [0u8; 3];
        hex::decode_to_slice("616263", &mut message as &mut [u8]).unwrap();
        let context = b"";
        assert_eq!(
            std_verify(
                &sig,
                &public_key,
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len(),
            ),
            ErrorCode::NO_ERROR.value()
        );
    }

    #[test]
    fn can_sign_message_and_verify_signature_with_empty_context() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];

        let message = b"message";
        let context = b"";
        assert_eq!(
            std_sign(
                &mut sig,
                &mut public_key,
                &private_key,
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len(),
            ),
            ErrorCode::NO_ERROR.value()
        );

        assert_eq!(
            std_verify(
                &sig,
                &public_key,
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len(),
            ),
            ErrorCode::NO_ERROR.value()
        );
    }
}

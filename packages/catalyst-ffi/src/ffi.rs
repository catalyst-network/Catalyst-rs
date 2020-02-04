//! The foreign function interface which exposes this library to non-Rust
//! languages. Error codes returned are as defined in protocol protobuffs https://github.com/catalyst-network/protocol-protobuffs/blob/develop/src/Cryptography.proto

use super::*;
use libc::c_int;
use std::slice;

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
    let message = unsafe {
        slice::from_raw_parts(message, message_length)
    };
    let context = unsafe {
        slice::from_raw_parts(context, context_length)
    };
    std_signature::verify(
        signature,
        publickey,
        message,
        context,
    )
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
    let message = unsafe {
        slice::from_raw_parts(message, message_length)
    };
    let context = unsafe {
        slice::from_raw_parts(context, context_length)
    };
    std_signature::sign(
        out_signature,
        out_public_key,
        private_key,
        message,
        context,
    )
}

/// Calculates corresponding public key, given a private key. 
#[no_mangle]
pub extern "C" fn publickey_from_private(
    out_publickey: &mut [u8; constants::PUBLIC_KEY_LENGTH],
    private_key: &[u8; constants::PRIVATE_KEY_LENGTH],
) -> c_int {
    keys::publickey_from_private(out_publickey, private_key)
}

/// Randomly generated private key.
#[no_mangle]
pub extern "C" fn generate_key(out_key: &mut [u8; constants::PRIVATE_KEY_LENGTH]) -> c_int {
    keys::generate_private_key(out_key)
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

    #[test]
    fn can_throw_context_length_error() {

        let mut sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut public_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
        let mut private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];
        keys::generate_private_key(&mut private_key);

        let message = b"message";

        let context: Vec<u8> = (0..256).map(|_| rand::random::<u8>()).collect();

        let error_code = std_sign(
            &mut sig,
            &mut public_key,
            &private_key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );
        assert_eq!(error_code, ErrorCode::INVALID_CONTEXT_LENGTH.value());
    }

    #[test]
    fn can_use_lib_to_sign() {
        let mut sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut public_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
        let mut private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];
        generate_key(&mut private_key);
        let message = b"message";
        let context = b"context";
        std_sign(
            &mut sig,
            &mut public_key, 
            &private_key, 
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );
    }

    #[test]
    fn can_use_lib_to_verify() {
        let mut sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut public_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
        let mut private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];
        keys::generate_private_key(&mut private_key);
        let message = b"message";
        let context = b"context";
        std_sign(
            &mut sig,
            &mut public_key, 
            &private_key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );
        let verified = std_verify(
            &mut sig,
            &mut public_key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );
        assert_eq!(verified, ErrorCode::NO_ERROR.value())
    }

    #[test]
    fn lib_verification_can_fail() {
        let mut sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut public_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
        let mut private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];
        keys::generate_private_key(&mut private_key);
        let message = b"message";
        let context1 = b"context1";
        let context2 = b"context2";
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
}

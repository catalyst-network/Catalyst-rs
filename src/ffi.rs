//! The foreign function interface which exposes this library to non-Rust
//! languages. Error codes returned are as defined in protocol protobuffs https://github.com/catalyst-network/protocol-protobuffs/blob/develop/src/Cryptography.proto

use super::*; 
use libc::c_int;
use catalyst_protocol_sdk_rust::Cryptography::{ErrorCode, SignatureBatch};

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
    std_signature::unwrap_and_verify(
        signature,
        publickey,
        message,
        message_length,
        context,
        context_length,
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
    std_signature::unwrap_and_sign(
        out_signature,
        out_public_key,
        private_key,
        message,
        message_length,
        context,
        context_length,
    )
}

#[no_mangle]
pub extern "C" fn batch_verify(bytes: &[u8]) -> c_int{
    let mut batch_sigs = SignatureBatch::new();
    batch_sigs.merge_from_bytes(bytes);
    batch::unwrap_and_verify_batch(&mut batch_sigs)
    }
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
    keys::generate_key(out_key)
}

/// Checks that the bytes provided represent a valid public key.
#[no_mangle]
pub extern "C" fn validate_public_key(public_key: &[u8; constants::PUBLIC_KEY_LENGTH]) -> c_int {
    keys::validate_public(&public_key)
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
        use catalyst_protocol_sdk_rust::prelude::*;
        use catalyst_protocol_sdk_rust::Cryptography::ErrorCode;

        let initial_sig: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        let mut out_sig: [u8; constants::SIGNATURE_LENGTH] = Clone::clone(&initial_sig);

        let mut out_public_key: [u8; constants::PRIVATE_KEY_LENGTH] =
            [0; constants::PUBLIC_KEY_LENGTH];

        let context: Vec<u8> = (0..256).map(|_| rand::random::<u8>()).collect();
        println!("********* context length is: {}", context.len());

        let mut key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];
        assert_eq!(keys::generate_key(&mut key), ErrorCode::NO_ERROR.value());
        let message = String::from("You are a sacrifice article that I cut up rough now");
        let error_code = std_sign(
            &mut out_sig,
            &mut out_public_key,
            &key,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
        );
        assert_eq!(error_code, ErrorCode::INVALID_CONTEXT_LENGTH.value());
    }
}

//! The foreign function interface which exposes this library to non-Rust
//! languages. Error codes returned are as defined in protocol protobuffs https://github.com/catalyst-network/protocol-protobuffs/blob/develop/src/Cryptography.proto

use super::*;
use libc::c_int;
use rand::rngs::OsRng;
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

/// Checks public key is a valid point on the curve.
#[no_mangle]
pub extern "C" fn validate_public_key(
    public_key: &mut [u8; constants::PUBLIC_KEY_LENGTH]
) -> c_int {
    keys::validate_public_key(public_key)
}

#[no_mangle]
#[allow(unused_must_use)]
pub extern "C" fn verify_batch(bytes: *const u8, bytes_length: usize,) -> c_int {
    let bytes = unsafe { slice::from_raw_parts(bytes, bytes_length) };
    let mut batch_sigs = SignatureBatch::new();
    batch_sigs.merge_from_bytes(bytes);
    batch::verify_batch(&mut batch_sigs, &mut OsRng {})
}

/// Randomly generated private key.
#[no_mangle]
pub extern "C" fn generate_private_key(out_key: &mut [u8; constants::PRIVATE_KEY_LENGTH]) -> c_int {
    keys::generate_private_key(out_key, &mut OsRng {})
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
    use protobuf::RepeatedField;

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

    #[test]
    fn batch_verify_validates_multiple_correct_signatures() {
        let mut sigs: std::vec::Vec<Vec<u8>> = Vec::new();
        let mut public_keys: std::vec::Vec<Vec<u8>> = Vec::new();
        let mut messages = Vec::new();

        messages.push(b"'Twas brillig, and the slithy toves".to_vec());
        messages.push(b"Did gyre and gimble in the wabe:".to_vec());
        messages.push(b"All mimsy were the borogoves,".to_vec());
        messages.push(b"And the mome raths outgrabe.".to_vec());
        messages.push(b"'Beware the Jabberwock, my son!".to_vec());
        let context = b"context";

        for i in 0..messages.len() {
            let mut sig = [0u8; constants::SIGNATURE_LENGTH];
            let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
            let mut private_key = [0u8; constants::PRIVATE_KEY_LENGTH];
            generate_private_key(&mut private_key);

            std_sign(
                &mut sig,
                &mut public_key,
                &private_key,
                messages[i].as_ptr(),
                messages[i].len(),
                context.as_ptr(),
                context.len(),
            );
            sigs.push(sig.to_vec());
            public_keys.push(public_key.to_vec());
        }

        let mut batch_sigs = SignatureBatch::new();
        batch_sigs.set_context(b"context".to_vec());
        batch_sigs.set_messages(RepeatedField::from_vec(messages));
        batch_sigs.set_signatures(RepeatedField::from_vec(sigs));
        batch_sigs.set_public_keys(RepeatedField::from_vec(public_keys));
        let batch = batch_sigs.write_to_bytes().unwrap();

        let result = verify_batch(batch.as_ptr(), batch.len());

        assert_eq!(result, ErrorCode::NO_ERROR.value());
    }

    #[test]
    fn batch_verify_fails_on_single_incorrect_message() {
        let mut sigs: std::vec::Vec<Vec<u8>> = Vec::new();
        let mut public_keys: std::vec::Vec<Vec<u8>> = Vec::new();
        let mut messages = Vec::new();

        messages.push(b"'Twas brillig, and the slithy toves".to_vec());
        messages.push(b"Did gyre and gimble in the wabe:".to_vec());
        messages.push(b"All mimsy were the borogoves,".to_vec());
        messages.push(b"And the mome raths outgrabe.".to_vec());
        messages.push(b"'Beware the Jabberwock, my son!".to_vec());
        let context = b"context";

        for i in 0..messages.len() {
            let mut sig = [0u8; constants::SIGNATURE_LENGTH];
            let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
            let mut private_key = [0u8; constants::PRIVATE_KEY_LENGTH];
            generate_private_key(&mut private_key);

            std_sign(
                &mut sig,
                &mut public_key,
                &private_key,
                messages[i].as_ptr(),
                messages[i].len(),
                context.as_ptr(),
                context.len(),
            );
            sigs.push(sig.to_vec());
            public_keys.push(public_key.to_vec());
        }
        //alter a message before batch verification
        messages[4] = b"The jaws that bite, the claws that catch!".to_vec();

        let mut batch_sigs = SignatureBatch::new();
        batch_sigs.set_context(b"context".to_vec());
        batch_sigs.set_messages(RepeatedField::from_vec(messages));
        batch_sigs.set_signatures(RepeatedField::from_vec(sigs));
        batch_sigs.set_public_keys(RepeatedField::from_vec(public_keys));
        let batch = batch_sigs.write_to_bytes().unwrap();

        let result = verify_batch(batch.as_ptr(), batch.len());


        assert_eq!(result, ErrorCode::BATCH_VERIFICATION_FAILURE.value());
    }

    #[test]
    fn batch_verify_fails_on_single_incorrect_signature() {
        let mut sigs: std::vec::Vec<Vec<u8>> = Vec::new();
        let mut public_keys: std::vec::Vec<Vec<u8>> = Vec::new();
        let mut messages = Vec::new();

        messages.push(b"'Twas brillig, and the slithy toves".to_vec());
        messages.push(b"Did gyre and gimble in the wabe:".to_vec());
        messages.push(b"All mimsy were the borogoves,".to_vec());
        messages.push(b"And the mome raths outgrabe.".to_vec());
        messages.push(b"'Beware the Jabberwock, my son!".to_vec());
        let context = b"context";

        for i in 0..messages.len() {
            let mut sig = [0u8; constants::SIGNATURE_LENGTH];
            let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
            let mut private_key = [0u8; constants::PRIVATE_KEY_LENGTH];
            generate_private_key(&mut private_key);

            std_sign(
                &mut sig,
                &mut public_key,
                &private_key,
                messages[i].as_ptr(),
                messages[i].len(),
                context.as_ptr(),
                context.len(),
            );
            sigs.push(sig.to_vec());
            public_keys.push(public_key.to_vec());
        }
        //alter a signature before batch verification
        sigs[3] = sigs[4].to_owned();

        let mut batch_sigs = SignatureBatch::new();
        batch_sigs.set_context(b"context".to_vec());
        batch_sigs.set_messages(RepeatedField::from_vec(messages));
        batch_sigs.set_signatures(RepeatedField::from_vec(sigs));
        batch_sigs.set_public_keys(RepeatedField::from_vec(public_keys));
        let batch = batch_sigs.write_to_bytes().unwrap();

        let result = verify_batch(batch.as_ptr(), batch.len());

        assert_eq!(result, ErrorCode::BATCH_VERIFICATION_FAILURE.value());
    }

    #[test]
    fn batch_verify_fails_on_incorrect_context() {
        let mut sigs: std::vec::Vec<Vec<u8>> = Vec::new();
        let mut public_keys: std::vec::Vec<Vec<u8>> = Vec::new();
        let mut messages = Vec::new();

        messages.push(b"'Twas brillig, and the slithy toves".to_vec());
        messages.push(b"Did gyre and gimble in the wabe:".to_vec());
        messages.push(b"All mimsy were the borogoves,".to_vec());
        messages.push(b"And the mome raths outgrabe.".to_vec());
        messages.push(b"'Beware the Jabberwock, my son!".to_vec());
        let context = b"context";

        for i in 0..messages.len() {
            let mut sig = [0u8; constants::SIGNATURE_LENGTH];
            let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
            let mut private_key = [0u8; constants::PRIVATE_KEY_LENGTH];
            generate_private_key(&mut private_key);

            std_sign(
                &mut sig,
                &mut public_key,
                &private_key,
                messages[i].as_ptr(),
                messages[i].len(),
                context.as_ptr(),
                context.len(),
            );
            sigs.push(sig.to_vec());
            public_keys.push(public_key.to_vec());
        }

        let mut batch_sigs = SignatureBatch::new();
        batch_sigs.set_context(b"context2".to_vec());
        batch_sigs.set_messages(RepeatedField::from_vec(messages));
        batch_sigs.set_signatures(RepeatedField::from_vec(sigs));
        batch_sigs.set_public_keys(RepeatedField::from_vec(public_keys));
        let batch = batch_sigs.write_to_bytes().unwrap();

        let result = verify_batch(batch.as_ptr(), batch.len());

        assert_eq!(result, ErrorCode::BATCH_VERIFICATION_FAILURE.value());
    }
}

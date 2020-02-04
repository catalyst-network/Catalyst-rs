use catalyst_common::std_signature::*;
use catalyst_common::constants::*;
pub use catalyst_protocol_sdk_rust::prelude::*;
pub use catalyst_protocol_sdk_rust::Cryptography::ErrorCode;



#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn can_create_signature() {
        let mut sig: [u8; SIGNATURE_LENGTH] = [0; SIGNATURE_LENGTH];
        let mut public_key: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
        let private_key: [u8; PRIVATE_KEY_LENGTH] = [0; PRIVATE_KEY_LENGTH];
        let message = b"message";
        let context = b"context";
        let result = sign(&mut sig, &mut public_key, &private_key, message, context);
        assert_eq!(result, ErrorCode::NO_ERROR.value());
    }

    #[test]
    fn can_sign_message_and_verify_signature() {
        let mut sig: [u8; SIGNATURE_LENGTH] = [0; SIGNATURE_LENGTH];
        let mut public_key: [u8; PRIVATE_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
        let private_key: [u8; PRIVATE_KEY_LENGTH] = [0; PRIVATE_KEY_LENGTH];

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
        let mut sig: [u8; SIGNATURE_LENGTH] = [0; SIGNATURE_LENGTH];
        let mut public_key: [u8; PRIVATE_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
        let private_key: [u8; PRIVATE_KEY_LENGTH] = [0; PRIVATE_KEY_LENGTH];

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

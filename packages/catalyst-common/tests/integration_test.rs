use catalyst_common::batch::*;
use catalyst_common::constants;
use catalyst_common::keys::*;
use catalyst_common::std_signature::*;
pub use catalyst_protocol_sdk_rust::prelude::*;
pub use catalyst_protocol_sdk_rust::Cryptography::{ErrorCode, SignatureBatch};
use protobuf::RepeatedField;
use rand::rngs::OsRng;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn can_create_signature() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];
        let message = b"message";
        let context = b"context";
        let result = sign(&mut sig, &mut public_key, &private_key, message, context);
        assert_eq!(result, ErrorCode::NO_ERROR.value());
    }

    #[test]
    fn can_sign_message_and_verify_signature() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];

        let message = b"message";
        let context = b"Context 1 2 3";
        sign(&mut sig, &mut public_key, &private_key, message, context);

        assert_eq!(
            verify(&sig, &public_key, message, context,),
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
        sign(&mut sig, &mut public_key, &private_key, message, context1);
        let verified = verify(&sig, &public_key, message, context2);
        assert_eq!(verified, ErrorCode::SIGNATURE_VERIFICATION_FAILURE.value())
    }

    #[test]
    fn signing_fails_for_context_length_exceeding_maximum() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];

        let message = b"message";
        let context = b"2hPB7lVGQHENtQLcfOoTnEjBHO5jg0zgyQYyrKHOxywDrDDfmyg0z9M9Q0hRRfPUV4fWvRGR9l48a3cXmFqBPneErN5GwzD28E3cLhDRNAdaNEpelPRDzN4w2dGaNWc4Jrc7TlVEbC5JQdfMgmtPkakmF3mPCU1YUFQArFUbQFQdFLHL2PByvyzdHaStkSgZbCz0zb9jCBO0vwx4J6YXvXFoc9urYREcR7uiFEVcrf6L2C2uUVOtWQUHRQyIRtmx";
        let result = sign(&mut sig, &mut public_key, &private_key, message, context);

        assert_eq!(result, ErrorCode::INVALID_CONTEXT_LENGTH.value())
    }

    #[test]
    fn verification_fails_for_invalid_public_key() {
        let mut sig = [0u8; constants::SIGNATURE_LENGTH];
        let mut public_key = [0u8; constants::PUBLIC_KEY_LENGTH];
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];

        let message = b"message";
        let context = b"Context 1 2 3";
        sign(&mut sig, &mut public_key, &private_key, message, context);
        public_key[constants::PUBLIC_KEY_LENGTH - 1] =
            public_key[constants::PUBLIC_KEY_LENGTH - 1].wrapping_add(1u8);
        let verified = verify(&sig, &public_key, message, context);
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
            verify(&sig, &public_key, &message, context,),
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
            sign(&mut sig, &mut public_key, &private_key, message, context,),
            ErrorCode::NO_ERROR.value()
        );

        assert_eq!(
            verify(&sig, &public_key, message, context,),
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
            generate_private_key(&mut private_key, &mut OsRng {});

            sign(
                &mut sig,
                &mut public_key,
                &private_key,
                &messages[i],
                context,
            );
            sigs.push(sig.to_vec());
            public_keys.push(public_key.to_vec());
        }

        let mut batch_sigs = SignatureBatch::new();
        batch_sigs.set_context(b"context".to_vec());
        batch_sigs.set_messages(RepeatedField::from_vec(messages));
        batch_sigs.set_signatures(RepeatedField::from_vec(sigs));
        batch_sigs.set_public_keys(RepeatedField::from_vec(public_keys));

        let result = verify_batch(&mut batch_sigs, &mut OsRng {});

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
            generate_private_key(&mut private_key, &mut OsRng {});

            sign(
                &mut sig,
                &mut public_key,
                &private_key,
                &messages[i],
                context,
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

        let result = verify_batch(&mut batch_sigs, &mut OsRng {});

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
            generate_private_key(&mut private_key, &mut OsRng {});

            sign(
                &mut sig,
                &mut public_key,
                &private_key,
                &messages[i],
                context,
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

        let result = verify_batch(&mut batch_sigs, &mut OsRng {});

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
            generate_private_key(&mut private_key, &mut OsRng {});

            sign(
                &mut sig,
                &mut public_key,
                &private_key,
                &messages[i],
                context,
            );
            sigs.push(sig.to_vec());
            public_keys.push(public_key.to_vec());
        }

        let mut batch_sigs = SignatureBatch::new();
        batch_sigs.set_context(b"context2".to_vec());
        batch_sigs.set_messages(RepeatedField::from_vec(messages));
        batch_sigs.set_signatures(RepeatedField::from_vec(sigs));
        batch_sigs.set_public_keys(RepeatedField::from_vec(public_keys));

        let result = verify_batch(&mut batch_sigs, &mut OsRng {});

        assert_eq!(result, ErrorCode::BATCH_VERIFICATION_FAILURE.value());
    }
}

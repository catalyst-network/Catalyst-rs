extern crate catalyst_protocol_sdk_rust;
extern crate catalystffi;

pub use catalyst_protocol_sdk_rust::prelude::*;
pub use catalyst_protocol_sdk_rust::Cryptography::{ErrorCode, SignatureBatch};
use catalystffi::{PublicKey, SecretKey, Keypair, Signature, Sha512, Digest};
use rand::thread_rng;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn can_use_lib_to_sign() {
        let mut csprng = thread_rng();
        let private: SecretKey = SecretKey::generate(&mut csprng);
        let public: PublicKey = (&private).into();
        let message = b"message";
        let context = b"context";
        let _sig = catalystffi::std_signature::sign(private, public, message, Some(context));
    }

    #[test]
    fn can_use_lib_to_verify() {
        let mut csprng = thread_rng();
        let private: SecretKey = SecretKey::generate(&mut csprng);
        let public: PublicKey = (&private).into();
        let message = b"message";
        let context = b"context";
        let sig = catalystffi::std_signature::sign(private, public, message, Some(context));
        let verified = catalystffi::std_signature::verify(sig, public, message, Some(context));
        assert_eq!(verified, ErrorCode::NO_ERROR.value())
    }

    #[test]
    fn lib_verification_can_fail() {
        let mut csprng = thread_rng();
        let private: SecretKey = SecretKey::generate(&mut csprng);
        let public: PublicKey = (&private).into();
        let message = b"message";
        let context1 = b"context1";
        let context2 = b"context2";
        let sig = catalystffi::std_signature::sign(private, public, message, Some(context1));
        let verified = catalystffi::std_signature::verify(sig, public, message, Some(context2));
        assert_eq!(verified, ErrorCode::SIGNATURE_VERIFICATION_FAILURE.value())
    }

    #[test]
    fn can_batch_verify() {
        let mut csprng = thread_rng();

        let messages: [&[u8]; 5] = [
            b"'Twas brillig, and the slithy toves",
            b"Did gyre and gimble in the wabe:",
            b"All mimsy were the borogoves,",
            b"And the mome raths outgrabe.",
            b"'Beware the Jabberwock, my son!", ];
        
        let context = b"any old context";
        let mut sig_batch = SignatureBatch::new();

        for i in 0..messages.len() {
            let secret = Keypair::generate(&mut csprng).secret;
            let public: PublicKey = (&secret).into();
            sig_batch.signatures.push(catalystffi::std_signature::sign(secret, public, messages[i], Some(context)).to_bytes().to_vec());
            sig_batch.public_keys.push(public.to_bytes().to_vec());
            sig_batch.messages.push(messages[i].to_vec());
        }
        sig_batch.set_context(context.to_vec());

        let batch = sig_batch.write_to_bytes().expect("could not write protobuff message to bytes");
        let result = catalystffi::ffi::batch_verify(batch.as_slice());
        assert_eq!(result, ErrorCode::NO_ERROR.value())
    }

    #[test]
    fn batch_verify_fails_with_incorrect_context() {
        let mut csprng = thread_rng();

        let messages: [&[u8]; 5] = [
            b"'Twas brillig, and the slithy toves",
            b"Did gyre and gimble in the wabe:",
            b"All mimsy were the borogoves,",
            b"And the mome raths outgrabe.",
            b"'Beware the Jabberwock, my son!", ];
        
        let context = b"any old context";
        let mut sig_batch = SignatureBatch::new();

        for i in 0..messages.len() {
            let secret = Keypair::generate(&mut csprng).secret;
            let public: PublicKey = (&secret).into();
            sig_batch.signatures.push(catalystffi::std_signature::sign(secret, public, messages[i], Some(context)).to_bytes().to_vec());
            sig_batch.public_keys.push(public.to_bytes().to_vec());
            sig_batch.messages.push(messages[i].to_vec());
        }
        sig_batch.set_context(b"incorrect context".to_vec());

        let batch = sig_batch.write_to_bytes().expect("could not write protobuff message to bytes");
        let result = catalystffi::ffi::batch_verify(batch.as_slice());
        assert_eq!(result, ErrorCode::BATCH_VERIFICATION_FAILURE.value())  
    }
}

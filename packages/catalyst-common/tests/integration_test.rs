/*extern crate catalyst_protocol_sdk_rust;
extern crate catalystffi;

pub use catalyst_protocol_sdk_rust::prelude::*;
pub use catalyst_protocol_sdk_rust::Cryptography::ErrorCode;
use catalystffi::{PublicKey, SecretKey};
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
}
*/

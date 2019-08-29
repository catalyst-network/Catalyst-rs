extern crate catalystffi;

use catalystffi::{SecretKey, PublicKey};
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
        let sig = catalystffi::std_signature::sign(private, public, message, Some(context));
        assert!(sig.is_ok())
    }

    #[test]
    fn can_use_lib_to_verify() {
        let mut csprng = thread_rng();
        let private: SecretKey = SecretKey::generate(&mut csprng);
        let public: PublicKey = (&private).into();
        let message = b"message";
        let context = b"context";
        let sig = catalystffi::std_signature::sign(private, public, message, Some(context)).unwrap();
        let verified = catalystffi::std_signature::verify(sig, public, message, Some(context));
        assert_eq!(verified.unwrap(), true)
    }

    #[test]
    fn lib_verification_can_fail() {
        let mut csprng = thread_rng();
        let private: SecretKey = SecretKey::generate(&mut csprng);
        let public: PublicKey = (&private).into();
        let message = b"message";
        let context1 = b"context1";
        let context2 = b"context2";
        let sig = catalystffi::std_signature::sign(private, public, message, Some(context1)).unwrap();
        let verified = catalystffi::std_signature::verify(sig, public, message, Some(context2));
        assert_eq!(verified.unwrap(), false)
    }




}

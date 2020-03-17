//! ed25519ph keys

use super::*;
use rand::{CryptoRng, RngCore};

pub fn publickey_from_private(
    out_publickey: &mut [u8; constants::PUBLIC_KEY_LENGTH],
    private_key: &[u8; constants::PRIVATE_KEY_LENGTH],
) -> i32 {
    let secret_key: SecretKey = match SecretKey::from_bytes(private_key) {
        Ok(secret_key) => secret_key,
        Err(_) => return ErrorCode::INVALID_PRIVATE_KEY.value(),
    };
    let public_key: PublicKey = (&secret_key).into();
    out_publickey.copy_from_slice(&public_key.to_bytes());
    ErrorCode::NO_ERROR.value()
}

pub fn validate_public_key(public_key: &[u8;constants::PUBLIC_KEY_LENGTH]) -> i32 {
    match PublicKey::from_bytes(public_key) {
        Ok(_public_key) => ErrorCode::NO_ERROR.value(),
        Err(_) => ErrorCode::INVALID_PUBLIC_KEY.value(),
    }
}

pub fn generate_private_key<T>(
    out_key: &mut [u8; constants::PRIVATE_KEY_LENGTH],
    mut csprng: &mut T,
) -> i32
where
    T: CryptoRng + RngCore,
{
    let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    out_key.copy_from_slice(&secret_key.to_bytes());
    ErrorCode::NO_ERROR.value()
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn can_generate_private_key() {
        let initial_key = [0u8; constants::PRIVATE_KEY_LENGTH];
        let mut private_key = Clone::clone(&initial_key);
        let mut csprng = OsRng {};
        assert_eq!(private_key, initial_key, "arrays should be the same");
        assert_eq!(
            generate_private_key(&mut private_key, &mut csprng),
            ErrorCode::NO_ERROR.value()
        );
        assert_ne!(
            private_key, initial_key,
            "key bytes should have been changed by generate_key function"
        );
    }

    #[test]
    fn can_get_public_key_from_private_key() {
        let private_key = [0u8; constants::PRIVATE_KEY_LENGTH];
        let mut out_publickey = [0u8; constants::PUBLIC_KEY_LENGTH];
        assert_eq!(
            publickey_from_private(&mut out_publickey, &private_key),
            ErrorCode::NO_ERROR.value()
        );
        let private_key: SecretKey =
            SecretKey::from_bytes(&private_key).expect("failed to create private key");
        let public_key: PublicKey = (&private_key).into();
        assert_eq!(out_publickey, public_key.to_bytes());
    }
}

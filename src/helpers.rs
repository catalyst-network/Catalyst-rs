//! Provides helper functions.


#[cfg(test)]
pub mod tests {
    use std::result;
    use crate::std_signature;
    use crate::keys;
    use crate::constants;

    type Result<T> = result::Result<T, failure::Error>;

    #[allow(unused_must_use)]
    pub fn get_signature_result_with_error() -> Result<bool> {
        let mut invalid_signature: [u8; constants::SIGNATURE_LENGTH] = [0; constants::SIGNATURE_LENGTH];
        invalid_signature[constants::SIGNATURE_LENGTH - 1] = 32;
        let mut private_key: [u8; constants::PRIVATE_KEY_LENGTH] = [0; constants::PRIVATE_KEY_LENGTH];
        let mut public_key: [u8; constants::PUBLIC_KEY_LENGTH] = [0; constants::PUBLIC_KEY_LENGTH];
        keys::generate_key(&mut private_key);
        keys::publickey_from_private(&mut public_key, &mut private_key);
        let message = String::from("Message text");
        let context = String::from("Context text");
        std_signature::unwrap_and_verify(&invalid_signature, &public_key, message.as_ptr(), message.len(), context.as_ptr(), context.len())
    }
}
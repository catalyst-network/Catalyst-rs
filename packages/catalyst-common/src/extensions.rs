use super::*;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Signature;

#[allow(non_snake_case)]
#[derive(Debug, Copy, Clone)]
pub struct SignatureExposed {
    pub(crate) R: CompressedEdwardsY,
    pub(crate) s: Scalar,
}

impl From<Signature> for SignatureExposed {
    fn from(sig: Signature) -> Self {
        unsafe { std::mem::transmute::<Signature, Self>(sig) }
    }
}

pub trait PublicKeyExt {
    fn to_decompressed_point(&self) -> EdwardsPoint;
}

impl PublicKeyExt for PublicKey {
    fn to_decompressed_point(&self) -> EdwardsPoint {
        let bytes = self.to_bytes();
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let compressed = CompressedEdwardsY(bits);
        compressed.decompress().unwrap()
    }
}

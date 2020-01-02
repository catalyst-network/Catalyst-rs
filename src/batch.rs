#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use super::*;

use core::iter::once;

use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::traits::VartimeMultiscalarMul;

pub use curve25519_dalek::digest::Digest;

use crate::rand::Rng;
use rand::thread_rng;

use ed25519_dalek::Sha512;
use catalyst_protocol_sdk_rust::Cryptography::ErrorCode;
use crate::extensions::SignatureExposed;

pub fn verify_batch(
    messages: &[&[u8]],
    signatures: &[Signature],
    public_keys: &[PublicKey],
    context: Option<&'static [u8]>,
) -> i32
{
    // Return an error code if any of the vectors are not the same size as the others.
    if signatures.len() != messages.len() ||
        signatures.len() != public_keys.len() ||
        public_keys.len() != messages.len() {
        return ErrorCode::SIGNATURE_VERIFICATION_FAILURE.value();
    }

    let ctx: &[u8] = context.unwrap_or(b"");
        debug_assert!(ctx.len() <= 255, "The context must not be longer than 255 octets.");

    let prehashed_messages : Vec<Sha512> = (0..messages.len()).map(|i| {
        let mut prehashed: Sha512 = Sha512::new();
        prehashed.input(&messages[i]);
        prehashed
    }).collect();

    let sigs: Vec<SignatureExposed> = signatures
        .iter()
        .map(|x| x.into())
        .collect();

    // Compute H(dom || R || A || H(M)) for each (signature, public_key, message) triplet
    let hrams: Vec<Scalar> = (0..signatures.len()).map(|i| {
        let mut h : Sha512 = Sha512::default();
        h.input(b"SigEd25519 no Ed25519 collisions");
        h.input(&[1]); // Ed25519ph
        h.input(&[ctx.len() as u8]);
        h.input(ctx);
        h.input(sigs[i].R.as_bytes());
        h.input(public_keys[i].as_bytes());
        h.input(&prehashed_messages[i].result().as_slice());
        Scalar::from_hash(h)
    }).collect();

    // Select a random 128-bit scalar for each signature.
    let zs: Vec<Scalar> = signatures
        .iter()
        .map(|_| Scalar::from(thread_rng().gen::<u128>()))
        .collect();


    // Compute the basepoint coefficient, ∑ s[i]z[i] (mod l)
    let B_coefficient: Scalar = sigs
        .iter()
        .map(|sig| sig.s)
        .zip(zs.iter())
        .map(|(s, z)| z * s)
        .sum();

    // Multiply each H(dom || R || A || H(M)) by the random value
    let zhrams = hrams.iter().zip(zs.iter()).map(|(hram, z)| hram * z);

    let Rs = sigs.iter().map(|sig| sig.R.decompress());
    let As = public_keys.iter().map(|pk| Some(pk.1));
    let B = once(Some(constants::ED25519_BASEPOINT_POINT));

    // Compute (-∑ z[i]s[i] (mod l)) B + ∑ z[i]R[i] + ∑ (z[i]H(dom || R || A || H(M))[i] (mod l)) A[i] = 0
    let id = EdwardsPoint::optional_multiscalar_mul(
        once(-B_coefficient).chain(zs.iter().cloned()).chain(zhrams),
        B.chain(Rs).chain(As),
    ).ok_or_else(|| return ErrorCode::SIGNATURE_VERIFICATION_FAILURE.value()).unwrap();

    if id.is_identity() {
        ErrorCode::NO_ERROR.value()
    } else {
        ErrorCode::SIGNATURE_VERIFICATION_FAILURE.value()
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn can_run_test() {
        let b = true;
    }

}
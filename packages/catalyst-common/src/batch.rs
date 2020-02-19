use super::*;

use core::iter::once;

use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use crate::extensions::{SignatureExposed, PublicKeyExt};
use rand::Rng;

use std::slice;


use ed25519_dalek::{Sha512, Digest, Signature};
use catalyst_protocol_sdk_rust::Cryptography::{ErrorCode, SignatureBatch};
use rand::{CryptoRng, RngCore};

#[allow(non_snake_case)]
pub(crate) fn verify_batch<T>(
    messages: &[Vec<u8>],
    sigs: &[SignatureExposed],
    public_keys: &[PublicKey],
    context: Option<&'static [u8]>,
    csprng : &mut T,
) -> i32
where 
    T: CryptoRng + RngCore, 
{
    // Return an error code if any of the vectors are not the same size as the others.
    if sigs.len() != messages.len() ||
        sigs.len() != public_keys.len() ||
        public_keys.len() != messages.len() {
        return ErrorCode::ARRAYS_NOT_EQUAL_LENGTH.value();
    }

    let ctx: &[u8] = context.unwrap_or(b"");
        debug_assert!(ctx.len() <= 255, "The context must not be longer than 255 octets.");

    let mut common_hash: Sha512 = Sha512::new();
    common_hash.input(b"SigEd25519 no Ed25519 collisions");
    common_hash.input(&[1]); // Ed25519ph
    common_hash.input(&[ctx.len() as u8]);
    common_hash.input(ctx);

    // Compute H(dom || R || A || H(M)) for each (signature, public_key, message) triplet
    let hrams: Vec<Scalar> = (0..messages.len()).map(|i| {
        let mut h : Sha512 = common_hash.clone();
        h.input(sigs[i].R.as_bytes());
        h.input(public_keys[i].as_bytes());
        h.input(Sha512::digest(&messages[i]).as_slice());
        Scalar::from_hash(h)
    }).collect();

    // Select a random 128-bit scalar for each signature.
    let zs: Vec<Scalar> = sigs
        .iter()
        .map(|_| Scalar::from(csprng.gen::<u128>()))
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
    let As = public_keys.iter().map(|pk| Some(pk.to_decompressed_point()));
    let B = once(Some(constants::ED25519_BASEPOINT_POINT));

    // Compute (-∑ z[i]s[i] (mod l)) B + ∑ z[i]R[i] + ∑ (z[i]H(dom || R || A || H(M))[i] (mod l)) A[i] = 0
    let id = EdwardsPoint::optional_multiscalar_mul(
        once(-B_coefficient).chain(zs.iter().cloned()).chain(zhrams),
        B.chain(Rs).chain(As),
    ).ok_or_else(|| return ErrorCode::BATCH_VERIFICATION_FAILURE.value()).unwrap();

    if id.is_identity() {
        ErrorCode::NO_ERROR.value()
    } else {
        ErrorCode::BATCH_VERIFICATION_FAILURE.value()
    }
}

pub(crate) fn unwrap_and_verify_batch<T>(batch_sigs : &mut SignatureBatch, mut csprng : &mut T) -> i32
where 
    T: CryptoRng + RngCore, 
{
    let sigs = batch_sigs.take_signatures().iter().map(|x| Signature::from_bytes(&x).expect("not decoding sigs").into()).collect::<Vec<SignatureExposed>>();
    if sigs.len() <=0 
    {
        return ErrorCode::INVALID_SIGNATURE.value();
    }
    let pks = batch_sigs.take_public_keys().iter().map(|x| PublicKey::from_bytes(&x).unwrap()).collect::<Vec<PublicKey>>();
    
    let context_vec = batch_sigs.take_context();

    let context = unsafe { slice::from_raw_parts(context_vec.as_ptr(), context_vec.len()) };
    verify_batch(batch_sigs.messages.as_slice(), sigs.as_slice(), pks.as_slice(), Some(context), &mut csprng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn batch_verify_validates_multiple_correct_signatures() {
        let mut csprng = OsRng{};
        let messages: [Vec<u8>;5] = [
            b"'Twas brillig, and the slithy toves".to_vec(),
            b"Did gyre and gimble in the wabe:".to_vec(),
            b"All mimsy were the borogoves,".to_vec(),
            b"And the mome raths outgrabe.".to_vec(),
            b"'Beware the Jabberwock, my son!".to_vec(), ];
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<SignatureExposed> = Vec::new();
        let context = b"any old context";

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            let mut h = Sha512::default();
            h.input(&messages[i]);
            signatures.push(keypair.sign_prehashed(h, Some(context)).into());
            keypairs.push(keypair);
        }

        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();       

        let result = verify_batch(&messages, &signatures.as_slice(), &public_keys, Some(context), &mut csprng);

        assert_eq!(result, ErrorCode::NO_ERROR.value());
    }

    #[test]
    fn batch_verify_fails_on_single_incorrect_message() {
        let mut csprng = OsRng{};
        let mut messages: [Vec<u8>;5] = [
            b"'Twas brillig, and the slithy toves".to_vec(),
            b"Did gyre and gimble in the wabe:".to_vec(),
            b"All mimsy were the borogoves,".to_vec(),
            b"And the mome raths outgrabe.".to_vec(),
            b"'Beware the Jabberwock, my son!".to_vec(), ];
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<SignatureExposed> = Vec::new();
        let context = b"any old context";

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            let mut h = Sha512::default();
            h.input(&messages[i]);
            signatures.push(keypair.sign_prehashed(h, Some(context)).into());
            keypairs.push(keypair);
        }
        //alter a message before batch verification
        messages[4] = b"The jaws that bite, the claws that catch!".to_vec();

        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
        
        let result = verify_batch(&messages, &signatures, &public_keys, Some(context), &mut csprng);

        assert_eq!(result, ErrorCode::BATCH_VERIFICATION_FAILURE.value());
    }

    #[test]
    fn batch_verify_fails_on_single_incorrect_signature() {
        let mut csprng = OsRng{};
        let messages: [Vec<u8>;5] = [
            b"'Twas brillig, and the slithy toves".to_vec(),
            b"Did gyre and gimble in the wabe:".to_vec(),
            b"All mimsy were the borogoves,".to_vec(),
            b"And the mome raths outgrabe.".to_vec(),
            b"'Beware the Jabberwock, my son!".to_vec(), ];
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<SignatureExposed> = Vec::new();
        let context = b"any old context";

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            let mut h = Sha512::default();
            h.input(&messages[i]);
            signatures.push(keypair.sign_prehashed(h, Some(context)).into());
            keypairs.push(keypair);
        }
        //alter a signature before batch verification
        signatures[3] = signatures[4];

        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
        
        let result = verify_batch(&messages, &signatures, &public_keys, Some(context), &mut csprng);

        assert_eq!(result, ErrorCode::BATCH_VERIFICATION_FAILURE.value());
    }

    #[test]
    fn batch_verify_fails_on_incorrect_context() {
        let mut csprng = OsRng{};
        let messages: [Vec<u8>;5] = [
            b"'Twas brillig, and the slithy toves".to_vec(),
            b"Did gyre and gimble in the wabe:".to_vec(),
            b"All mimsy were the borogoves,".to_vec(),
            b"And the mome raths outgrabe.".to_vec(),
            b"'Beware the Jabberwock, my son!".to_vec(), ];
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<SignatureExposed> = Vec::new();
        let context = b"any old context";

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            let mut h = Sha512::default();
            h.input(&messages[i]);
            signatures.push(keypair.sign_prehashed(h, Some(context)).into());
            keypairs.push(keypair);
        }

        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
        
        let result = verify_batch(&messages, signatures.as_slice(), &public_keys, Some(b"a different context"), &mut csprng);

        assert_eq!(result, ErrorCode::BATCH_VERIFICATION_FAILURE.value());
    }
}

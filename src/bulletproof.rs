use std::slice;
use std::result;
use failure;

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

use crate::constants;
use lazy_static::lazy_static;

lazy_static! {
    
    // Generators for Pedersen commitments.
    pub static ref PC_GENS : PedersenGens = PedersenGens::default();
}

type Result<T> = result::Result<T, failure::Error>;

pub fn create_bulletproof(secret_value: u64, blinding: &Scalar) -> Result<RangeProof>{

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(constants::BULLETPROOF_N, 1);

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"doctest example");

    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &PC_GENS,
        &mut prover_transcript,
        secret_value,
        blinding,
        constants::BULLETPROOF_N,
    )?;
    Ok(proof)
}

pub fn verify_bulletprooofs(){
    // Verification requires a transcript with identical initial state:
    //let mut verifier_transcript = Transcript::new(b"doctest example");
    //assert!(
        //proof
            //.verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 32)
            //.is_ok()
    //);
}

pub(crate) fn unwrap_and_bulletproof(out_rangeproof: &mut [u8;constants::BULLETPROOF_SIZE],
                         secret_value: u64, 
                         blinding: &[u8;32], 
                         context: *const u8, 
                         context_length: usize) -> Result<()> {
    let context = unsafe {
        assert!(!context.is_null());
        slice::from_raw_parts(context, context_length)
    };

    let blinding = Scalar::from_bits(*blinding);

    let rangeproof = create_bulletproof(secret_value, &blinding)?;

    out_rangeproof.copy_from_slice(&rangeproof.to_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn can_create_bulletproof(){
        let blinding = Scalar::random(&mut thread_rng());
        create_bulletproof(1037578891u64, &blinding);
    }

    #[test]
    fn can_get_bulletproof_size(){
        assert!(constants::BULLETPROOF_SIZE > 0)
    }
}
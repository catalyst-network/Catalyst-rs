use crate::custom_errors;

pub const SIGNATURE_ERROR : i32 = 101;

pub const CONTEXT_LENGTH_ERROR: i32 = 201;

pub const BULLETPROOF_INVALID_BITSIZE_ERROR: i32 = 301;

pub const UNKNOWN_ERROR : i32 = -1;


/// Retrieve error code corresponding to error type.
pub(crate) fn get_error_code(err : &failure::Error ) -> i32 {
    /*println!("{}", err.as_fail());
    if let Some(_) = err.downcast_ref::<ed25519_dalek::SignatureError>() {
        return SIGNATURE_ERROR;
    }
    if let Some(_) = err.downcast_ref::<custom_errors::ContextLengthError>() {
        return CONTEXT_LENGTH_ERROR;
    }
    if let Some(e) = err.downcast_ref::<bulletproofs::ProofError>() {
        match e {
            bulletproofs::ProofError::InvalidBitsize => return BULLETPROOF_INVALID_BITSIZE_ERROR}
        }
    */
    else {return UNKNOWN_ERROR;}
}
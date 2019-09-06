use crate::constants;
use failure::{Fail};
use std::fmt;

#[derive(Fail, Debug)]
pub struct ContextLengthError;

impl fmt::Display for ContextLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "The context length should be less than {} bytes.", constants::CONTEXT_MAX_LENGTH)
    }
}
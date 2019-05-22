use std::io::Read;
use reqwest::{self, StatusCode};

use crate::errors::*;


#[derive(Debug, Clone)]
pub struct Response {
    pub body: Vec<u8>,
    pub status: StatusCode,
}

impl Response {
    pub(crate) fn from_reqwest(original: reqwest::Response) -> Result<Response> {
        let mut original = original.error_for_status()?;
        let status = original.status();

        let mut body = Vec::new();
        original
            .read_to_end(&mut body)
            .chain_err(|| "Unable to read the response body")?;

        Ok(Response {
            status,
            body,
        })
    }
}
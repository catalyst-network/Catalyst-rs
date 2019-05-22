use reqwest::{self, Method, Url};


/// A HTTP request.
#[derive(Debug, Clone)]
pub struct Request {
    pub destination: Url,
    pub method: Method,
    pub body: Option<Vec<u8>>,
}


impl Request {
    pub fn new(destination: Url, method: Method) -> Request {
        let body = None;

        Request {
            destination,
            method,
            body,
        }
    }
}

impl Request {
    pub(crate) fn to_reqwest(&self) -> reqwest::Request {
        let mut r = reqwest::Request::new(self.method.clone(), self.destination.clone());

        r
    }
}
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct MyError {
    pub message: String,
}

impl MyError {
    pub const fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for MyError {}

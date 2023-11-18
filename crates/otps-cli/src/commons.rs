use std::fmt::Display;

pub const WORKING_DIR: &str = env!("HOME");

pub const WORKING_FILENAME: &str = ".otps";

#[derive(Clone, PartialEq, Debug)]
pub enum ClientType {
    Hotp,
    Totp,
}

impl Display for ClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientType::Hotp => write!(f, "hotp"),
            ClientType::Totp => write!(f, "totp"),
        }
    }
}

impl From<&str> for ClientType {
    fn from(value: &str) -> Self {
        match value {
            "hotp" => ClientType::Hotp,
            "totp" => ClientType::Totp,
            _ => unreachable!("ClientType exception: {} isn't a valid value", value),
        }
    }
}

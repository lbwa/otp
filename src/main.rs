use crate::{hotp::HOTP, totp::TOTP};
use base32::{decode, Alphabet};
use ring::hmac::{Key, HMAC_SHA1_FOR_LEGACY_USE_ONLY};

mod hotp;
mod totp;

pub fn main() {
    // Generally, secret (AKA, setup key) is a base32 string which should be decoded before hashed
    let base32_secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let decoded_secret = decode(Alphabet::RFC4648 { padding: false }, base32_secret.as_ref())
        .expect("failed to decode base32 secret");
    // use SHA-1 algorithm to encode secret by default
    let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &decoded_secret);

    let mut hotp = HOTP::new(0);
    let hotp_code = hotp.generate(&key);
    println!("HOTP: {}", hotp_code);

    let mut totp = TOTP::new();
    let totp_code = totp.generate(&key);
    println!("TOTP: {}", totp_code);
}

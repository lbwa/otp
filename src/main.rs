use base32::{decode, Alphabet};
use ring::hmac::{sign, Key, Tag, HMAC_SHA1_FOR_LEGACY_USE_ONLY};
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of digits in an HOTP value; system parameter
const OTP_DIGITS: usize = 6;
/// 30 seconds by default, see https://datatracker.ietf.org/doc/html/rfc6238#section-4.1
const TOTP_PERIOD: u64 = 30u64;

/// It converts an HMAC-SHA-1 value into an HOTP value as define in [RFC 4226 - Section 5.3](https://datatracker.ietf.org/doc/html/rfc4226#section-5.3)
fn truncated_hash(hmac: &Tag) -> u32 {
    let hashed_tag = hmac.as_ref();
    let offset = (hashed_tag[hashed_tag.len() - 1 /* 19 */] as usize) & 0xf;
    let bin_code: u32 = (((hashed_tag[offset] & 0x7f) as u32) << 24)
        | (((hashed_tag[offset + 1] & 0xff) as u32) << 16)
        | (((hashed_tag[offset + 2] & 0xff) as u32) << 8)
        | (hashed_tag[offset + 3] & 0xff) as u32;
    bin_code % 10u32.pow(OTP_DIGITS as u32)
}

/// HMAC-based one-time password
///
/// - RFC 4226: <https://datatracker.ietf.org/doc/html/rfc4226>
/// - Generating an HOTP value: <https://datatracker.ietf.org/doc/html/rfc4226#section-5.3>
fn generate_hotp(key: &Key, counter: u64) -> String {
    let counter_bytes = counter.to_be_bytes();
    let hash = sign(key, &counter_bytes);
    let code = truncated_hash(&hash);
    format!("{:0>width$}", code, width = OTP_DIGITS)
}

/// Time-based one-time password is based on HTOP algorithm, and use current system time as counter
///
/// - RFC 6238: <https://datatracker.ietf.org/doc/html/rfc6238>
/// - wiki: <https://en.wikipedia.org/wiki/Time-based_one-time_password>
fn generate_totp(key: &Key) -> String {
    let counter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / TOTP_PERIOD;

    generate_hotp(key, counter)
}

pub fn main() {
    // Generally, secret (AKA, setup key) is a base32 string which should be decoded before hashed
    let base32_secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let decoded_secret = decode(Alphabet::RFC4648 { padding: false }, base32_secret.as_ref())
        .expect("failed to decode base32 secret");
    // use SHA-1 algorithm to encode secret by default
    let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &decoded_secret);
    let counter = 0;

    let hopt = generate_hotp(&key, counter);
    let totp = generate_totp(&key);

    println!("HOTP: {}", hopt);
    println!("TOTP: {}", totp)
}

#[test]
fn test_hotp() {
    let secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let decoded_secret = decode(Alphabet::RFC4648 { padding: false }, secret.as_ref())
        .expect("failed to decode secret");
    let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &decoded_secret);

    assert_eq!(generate_hotp(&key, 0), "679988")
}

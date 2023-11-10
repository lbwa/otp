use ring::hmac::{sign, Key, Tag, HMAC_SHA1_FOR_LEGACY_USE_ONLY};
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of digits in an HOTP value; system parameter
const DIGIT: usize = 6;
/// https://datatracker.ietf.org/doc/html/rfc6238#section-4.1
const TOTP_PERIOD: u64 = 30; // seconds

/// It converts an HMAC-SHA-1 value into an HOTP value as define in [RFC 4226 - Section 5.3](https://datatracker.ietf.org/doc/html/rfc4226#section-5.3)
fn truncated_hash(hmac: &Tag) -> u32 {
    let hash = hmac.as_ref();
    let offset = (hash[hash.len() - 1 /* 19 */] as usize) & 0xf;
    let bin_code: u32 = ((hash[offset] & 0x7f) as u32) << 24
        | ((hash[offset + 1] & 0xff) as u32) << 16
        | ((hash[offset + 2] & 0xff) as u32) << 8
        | (hash[offset + 3] & 0xff) as u32;
    bin_code % 10u32.pow(DIGIT as u32)
}

/// HMAC-based one-time password
///
/// - RFC 4226: <https://datatracker.ietf.org/doc/html/rfc4226>
/// - Generating an HOTP value: <https://datatracker.ietf.org/doc/html/rfc4226#section-5.3>
fn generate_hotp(key: &Key, counter: u64) -> String {
    let counter_bytes: [u8; 8] = counter.to_be_bytes();
    let hash = sign(key, &counter_bytes);
    let code = truncated_hash(&hash);
    format!("{:0>width$}", code, width = DIGIT)
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
    let secret = "THIS_IS_A_SECRET_KEY_STRING";
    // use SHA-1 algorithm to encode secret string by default
    let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret.as_bytes());
    let counter = 0;

    let hopt = generate_hotp(&key, counter);
    let totp = generate_totp(&key);

    println!("HOTP: {}\nTOTP: {}", hopt, totp);
}

#[test]
fn test_hotp() {
    let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, b"hello world");

    assert_eq!(generate_hotp(&key, 12345), "025489")
}

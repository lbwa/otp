use ring::hmac::{sign, Key, Tag};
use std::ops::Add;

/// Number of digits in an HOTP value; system parameter
const OTP_DIGITS: usize = 6;

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
#[derive(Default, Debug)]
pub struct HOTP<Counter: Add>(Counter);

impl HOTP<u64> {
    pub fn new(initial_counter: u64) -> Self {
        Self(initial_counter)
    }

    pub fn generate(&mut self, key: &Key) -> String {
        let HOTP(counter) = self;
        let counter_bytes = counter.to_be_bytes();
        let hash = sign(key, &counter_bytes);
        let code = truncated_hash(&hash);
        *counter += 1;
        format!("{:0>width$}", code, width = OTP_DIGITS)
    }
}

#[test]
fn test_generate() {
    let mut hotp = HOTP::new(0);
    let key = Key::new(
        ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        b"12345678901234567890",
    );
    let code = hotp.generate(&key);
    assert_eq!(code, "755224");
    let HOTP(counter) = hotp;
    assert_eq!(counter, 1);

    let code = hotp.generate(&key);
    assert_eq!(code, "287082");
    let HOTP(counter) = hotp;
    assert_eq!(counter, 2);
}

#[test]
fn test_generate_with_base32_secret() {
    use base32::{decode, Alphabet};
    use ring::hmac::{Key, HMAC_SHA1_FOR_LEGACY_USE_ONLY};

    let secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let decoded_secret = decode(Alphabet::RFC4648 { padding: false }, secret.as_ref())
        .expect("failed to decode secret");
    let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &decoded_secret);

    let mut hotp = HOTP::new(0);
    assert_eq!(hotp.generate(&key), "679988")
}

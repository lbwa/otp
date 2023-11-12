use derive_builder::Builder;
use ring::{
    constant_time::verify_slices_are_equal,
    hmac::{sign, Key, Tag, HMAC_SHA1_FOR_LEGACY_USE_ONLY},
};

use crate::otp::secret_encoding;

/// Number of digits in an HOTP value; system parameter
const OTP_DIGITS: usize = 6;

/// It converts an HMAC-SHA-1 value into an HOTP value as define in [RFC 4226 - Section 5.3](https://datatracker.ietf.org/doc/html/rfc4226#section-5.3)
fn truncated_hash(hmac: &Tag) -> u32 {
    let hmac_result = hmac.as_ref();
    let offset = (hmac_result[hmac_result.len() - 1 /* 19 */] as usize) & 0xf;
    let bin_code: u32 = (((hmac_result[offset] & 0x7f) as u32) << 24)
        | (((hmac_result[offset + 1] & 0xff) as u32) << 16)
        | (((hmac_result[offset + 2] & 0xff) as u32) << 8)
        | (hmac_result[offset + 3] & 0xff) as u32;
    bin_code % 10u32.pow(OTP_DIGITS as u32)
}

/// HMAC-based one-time password
///
/// - RFC 4226: <https://datatracker.ietf.org/doc/html/rfc4226>
/// - Generating an HOTP value: <https://datatracker.ietf.org/doc/html/rfc4226#section-5.3>
#[derive(Default, Debug, Builder)]
pub struct HOTP {
    #[builder(default)]
    counter: u64,
    #[builder(default)]
    key: Vec<u8>,
}

impl HOTPBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    secret_encoding!(Self);
}

impl HOTP {
    pub fn increment_counter(&mut self) -> &mut Self {
        let HOTP { counter, .. } = self;
        *counter += 1;
        self
    }

    pub fn generate(&self) -> String {
        let hash_key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.key);
        let HOTP { counter, .. } = self;
        let counter_bytes = counter.to_be_bytes();
        let hashed_tag = sign(&hash_key, &counter_bytes);
        let code: u32 = truncated_hash(&hashed_tag);
        format!("{:0>width$}", code, width = OTP_DIGITS)
    }

    pub fn validate(&self, code: &str) -> bool {
        if code.len() != OTP_DIGITS {
            return false;
        }

        let hashed_tag = sign(
            &Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.key),
            code.as_bytes(),
        );

        let ref_code = self.generate().into_bytes();
        let hashed_ref_tag = sign(
            &Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.key),
            &ref_code,
        );

        verify_slices_are_equal(hashed_tag.as_ref(), hashed_ref_tag.as_ref())
            .map(|_| true)
            .unwrap_or(false)
    }
}

#[test]
fn test_generate() {
    let mut hotp = HOTPBuilder::new()
        .base32_secret("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        .build()
        .unwrap();

    for _ in 0..2 {
        assert_eq!(hotp.generate(), "679988")
    }

    assert!(!hotp.validate("123456"));
    assert!(hotp.validate("679988"));

    hotp.increment_counter();

    for _ in 0..2 {
        assert_ne!(hotp.generate(), "679988");
        assert_eq!(hotp.generate(), "983918");
    }

    let mut hotp = HOTPBuilder::new()
        .base32_secret("12345678901234567890")
        .build()
        .expect("failed to initialize HOTP client");

    for _ in 0..2 {
        assert_eq!(hotp.generate(), "755224");
    }

    hotp.increment_counter();

    for _ in 0..2 {
        assert_eq!(hotp.generate(), "287082");
    }
}

use crate::{hotp::HOTPBuilder, otp::secret_encoding};
use derive_builder::Builder;
use std::time::{SystemTime, UNIX_EPOCH};

/// 30 seconds by default, see https://datatracker.ietf.org/doc/html/rfc6238#section-4.1
const TOTP_PERIOD: u64 = 30u64;

/// Time-based one-time password is based on HTOP algorithm, and use current system time as counter
///
/// - RFC 6238: <https://datatracker.ietf.org/doc/html/rfc6238>
/// - wiki: <https://en.wikipedia.org/wiki/Time-based_one-time_password>
#[derive(Default, Debug, Builder)]
pub struct TOTP {
    key: Vec<u8>,
}

impl TOTPBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    secret_encoding!(Self);
}

impl TOTP {
    pub fn generate(&mut self) -> String {
        let hotp_client = HOTPBuilder::new()
            .key(self.key.to_owned())
            .counter(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    / TOTP_PERIOD,
            )
            .build()
            .expect("failed to initialization");

        hotp_client.generate()
    }
}

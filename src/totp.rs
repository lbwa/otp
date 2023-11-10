use crate::hotp::HOTP;
use ring::hmac::Key;
use std::time::SystemTime;

/// 30 seconds by default, see https://datatracker.ietf.org/doc/html/rfc6238#section-4.1
const TOTP_PERIOD: u64 = 30u64;

/// Time-based one-time password is based on HTOP algorithm, and use current system time as counter
///
/// - RFC 6238: <https://datatracker.ietf.org/doc/html/rfc6238>
/// - wiki: <https://en.wikipedia.org/wiki/Time-based_one-time_password>
#[derive(Default, Debug)]
pub struct TOTP;

impl TOTP {
    pub fn new() -> Self {
        Self {}
    }

    pub fn generate(&mut self, key: &Key) -> String {
        let mut hotp = HOTP::new(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / TOTP_PERIOD,
        );
        hotp.generate(key)
    }
}

//!
//! This package is a library designed to provide out-of-box HOTP and TOTP clients to generate one-time passwords.
//!
//! ## HOTP
//!
//! work with base32 secret string:
//!
//! ```
//! use otps::HotpBuilder;
//!
//! let mut hotp_client = HotpBuilder::new()
//!   .base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
//!   .build()
//!   .expect("failed to initialize HOTP client");
//!
//! assert_eq!(hotp_client.generate(), "755224");
//!
//! hotp_client.increment_counter();
//! assert_eq!(hotp_client.generate(), "287082");
//! ```
//! If secret string isn't base32 encoding, you should use `.key(secret_string.as_bytes().to_owned())` instead of `.base32_secret` method.
//!
//! ## TOTP
//!
//! work with base32 secret string:
//!
//! ```
//! use otps::TotpBuilder;
//! let mut totp_cleint = TotpBuilder::new()
//!   .base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
//!   .build()
//!   .expect("failed to initialize TOTP client");
//! let totp_code = totp_cleint.generate();
//! println!("TOTP: {}", totp_code);
//! ```
//! If secret string isn't base32 encoding, you should use `.key(secret_string.as_bytes().to_owned())` instead of `.base32_secret` method.

mod hotp;
mod otp;
mod totp;

pub use hotp::HotpBuilder;
pub use totp::TotpBuilder;

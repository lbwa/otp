//!
//! Out-of-box HOTP and TOTP client to generate one-time password.
//!
//! ## HOTP
//!
//! ```
//! use otpauth::HOTPBuilder;
//!
//! let mut hotp_client = HOTPBuilder::new()
//!   .base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
//!   .build()
//!   .expect("failed to initialize HOTP client");
//!
//! assert_eq!(hotp_client.generate(), "755224");
//!
//! hotp_client.increment_counter();
//! assert_eq!(hotp_client.generate(), "287082");
//! ```
//!
//! ## TOTP
//!
//! ```
//! use otpauth::TOTPBuilder;
//! let mut totp_cleint = TOTPBuilder::new()
//!   .base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
//!   .build()
//!   .expect("failed to initialize TOTP client");
//! let totp_code = totp_cleint.generate();
//! ```

mod hotp;
mod otp;
mod totp;

pub use hotp::HOTPBuilder;
pub use totp::TOTPBuilder;

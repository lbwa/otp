//!
//! Out-of-box HOTP and TOTP client to generate one-time password.
//!
//! ## HOTP
//!
//! ```
//! use otpauth::HotpBuilder;
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
//!
//! ## TOTP
//!
//! ```
//! use otpauth::TotpBuilder;
//! let mut totp_cleint = TotpBuilder::new()
//!   .base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
//!   .build()
//!   .expect("failed to initialize TOTP client");
//! let totp_code = totp_cleint.generate();
//! ```

mod hotp;
mod otp;
mod totp;

pub use hotp::HotpBuilder;
pub use totp::TotpBuilder;

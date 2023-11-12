# otpauth

[![tests_status](https://github.com/lbwa/otp/actions/workflows/tests.yml/badge.svg)](https://github.com/lbwa/otp/actions/workflows/tests.yml)

This package is a library designed to provide out-of-box HOTP and TOTP clients to generate one-time passwords.

## Usage

```bash
cargo add otpauth
```

```rs
use otpuath::TOTPBuilder;

let mut totp_cleint = TOTPBuilder::new()
    .base32_secret(base32_secret)
    .build()
    .expect("failed to initialize TOTP client");

let totp_code = totp_cleint.generate();
println!("TOTP: {}", totp_code);
```
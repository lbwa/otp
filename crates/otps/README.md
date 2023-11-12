# otps

[![Crates.io](https://img.shields.io/crates/v/otps?style=flat-square)](https://crates.io/crates/otps) [![Tests status](https://github.com/lbwa/otp/actions/workflows/tests.yml/badge.svg)](https://github.com/lbwa/otp/actions/workflows/tests.yml) [![docs.rs](https://img.shields.io/docsrs/otps?style=flat-square)](https://docs.rs/otps/latest/otps/)

This package is a library designed to provide out-of-box HOTP and TOTP clients to generate one-time passwords.

## Features

- HOTP and TOTP implementations are based on [RFC4226](https://datatracker.ietf.org/doc/html/rfc4226) and [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)
- Built-in base32 secret decoding

## Installation

```bash
cargo add otps
```

## Getting started

```rs
use otps::TotpBuilder;

let mut totp_cleint = TotpBuilder::new()
  .base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
  .build()
  .expect("failed to initialize TOTP client");

let totp_code = totp_cleint.generate();

println!("TOTP: {}", totp_code); // 123456
```

For more examples and detailed usage, refer to the [online documentation](https://docs.rs/otps/latest/otps/).

## Contributions

Contributions to this project are welcome and encouraged. If you encounter any bugs or issues, please open an issue on the [GitHub](https://github.com/lbwa/otp) repository. If you would like to contribute to the project, please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/lbwa/otp/blob/main/LICENSE) file for more details.
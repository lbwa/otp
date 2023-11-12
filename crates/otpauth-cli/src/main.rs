use otpauth::{HotpBuilder, TotpBuilder};

pub fn main() {
    let base32_secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    let hotp_client = HotpBuilder::new()
        .base32_secret(base32_secret)
        .build()
        .expect("failed to initialize HOTP client");

    let hotp_code = hotp_client.generate();
    println!("HOTP: {}", hotp_code);

    let mut totp_cleint = TotpBuilder::new()
        .base32_secret(base32_secret)
        .build()
        .expect("failed to initialize TOTP client");

    let totp_code = totp_cleint.generate();
    println!("TOTP: {}", totp_code);
}

macro_rules! secret_encoding {
    ($t:ty) => {
        pub fn base32_secret(&mut self, secret: &str) -> &mut $t {
            use base32::{decode, Alphabet};

            self.key =
                if let Some(decoded_key) = decode(Alphabet::RFC4648 { padding: false }, secret) {
                    Some(decoded_key)
                } else {
                    panic!(
                        "The secret({:?}) isn't a valid base32 encoding string. replace .base32_secret(secret) with .key(secret) or check the secret encoding to continue.",
                        secret
                    );
                };
            self
        }
    };
}

pub(crate) use secret_encoding;

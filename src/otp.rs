macro_rules! secret_encoding {
    ($t:ty) => {
        pub fn base32_secret(&mut self, secret: &str) -> &mut $t {
            use base32::{decode, Alphabet};

            self.key =
                if let Some(decoded_key) = decode(Alphabet::RFC4648 { padding: false }, secret) {
                    Some(decoded_key)
                } else {
                    Some(vec![])
                };
            self
        }
    };
}

pub(crate) use secret_encoding;

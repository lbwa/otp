use crate::commons::ClientType;

#[derive(Debug, Clone)]
pub struct Key {
    pub(crate) name: String,
    pub(crate) r#type: ClientType,
    pub(crate) secret: String,
    pub(crate) counter: Option<u64>,
}

impl Key {
    pub fn get_client_type(&self) -> &ClientType {
        &self.r#type
    }

    pub fn get_secret(&self) -> &str {
        &self.secret
    }

    pub fn get_counter(&self) -> Option<u64> {
        self.counter
    }
}

impl From<&str> for Key {
    fn from(value: &str) -> Self {
        let data = value.split_whitespace().collect::<Vec<&str>>();
        if data.len() < 4 || data[0].is_empty() || data[2].is_empty() {
            panic!("Type case exception");
        }

        match data[3].into() {
            ClientType::Hotp => {
                let (name, secret, counter) = (data[0], data[2], data[4]);
                Key {
                    name: name.to_owned(),
                    r#type: ClientType::Hotp,
                    secret: secret.to_owned(),
                    counter: Some(counter.parse().ok().unwrap_or_default()),
                }
            }
            ClientType::Totp => {
                let (name, secret) = (data[0], data[2]);
                Key {
                    name: name.to_owned(),
                    r#type: ClientType::Totp,
                    secret: secret.to_owned(),
                    counter: None,
                }
            }
        }
    }
}

impl From<Key> for String {
    fn from(value: Key) -> Self {
        let Key {
            name,
            r#type,
            secret,
            counter,
        } = value;

        let base = format!("{} {} {} {}", name, 6, secret, r#type);
        if let Some(initial_counter) = counter {
            base + &format!(" {}", initial_counter)
        } else {
            format!("{}\n", base)
        }
    }
}

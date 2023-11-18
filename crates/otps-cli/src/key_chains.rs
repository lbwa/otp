use crate::{
    commons::ClientType,
    fs::{create_file_reader, create_file_writer},
};
use std::{
    io::{BufRead, Error, ErrorKind, Result, Write},
    path::PathBuf,
};

pub struct KeyChains {
    file_path: PathBuf,
}

impl KeyChains {
    pub fn new(file: PathBuf) -> Self {
        Self { file_path: file }
    }

    pub fn alter(&self, key: String, value: String) -> Result<()> {
        let reader = create_file_reader(&self.file_path)?;

        let rows = reader
            .lines()
            .filter_map(|l| l.ok())
            .fold(vec![], |mut rows: Vec<_>, line| {
                match line.split_once(" ") {
                    Some((name, ..)) => {
                        rows.push(if name == key {
                            value.to_owned()
                        } else {
                            line.to_owned()
                        });
                    }
                    None => {
                        rows.push(line.to_owned());
                    }
                }
                return rows;
            });

        // `File::create` calling must be after `rows` identifier, otherwise, target file is empty
        let mut writer = create_file_writer(&self.file_path)?;

        for line in rows {
            // let _ = writer.write(line.as_bytes())?;
            let _ = writeln!(writer, "{}", line)?;
        }
        Ok(())
    }

    pub fn query(&self, target_name: &str) -> Result<Key> {
        // let file_content = fs::read_to_string(&self.file_path)?;
        // let lines = file_content
        //     .lines()
        //     .map(String::from)
        //     .collect::<Vec<String>>();

        create_file_reader(&self.file_path)?
            .lines()
            .find_map(|line_result| {
                if let Some(line) = line_result.ok() {
                    let data = line.split_whitespace().collect::<Vec<&str>>();
                    if data.len() < 4 || data[0].is_empty() || data[2].is_empty() {
                        return None;
                    }

                    match data[3].into() {
                        ClientType::Hotp => {
                            let (name, secret, counter) = (data[0], data[2], data[4]);
                            if name == target_name {
                                Some(Key {
                                    r#type: ClientType::Hotp,
                                    secret: secret.to_owned(),
                                    counter: Some(counter.parse().ok()?),
                                })
                            } else {
                                None
                            }
                        }
                        ClientType::Totp => {
                            let (name, secret) = (data[0], data[2]);
                            if name == target_name {
                                Some(Key {
                                    r#type: ClientType::Totp,
                                    secret: secret.to_owned(),
                                    counter: None,
                                })
                            } else {
                                None
                            }
                        }
                    }
                } else {
                    None
                }
            })
            .ok_or(Error::new(
                ErrorKind::Other,
                format!("There is no endpoint named {:?}", target_name),
            ))
    }

    pub fn get_endpoint_names(&self) -> Result<Vec<String>> {
        Ok(create_file_reader(&self.file_path)?
            .lines()
            .fold(vec![], |mut acc, line_result| {
                if let Ok(line) = line_result {
                    let data = line.split_whitespace().collect::<Vec<&str>>();
                    if data.len() >= 3 && !data[0].is_empty() && !data[2].is_empty() {
                        acc.push(data[0].to_owned());
                    }
                }
                acc
            }))
    }

    #[cfg(test)]
    fn set(&self, data: String) -> Result<()> {
        create_file_writer(&self.file_path)?.write_all(data.as_bytes())
    }
}

pub struct Key {
    r#type: ClientType,
    secret: String,
    counter: Option<u64>,
}

impl Key {
    pub fn get_client_type(&self) -> ClientType {
        self.r#type.to_owned()
    }

    pub fn get_secret(&self) -> &str {
        &self.secret
    }

    pub fn get_counter(&self) -> Option<u64> {
        self.counter
    }
}

#[test]
fn test_key_chains() {
    use std::env::temp_dir;
    use std::fs;

    let key_chains = KeyChains::new(temp_dir().join(".otps"));
    key_chains
        .set(
            vec![
                "github 6 this_is_github_secret totp",
                "google 6 this_is_google_secret totp",
                "meta 6 this_is_meta_secret totp",
                "twitter 6 this_is_meta_secret totp",
            ]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<String>>()
            .join("\n"),
        )
        .expect("should create successful");

    key_chains
        .alter("google".to_owned(), "google 6 1234 totp".to_owned())
        .expect("should alter successful");

    assert!(
        fs::metadata(&key_chains.file_path).is_ok(),
        "target file ({:?}) should exists",
        &key_chains.file_path
    );

    assert!(
        fs::metadata(&key_chains.file_path).unwrap().len() > 0,
        "Target file shouldn't be empty"
    );

    let ret = key_chains.query("google");
    assert!(ret.is_ok(), "Should return `google` result");

    let key = key_chains.query("google").unwrap();
    assert!(
        key.get_counter().is_none(),
        "Should return None in `counter` field"
    );
    assert_eq!(key.get_client_type(), ClientType::Totp);
    assert_eq!(key.get_secret(), "1234")
}

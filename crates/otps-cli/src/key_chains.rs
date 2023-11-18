use crate::commons::ClientType;
use std::{
    fs::{write, File},
    io::{BufRead, BufReader, Error, ErrorKind, Result},
    path::PathBuf,
};

pub struct KeyChains {
    file_path: PathBuf,
}

impl KeyChains {
    pub fn create_file_reader(&self) -> Result<BufReader<File>> {
        let file = File::open(&self.file_path)?;
        Ok(BufReader::new(file))
    }

    pub fn new(file: PathBuf) -> Self {
        Self { file_path: file }
    }

    pub fn set(&self, key: String) -> Result<()> {
        write(self.file_path.to_owned(), key)
    }

    pub fn get(&self, target_name: &str) -> Result<Key> {
        // let file_content = fs::read_to_string(&self.file_path)?;
        // let lines = file_content
        //     .lines()
        //     .map(String::from)
        //     .collect::<Vec<String>>();

        self.create_file_reader()?
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
        Ok(self
            .create_file_reader()?
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

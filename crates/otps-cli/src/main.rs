use crate::key_chains::KeyChains;
use arboard::Clipboard;
use clap::{Parser, Subcommand};
use commons::ClientType;
use key::Key;
use otps::{HotpBuilder, TotpBuilder};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::{path::PathBuf, process::ExitCode};

mod commons;
mod fs;
mod key;
mod key_chains;

#[derive(Parser)]
#[command(name = "otps", bin_name = "otps", author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new endpoint for generating a one-time password. It would create TOTP by default, otherwise --counter used
    Add {
        endpoint: String,
        /// The initial counter for creating HOTP
        #[arg(long, short)]
        counter: Option<u64>,
    },
    /// List all available endpoints
    List,
    /// Checkout specific endpoint one-time password
    Get {
        /// Specific target endpoint name
        endpoint: String,
        /// Whether copy code to system clipboard automatically
        #[arg(long, short)]
        clip: bool, // clipboard flag: --clip, -c
        /// Whether HOTP client should increment counter after querying
        #[arg(long, short, default_value_t = false)]
        increment: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let key_chains =
        KeyChains::new(PathBuf::from(commons::WORKING_DIR).join(commons::WORKING_FILENAME));

    match cli.command {
        Some(Commands::Add { endpoint, counter }) => {
            let mut editor = DefaultEditor::new().expect("Failed to initialize readline editor");
            let mut secret = loop {
                match editor.readline(&format!(">> secret key for {}: ", endpoint)) {
                    Ok(line) => {
                        if line.trim().is_empty() {
                            continue;
                        }
                        break line.replace(" ", "");
                    }
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        return ExitCode::FAILURE;
                    }
                    Err(err) => {
                        eprintln!("Readline exception: {}", err);
                        return ExitCode::FAILURE;
                    }
                }
            };

            // pad to 8 bytes
            secret.push_str(&"=".repeat(secret.len() & 7));

            let client_type = if counter.is_some() {
                ClientType::Hotp
            } else {
                ClientType::Totp
            };

            let key = Key {
                name: endpoint.to_owned(),
                r#type: client_type,
                secret,
                counter,
            };
            if let Err(error) = key_chains.alter(endpoint, key.into()) {
                eprintln!("KeyChain exception: {}", error);
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Some(Commands::List) => {
            if let Ok(names) = key_chains.get_endpoint_names() {
                println!("All available endpoints:\n{}", names.join("\n"));
                ExitCode::SUCCESS
            } else {
                eprintln!("There is no available endpoint.");
                ExitCode::FAILURE
            }
        }
        Some(Commands::Get {
            endpoint,
            clip,
            increment,
        }) => {
            if let Ok(key) = key_chains.query(&endpoint) {
                let client_type = key.get_client_type();
                let code = match client_type {
                    ClientType::Hotp => {
                        let mut hotp_client = HotpBuilder::new()
                            .base32_secret(key.get_secret())
                            .counter(key.get_counter().expect("Counter exception"))
                            .build()
                            .expect("Failed to initialize HOTP client");

                        if increment {
                            let _ = key_chains.alter(
                                endpoint.to_owned(),
                                Key {
                                    counter: Some(hotp_client.increment_counter().get_counter()),
                                    ..key.clone()
                                }
                                .into(),
                            );
                        }
                        hotp_client.generate()
                    }
                    ClientType::Totp => {
                        let mut totp_client = TotpBuilder::new()
                            .base32_secret(key.get_secret())
                            .build()
                            .expect("Failed to initialize TOTP client");
                        totp_client.generate()
                    }
                };
                println!("{} for {}: {}", client_type, endpoint, code);
                if clip {
                    let mut clipboard =
                        Clipboard::new().expect("Failed to initial clipboard writer, skip it");
                    if let Err(exception) = clipboard.set_text(code) {
                        eprintln!("{}", exception);
                        return ExitCode::FAILURE;
                    }
                }
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "There is no endpoint named {}, please try again after checking",
                    endpoint
                );
                ExitCode::FAILURE
            }
        }
        None => ExitCode::SUCCESS,
    }
}

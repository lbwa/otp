use crate::key_chains::KeyChains;
use arboard::Clipboard;
use clap::{Parser, Subcommand};
use otps::TotpBuilder;
use rustyline::{error::ReadlineError, DefaultEditor};
use std::{path::PathBuf, process::ExitCode};

mod constants;
mod key_chains;

#[derive(Parser)]
#[command(name = "otps", bin_name = "otps", author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new endpoint for generating a one-time password
    Add {
        endpoint: String, // TODO: --base32=false --counter=0
    },
    /// List all available endpoints
    List,
    /// Checkout specific endpoint one-time password
    Get {
        /// Specific target endpoint name
        endpoint: String,
        /// Whether copy code to system clipboard automatically. Only works with code querying
        #[arg(long, short)]
        clip: bool, // clipboard flag: --clip, -c
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let key_chains =
        KeyChains::new(PathBuf::from(constants::WORKING_DIR).join(constants::WORKING_FILENAME));

    match cli.command {
        Some(Commands::Add { endpoint }) => {
            let mut editor = DefaultEditor::new().expect("failed to open readline");
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
                        eprintln!("Exception occurred: {}", err);
                        return ExitCode::FAILURE;
                    }
                }
            };

            // pad to 8 bytes
            secret.push_str(&"=".repeat(secret.len() & 7));

            let mut chip = format!("{} {} {}", endpoint, 6, secret);
            chip.push_str("\n");

            if let Err(error) = key_chains.set(chip) {
                eprintln!("Opening keychains: {}", error);
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
        Some(Commands::Get { endpoint, clip }) => {
            if let Ok(secret) = key_chains.get(&endpoint) {
                let mut totp_client = TotpBuilder::new()
                    .base32_secret(&secret)
                    .build()
                    .expect("failed to initialize TOTP client");
                let code = totp_client.generate();
                println!("TOTP: {}", code);
                if clip {
                    if let Ok(mut clipboard) = Clipboard::new() {
                        if let Err(exception) = clipboard.set_text(code) {
                            eprintln!("{}", exception)
                        }
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

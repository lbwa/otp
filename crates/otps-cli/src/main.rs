use crate::key_chains::KeyChains;
use clap::{Parser, Subcommand};
use otps::TotpBuilder;
use rustyline::error::ReadlineError;
use std::path::PathBuf;

mod constants;
mod key_chains;

#[derive(Parser)]
#[command(name = "otps", bin_name = "otps", author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Use target name to query one-time password
    endpoint: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Setup a new endpoint for generating one-time password
    Add {
        endpoint: String, // TODO: --base32=false --counter=0

        /// To generate HOTP instead TOTP
        #[arg(long)]
        hotp: bool,
    },

    /// List all available endpoints
    List,

    /// Checkout specific endpoint one-time password
    Get {
        /// Specific target endpoint name
        endpoint: String,
    },
}

pub fn main() {
    let cli = Cli::parse();

    let key_chains =
        KeyChains::new(PathBuf::from(constants::WORKING_DIR).join(constants::WORKING_FILENAME));

    let query_otp = |endpoint: &str| {
        if let Ok(secret) = key_chains.get(endpoint) {
            let mut totp_client = TotpBuilder::new()
                .base32_secret(&secret)
                .build()
                .expect("failed to initialize TOTP client");
            println!("TOTP: {}", totp_client.generate());
        } else {
            eprintln!(
                "There is no endpoint named {}, please try again after checking",
                endpoint
            );
        }
    };

    if let Some(endpoint) = cli.endpoint {
        return query_otp(&endpoint);
    }

    match cli.command {
        Some(Commands::Add { endpoint, hotp }) => {
            let mut editor = rustyline::DefaultEditor::new().expect("failed to open readline");

            let mut secret = loop {
                match editor.readline(&format!(">> secret key for {}: ", endpoint)) {
                    Ok(line) => {
                        if line.trim().is_empty() {
                            continue;
                        }
                        break line.replace(" ", "");
                    }
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        return;
                    }
                    Err(err) => {
                        eprintln!("Exception occurred: {}", err);
                        return;
                    }
                }
            };

            // pad to 8 bytes
            secret.push_str(&"=".repeat(secret.len() & 7));

            let mut chip = format!("{} {} {}", endpoint, 6, secret);
            if hotp {
                chip.push_str((" ".to_owned() + "0".repeat(20).as_ref()).as_ref());
            }
            chip.push_str("\n");

            if let Err(error) = key_chains.set(chip) {
                eprintln!("Opening keychains: {}", error);
                return;
            }
        }
        Some(Commands::List) => {
            if let Ok(names) = key_chains.get_endpoint_names() {
                println!("All available endpoints:\n{}", names.join("\n"));
            } else {
                eprintln!("There is no available endpoint.")
            }
        }
        Some(Commands::Get { endpoint }) => query_otp(&endpoint),
        None => {}
    }
}

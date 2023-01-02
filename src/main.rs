use std::process;

use clap::{Parser, Subcommand};

use crate::subcommands::*;

mod error;
mod subcommands;
mod utils;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Subcommands,
}

#[derive(Debug, Subcommand)]
enum Subcommands {
    #[clap(about = "Encrypt file")]
    Lock(LockCommand),
    #[clap(about = "Decrypt file")]
    Unlock(UnlockCommand),
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Subcommands::Lock(cmd) => {
            if let Err(err) = cmd.run() {
                eprintln!("Error running command: {:#?}", err);
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
        Subcommands::Unlock(cmd) => {
            if let Err(err) = cmd.run() {
                eprintln!("Error running command: {:#?}", err);
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
    }
}

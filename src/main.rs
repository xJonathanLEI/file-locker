use clap::{Parser, Subcommand};
use std::process;

mod error;
mod run;

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

#[derive(Debug, Parser)]
struct LockCommand {
    #[clap(help = "Path to file to be encrypted")]
    file: String,
}

#[derive(Debug, Parser)]
struct UnlockCommand {
    #[clap(help = "Path to file to be decrypted")]
    file: String,
    #[clap(long, short, help = "Target file is in legacy format")]
    legacy: bool,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Subcommands::Lock(cmd) => {
            if let Err(err) = crate::run::run_encrypt(&cmd.file) {
                eprintln!("Error running command: {:#?}", err);
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
        Subcommands::Unlock(cmd) => {
            if let Err(err) = crate::run::run_decrypt(&cmd.file, cmd.legacy) {
                eprintln!("Error running command: {:#?}", err);
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
    }
}

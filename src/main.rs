use clap::{App, Arg, SubCommand};
use std::process;

mod error;
mod run;

fn main() {
    let file_arg = Arg::with_name("path")
        .help("Path to file to be encrypted/decrypted")
        .value_name("FILE")
        .required(true);

    let matches = App::new("File Locker")
        .version("0.1.0")
        .author("Jonathan LEI <xJonathan@outlook.com>")
        .about("A simple AES-based file encryptor/decryptor")
        .subcommand(
            SubCommand::with_name("lock")
                .about("Encrypt file")
                .arg(file_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("unlock")
                .about("Decrypt file")
                .arg(
                    Arg::with_name("legacy")
                        .long("legacy")
                        .short("l")
                        .help("Target file is in legacy format")
                        .takes_value(false),
                )
                .arg(file_arg),
        )
        .get_matches();

    // Dispatch subcommands
    if let Some(sub_matches) = matches.subcommand_matches("lock") {
        let path = sub_matches.value_of("path").expect("Missing value: FILE");

        if let Err(err) = crate::run::run_encrypt(path) {
            eprintln!("Error running command: {:#?}", err);
            process::exit(1);
        } else {
            process::exit(0);
        }
    } else if let Some(sub_matches) = matches.subcommand_matches("unlock") {
        let path = sub_matches.value_of("path").expect("Missing value: FILE");
        let legacy = sub_matches.is_present("legacy");

        if let Err(err) = crate::run::run_decrypt(path, legacy) {
            eprintln!("Error running command: {:#?}", err);
            process::exit(1);
        } else {
            process::exit(0);
        }
    }
}

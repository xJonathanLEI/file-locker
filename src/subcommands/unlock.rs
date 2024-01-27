use std::{
    convert::TryInto,
    fs,
    io::{Read, Write},
};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use clap::Parser;

use crate::{
    error::DecryptError,
    utils::{generate_legacy_iv, password_to_key},
};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug, Parser)]
pub struct UnlockCommand {
    #[clap(help = "Path to file to be decrypted")]
    file: String,
    #[clap(long, help = "Provide password on command line instead")]
    password: Option<String>,
    #[clap(long, short, help = "Target file is in legacy format")]
    legacy: bool,
    #[clap(
        long,
        short,
        help = "Print result to stdout instead of decrypting file"
    )]
    print: bool,
}

impl UnlockCommand {
    pub fn run(&self) -> Result<(), DecryptError> {
        let mut file = fs::File::open(&self.file).map_err(DecryptError::FileError)?;
        let password = match &self.password {
            Some(password) => password.to_owned(),
            None => rpassword::prompt_password("Enter Password: ")
                .map_err(DecryptError::ReadPasswordError)?,
        };

        // Generate key from password
        let key: [u8; 32] = password_to_key(&password);

        // Read IV from file
        let mut iv: [u8; 16] = [0; 16];
        if self.legacy {
            generate_legacy_iv(&mut iv);
        } else {
            file.read(&mut iv).map_err(DecryptError::FileError)?;
        }

        let input_file_meta = file.metadata().map_err(DecryptError::FileError)?;
        let file_len: usize = input_file_meta.len().try_into().unwrap();

        // TODO: change to encrypt by block
        let actual_file_length = if self.legacy {
            file_len
        } else {
            file_len - iv.len()
        };
        let mut buffer = Box::new(vec![0; actual_file_length]);
        if file.read(&mut buffer).map_err(DecryptError::FileError)? != buffer.len() {
            return Err(DecryptError::FileLengthMismatch);
        }

        let cipher = Aes256CbcDec::new_from_slices(&key, &iv).unwrap();
        let plaintext = cipher
            .decrypt_padded_vec_mut::<Pkcs7>(&buffer)
            .map_err(DecryptError::DecryptionFailed)?;

        if self.print {
            print!(
                "{}",
                String::from_utf8(plaintext).expect("Non utf-8 content")
            );
        } else {
            let mut tmp_file = tempfile::NamedTempFile::new().map_err(DecryptError::FileError)?;
            tmp_file
                .write(&plaintext[..])
                .map_err(DecryptError::FileError)?;
            tmp_file.flush().map_err(DecryptError::FileError)?;

            std::fs::copy(tmp_file.path(), &self.file).map_err(DecryptError::FileError)?;
        }

        Ok(())
    }
}

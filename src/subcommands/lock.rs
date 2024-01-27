use std::{
    convert::TryInto,
    fs,
    io::{Read, Write},
};

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use clap::Parser;

use crate::{error::EncryptError, utils::password_to_key};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

#[derive(Debug, Parser)]
pub struct LockCommand {
    #[clap(long, help = "Provide password on command line instead")]
    password: Option<String>,
    #[clap(help = "Path to file to be encrypted")]
    file: String,
}

impl LockCommand {
    pub fn run(&self) -> Result<(), EncryptError> {
        let mut file = fs::File::open(&self.file).map_err(EncryptError::FileError)?;
        let password = match &self.password {
            Some(password) => password.to_owned(),
            None => {
                let password = rpassword::prompt_password("Enter Password: ")
                    .map_err(EncryptError::ReadPasswordError)?;

                let confirm_password = rpassword::prompt_password("Repeat password: ")
                    .map_err(EncryptError::FileError)?;
                if confirm_password != password {
                    return Err(EncryptError::PasswordMismatch);
                }

                password
            }
        };

        // Generate key from password
        let key: [u8; 32] = password_to_key(&password);

        // Generate IV randomly
        let mut iv: [u8; 16] = [0; 16];
        getrandom::getrandom(&mut iv).map_err(EncryptError::RandomnessError)?;

        let input_file_meta = file.metadata().map_err(EncryptError::FileError)?;
        let file_len: usize = input_file_meta.len().try_into().unwrap();

        // TODO: change to encrypt by block
        let mut buffer = Box::new(vec![0; file_len]);
        if file.read(&mut buffer).map_err(EncryptError::FileError)? != file_len {
            return Err(EncryptError::FileLengthMismatch);
        }

        let cipher = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();
        let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(&buffer);

        let mut tmp_file = tempfile::NamedTempFile::new().map_err(EncryptError::FileError)?;
        tmp_file.write(&iv[..]).map_err(EncryptError::FileError)?;
        tmp_file
            .write(&ciphertext[..])
            .map_err(EncryptError::FileError)?;
        tmp_file.flush().map_err(EncryptError::FileError)?;

        std::fs::copy(tmp_file.path(), &self.file).map_err(EncryptError::FileError)?;

        Ok(())
    }
}

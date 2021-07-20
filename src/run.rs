use crate::error::{DecryptError, EncryptError};
use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use sha2::{Digest, Sha256};
use std::{
    convert::TryInto,
    fs,
    io::{Read, Write},
};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn run_encrypt(path: &str) -> Result<(), EncryptError> {
    let mut file = fs::File::open(path).map_err(EncryptError::FileError)?;
    let password = rpassword::read_password_from_tty(Some("Enter Password: "))
        .map_err(EncryptError::FileError)?;

    let confirm_password = rpassword::read_password_from_tty(Some("Repeat password: "))
        .map_err(EncryptError::FileError)?;
    if confirm_password != password {
        return Err(EncryptError::PasswordMismatch);
    }

    // Generate key from password
    let mut sha256 = Sha256::new();
    sha256.update(password.as_bytes());
    let key: [u8; 32] = sha256.finalize()[..].try_into().unwrap();

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

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(&buffer);

    let mut tmp_file = tempfile::NamedTempFile::new().map_err(EncryptError::FileError)?;
    tmp_file.write(&iv[..]).map_err(EncryptError::FileError)?;
    tmp_file
        .write(&ciphertext[..])
        .map_err(EncryptError::FileError)?;
    tmp_file.flush().map_err(EncryptError::FileError)?;

    std::fs::copy(tmp_file.path(), path).map_err(EncryptError::FileError)?;

    Ok(())
}

pub fn run_decrypt(_path: &str, _legacy: bool) -> Result<(), DecryptError> {
    todo!();
}

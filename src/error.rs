#[derive(Debug)]
pub enum EncryptError {
    FileError(std::io::Error),
    PasswordMismatch,
    RandomnessError(getrandom::Error),
    FileLengthMismatch,
}

#[derive(Debug)]
pub enum DecryptError {}

use aes::cipher::block_padding::UnpadError;

#[derive(Debug)]
pub enum EncryptError {
    FileError(std::io::Error),
    ReadPasswordError(std::io::Error),
    PasswordMismatch,
    RandomnessError(getrandom::Error),
    FileLengthMismatch,
}

#[derive(Debug)]
pub enum DecryptError {
    FileError(std::io::Error),
    ReadPasswordError(std::io::Error),
    FileLengthMismatch,
    DecryptionFailed(UnpadError),
}

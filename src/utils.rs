use sha2::{Digest, Sha256};
use std::convert::TryInto;

pub fn password_to_key(password: &str) -> [u8; 32] {
    let mut sha256 = Sha256::new();
    sha256.update(password.as_bytes());
    sha256.finalize()[..].try_into().unwrap()
}

pub fn generate_legacy_iv(iv: &mut [u8; 16]) {
    let mut sha256 = Sha256::new();
    sha256.update(b"File Locker");
    let hash = sha256.finalize();

    let iv_len = iv.len();
    iv.copy_from_slice(&hash[..iv_len]);
}

use crate::{exec::sqlite::Database, DATABASE_OBJ};
use base64::{engine::general_purpose, DecodeError, Engine as _};
use bcrypt::{hash, verify};
use std::ops::Drop;
use std::sync::mpsc::{SendError, Sender};
use std::sync::{MutexGuard, PoisonError};
use std::{fs, io::Write, string::FromUtf8Error};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Error converting string from utf-8: {0}")]
    FromUTF8Error(#[from] FromUtf8Error),
    #[error("Error decoding the base64 encoded input: {0}")]
    Base64DecodeError(#[from] DecodeError),
    #[error("Error while performing IO operations: {0}")]
    FileIOError(#[from] std::io::Error),
    #[error("Error while hashing the database file: {0}")]
    HashError(#[from] bcrypt::BcryptError),
    #[error("Error getting the lock on database: {0}")]
    DatabaseLockError(#[from] PoisonError<MutexGuard<'static, Database>>),
    #[error("Error while sending shutdown signal: {0}")]
    ShutdownSignalError(#[from] SendError<i32>),
}

pub struct DecryptDatabase {
    filepath: String,
    is_decrypted: bool,
}

impl DecryptDatabase {
    pub fn decrypt(filepath: String, sender: Option<Sender<i32>>) -> Result<Self, EncryptionError> {
        if let Err(err) = decrypt_file(filepath.as_str()) {
            eprintln!("Error while decrypting database: {err}");
            fs::remove_file(filepath.clone())?;
            if let Some(sender) = sender {
                sender.send(0)?; // shutdown signal
            }
        }
        Ok(Self {
            filepath,
            is_decrypted: true,
        })
    }

    fn encrypt(&mut self) -> Result<(), EncryptionError> {
        if self.is_decrypted {
            encrypt_file(self.filepath.as_str())?;
            self.is_decrypted = false;
        }
        Ok(())
    }
}

impl Drop for DecryptDatabase {
    fn drop(&mut self) {
        if let Err(err) = self.encrypt() {
            eprintln!("Error while encrypting the database: {err}");
        }
    }
}

pub fn get_database_decrypted<'a>(
    sender: Option<Sender<i32>>,
) -> Result<(MutexGuard<'a, Database>, DecryptDatabase), EncryptionError> {
    let db = DATABASE_OBJ.lock()?;
    let decryptor = DecryptDatabase::decrypt(db.filepath.clone(), sender)?;
    Ok((db, decryptor))
}

pub fn base64_decrypt(input: &str) -> Result<String, EncryptionError> {
    let content = general_purpose::STANDARD.decode(input)?;
    let decoded_str = String::from_utf8(content)?;
    Ok(decoded_str)
}

// /*
// backwards = true for encryption, backwards = false for decryption
pub fn byte_shift(text: Vec<u8>, shift_by: u8, backwards: bool) -> Vec<u8> {
    text.iter()
        .map(|byte| {
            if backwards {
                byte.wrapping_sub(shift_by)
            } else {
                byte.wrapping_add(shift_by)
            }
        })
        .collect()
}
// */
fn encrypt_file(filepath: &str) -> Result<bool, EncryptionError> {
    let content = fs::read(filepath)?;
    let new_content = byte_shift(content, 2, true);
    let mut file = fs::OpenOptions::new().write(true).open(filepath)?;
    file.write_all(&new_content)?;
    Ok(true)
}

fn decrypt_file(filepath: &str) -> Result<bool, EncryptionError> {
    let content = fs::read(filepath)?;
    let new_content = byte_shift(content, 2, false);
    let mut file = fs::OpenOptions::new().write(true).open(filepath)?;
    file.write_all(&new_content)?;
    Ok(true)
}

pub fn encrypt_string(input: &str) -> Result<String, EncryptionError> {
    let hashed_output = hash(input, 10)?;
    Ok(hashed_output)
}
pub fn decrypt_string(input: &str, hashed: &str) -> Result<bool, EncryptionError> {
    Ok(verify(input, hashed)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encryption() {
        let file_path: &str = "./utils/testfile.txt";
        let old_content = fs::read(file_path).unwrap();

        let mut result = encrypt_file(file_path);
        assert!(result.is_ok());

        result = decrypt_file(file_path);
        assert!(result.is_ok());

        let new_content = fs::read(file_path).unwrap();
        assert_eq!(old_content, new_content);
    }
}

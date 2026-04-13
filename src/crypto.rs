//! Cryptographic primitives for heist.
//!
//! Key derivation: Argon2id with OWASP-recommended parameters.
//! Encryption: AES-256-GCM with random 96-bit nonces.
//! All sensitive key material is zeroized on drop via the `Zeroizing` wrapper.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{HeistError, Result};

/// Length of Argon2id salt in bytes.
pub const SALT_LEN: usize = 32;
/// Length of AES-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;
/// Length of the AES-256 key in bytes.
pub const KEY_LEN: usize = 32;

// Argon2id parameters — OWASP minimum (64 MiB, 3 iterations, 4 threads).
const ARGON2_M_COST: u32 = 65_536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// Generate a cryptographically random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a 256-bit encryption key from `password` and `salt` using Argon2id.
///
/// The returned key is wrapped in `Zeroizing` so it is erased from memory
/// when dropped.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params =
        Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN)).map_err(|e| {
            HeistError::EncryptionError(format!("Argon2 parameter error: {e}"))
        })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt.as_slice(), key.as_mut_slice())
        .map_err(|e| HeistError::EncryptionError(format!("Key derivation failed: {e}")))?;

    Ok(key)
}

/// Encrypt `plaintext` with AES-256-GCM using `key`.
///
/// Returns `(ciphertext, nonce)`. The nonce is randomly generated.
pub fn encrypt(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_generic = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce_generic, plaintext)
        .map_err(|e| HeistError::EncryptionError(format!("AES-GCM encrypt failed: {e}")))?;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_generic);
    Ok((ciphertext, nonce))
}

/// Decrypt `ciphertext` with AES-256-GCM using `key` and `nonce`.
pub fn decrypt(ciphertext: &[u8], key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| HeistError::DecryptionError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let salt = generate_salt();
        let key = derive_key("correct-horse-battery-staple", &salt).unwrap();
        let plaintext = b"super secret data";

        let (ct, nonce) = encrypt(plaintext, &key).unwrap();
        let recovered = decrypt(&ct, &key, &nonce).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let salt = generate_salt();
        let key = derive_key("password-a", &salt).unwrap();
        let wrong_key = derive_key("password-b", &salt).unwrap();
        let (ct, nonce) = encrypt(b"data", &key).unwrap();

        assert!(decrypt(&ct, &wrong_key, &nonce).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let salt = generate_salt();
        let key = derive_key("password", &salt).unwrap();
        let (mut ct, nonce) = encrypt(b"hello", &key).unwrap();
        ct[0] ^= 0xFF; // flip a byte

        assert!(decrypt(&ct, &key, &nonce).is_err());
    }
}

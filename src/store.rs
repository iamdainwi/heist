//! Vault persistence layer.
//!
//! `Store` owns the decrypted secret data and audit log in memory and
//! handles reading/writing the vault file with atomic (tmp + rename) saves.
//! The Argon2id salt is stable across saves and regenerated only on password
//! rotation.

use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{HeistError, Result};
use crate::vault::{AuditAction, AuditLog, VaultData, VaultFile};

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("vault_path", &self.vault_path)
            .field("secret_count", &self.data.secrets.len())
            .finish_non_exhaustive()
    }
}

/// In-memory vault state.
pub struct Store {
    /// Path to the `.heist` vault file.
    pub vault_path: PathBuf,
    /// Argon2id salt — stable across saves.
    salt: [u8; SALT_LEN],
    /// AES-256 key derived from the master password.
    key: Zeroizing<[u8; KEY_LEN]>,
    /// Decrypted vault contents.
    pub data: VaultData,
    /// Decrypted audit log.
    pub audit: AuditLog,
}

impl Store {
    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /// Create and persist a brand-new vault.
    pub fn init(vault_path: &Path, password: &str, force: bool) -> Result<Self> {
        if vault_path.exists() && !force {
            return Err(HeistError::VaultAlreadyExists {
                path: vault_path.display().to_string(),
            });
        }

        let salt = crypto::generate_salt();
        let key = crypto::derive_key(password, &salt)?;

        let mut store = Self {
            vault_path: vault_path.to_path_buf(),
            salt,
            key,
            data: VaultData::new(),
            audit: AuditLog::new(),
        };
        store.audit.record(AuditAction::Init, "*", None);
        store.save()?;
        Ok(store)
    }

    /// Open an existing vault, decrypting it with `password`.
    pub fn open(vault_path: &Path, password: &str) -> Result<Self> {
        if !vault_path.exists() {
            return Err(HeistError::VaultNotFound {
                path: vault_path.display().to_string(),
            });
        }

        let content = fs::read_to_string(vault_path)?;
        let vf: VaultFile = serde_json::from_str(&content)
            .map_err(|e| HeistError::CorruptedVault(format!("cannot parse vault file: {e}")))?;

        if vf.version != 1 {
            return Err(HeistError::CorruptedVault(format!(
                "unsupported vault version {}",
                vf.version
            )));
        }

        let salt = decode_hex_fixed::<SALT_LEN>(&vf.salt, "salt")?;

        let key = crypto::derive_key(password, &salt)?;

        // Decrypt secret data.
        let nonce = decode_hex_fixed::<NONCE_LEN>(&vf.nonce, "nonce")?;
        let ct = BASE64
            .decode(&vf.ciphertext)
            .map_err(|e| HeistError::CorruptedVault(format!("invalid ciphertext base64: {e}")))?;
        let plaintext = crypto::decrypt(&ct, &key, &nonce)?;
        let data: VaultData = serde_json::from_slice(&plaintext).map_err(|e| {
            HeistError::CorruptedVault(format!("cannot deserialise vault data: {e}"))
        })?;

        // Decrypt audit log (best-effort; absent or corrupt → empty log).
        let audit = match (&vf.audit_nonce, &vf.audit_ciphertext) {
            (Some(an_hex), Some(act_b64)) => {
                let an = decode_hex_fixed::<NONCE_LEN>(an_hex, "audit nonce")
                    .unwrap_or([0u8; NONCE_LEN]);
                let act = BASE64.decode(act_b64).unwrap_or_default();
                match crypto::decrypt(&act, &key, &an) {
                    Ok(pt) => serde_json::from_slice(&pt).unwrap_or_default(),
                    Err(_) => AuditLog::new(),
                }
            }
            _ => AuditLog::new(),
        };

        Ok(Self {
            vault_path: vault_path.to_path_buf(),
            salt,
            key,
            data,
            audit,
        })
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /// Encrypt and persist the vault to disk atomically.
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.vault_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let data_json =
            serde_json::to_vec(&self.data).map_err(|e| HeistError::Serialization(e.to_string()))?;
        let (data_ct, data_nonce) = crypto::encrypt(&data_json, &self.key)?;

        let audit_json = serde_json::to_vec(&self.audit)
            .map_err(|e| HeistError::Serialization(e.to_string()))?;
        let (audit_ct, audit_nonce) = crypto::encrypt(&audit_json, &self.key)?;

        let vf = VaultFile {
            version: 1,
            created_at: chrono::Utc::now(),
            salt: hex::encode(self.salt),
            nonce: hex::encode(data_nonce),
            ciphertext: BASE64.encode(&data_ct),
            audit_nonce: Some(hex::encode(audit_nonce)),
            audit_ciphertext: Some(BASE64.encode(&audit_ct)),
        };

        let content = serde_json::to_string_pretty(&vf)
            .map_err(|e| HeistError::Serialization(e.to_string()))?;

        // Atomic write: tmp → rename.
        let tmp = self.vault_path.with_extension("tmp");
        fs::write(&tmp, &content)?;
        fs::rename(&tmp, &self.vault_path)?;

        Ok(())
    }

    // ── Password rotation ─────────────────────────────────────────────────────

    /// Re-encrypt the vault with a new master password (new salt + new key).
    pub fn rotate_password(&mut self, new_password: &str) -> Result<()> {
        self.salt = crypto::generate_salt();
        self.key = crypto::derive_key(new_password, &self.salt)?;
        self.audit.record(AuditAction::Rotate, "*", None);
        self.save()
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Returns the number of secrets stored.
    pub fn secret_count(&self) -> usize {
        self.data.secrets.len()
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn decode_hex_fixed<const N: usize>(hex_str: &str, field: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| HeistError::CorruptedVault(format!("invalid {field} hex: {e}")))?;

    if bytes.len() != N {
        return Err(HeistError::CorruptedVault(format!(
            "{field} length mismatch: expected {N}, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_and_open_roundtrip() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.heist");

        Store::init(&vault_path, "hunter2", false).unwrap();

        let store = Store::open(&vault_path, "hunter2").unwrap();
        assert_eq!(store.secret_count(), 0);
    }

    #[test]
    fn wrong_password_fails() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.heist");

        Store::init(&vault_path, "correct", false).unwrap();

        let err = Store::open(&vault_path, "wrong").unwrap_err();
        assert!(matches!(err, HeistError::DecryptionError));
    }

    #[test]
    fn vault_already_exists_no_force() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.heist");

        Store::init(&vault_path, "pw", false).unwrap();

        let err = Store::init(&vault_path, "pw", false).unwrap_err();
        assert!(matches!(err, HeistError::VaultAlreadyExists { .. }));
    }

    #[test]
    fn vault_already_exists_with_force() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.heist");

        Store::init(&vault_path, "pw", false).unwrap();
        Store::init(&vault_path, "pw2", true).unwrap();

        let store = Store::open(&vault_path, "pw2").unwrap();
        assert_eq!(store.secret_count(), 0);
    }

    #[test]
    fn persist_and_read_secrets() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.heist");

        let mut store = Store::init(&vault_path, "pw", false).unwrap();
        store.data.secrets.insert(
            "TOKEN".into(),
            crate::vault::Secret::new("abc123".into(), None, vec![]),
        );
        store.save().unwrap();

        let store2 = Store::open(&vault_path, "pw").unwrap();
        assert_eq!(store2.data.secrets["TOKEN"].value, "abc123");
    }

    #[test]
    fn password_rotation() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.heist");

        let mut store = Store::init(&vault_path, "old-pw", false).unwrap();
        store.data.secrets.insert(
            "KEY".into(),
            crate::vault::Secret::new("val".into(), None, vec![]),
        );
        store.rotate_password("new-pw").unwrap();

        assert!(Store::open(&vault_path, "old-pw").is_err());

        let store2 = Store::open(&vault_path, "new-pw").unwrap();
        assert_eq!(store2.data.secrets["KEY"].value, "val");
    }
}

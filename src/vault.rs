//! Core vault data structures.
//!
//! [`VaultFile`] is the on-disk envelope (encrypted blobs + cleartext metadata).
//! [`VaultData`] is the in-memory plaintext representation after decryption.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── On-disk envelope ──────────────────────────────────────────────────────────

/// The serialised structure written to the vault file.
///
/// Only `salt` and `version` are stored in the clear; everything sensitive
/// is inside the encrypted blobs.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    /// File format version — increment on breaking changes.
    pub version: u32,
    /// When this vault was first created.
    pub created_at: DateTime<Utc>,
    /// Argon2id salt (hex-encoded, 32 bytes).
    pub salt: String,
    /// AES-GCM nonce for the secret data blob (hex-encoded, 12 bytes).
    pub nonce: String,
    /// AES-256-GCM ciphertext of `VaultData` (base64-encoded).
    pub ciphertext: String,
    /// AES-GCM nonce for the audit log blob (hex-encoded, 12 bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_nonce: Option<String>,
    /// AES-256-GCM ciphertext of `AuditLog` (base64-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_ciphertext: Option<String>,
}

// ── Plaintext vault contents ──────────────────────────────────────────────────

/// The decrypted contents of a vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u32,
    /// Map of key → Secret.  Keys may contain `/` as a namespace separator.
    pub secrets: HashMap<String, Secret>,
}

impl VaultData {
    pub fn new() -> Self {
        Self {
            version: 1,
            secrets: HashMap::new(),
        }
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

// ── Individual secret ─────────────────────────────────────────────────────────

/// A single stored secret.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    /// The secret value (zeroized on drop).
    pub value: String,
    /// Human-readable description (optional).
    pub description: Option<String>,
    /// Free-form tags for grouping and filtering.
    pub tags: Vec<String>,
    /// When the secret was first stored.
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,
    /// When the secret was last updated.
    #[zeroize(skip)]
    pub updated_at: DateTime<Utc>,
}

impl Secret {
    pub fn new(value: String, description: Option<String>, tags: Vec<String>) -> Self {
        let now = Utc::now();
        Self {
            value,
            description,
            tags,
            created_at: now,
            updated_at: now,
        }
    }

    /// Update the value and optional metadata, bumping `updated_at`.
    pub fn update(
        &mut self,
        value: String,
        description: Option<String>,
        tags: Option<Vec<String>>,
    ) {
        self.value = value;
        if let Some(d) = description {
            self.description = Some(d);
        }
        if let Some(t) = tags {
            self.tags = t;
        }
        self.updated_at = Utc::now();
    }
}

// ── Audit log ─────────────────────────────────────────────────────────────────

/// Encrypted audit log stored alongside the secret data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry, evicting the oldest beyond the 1 000-entry cap.
    pub fn record(&mut self, action: AuditAction, key: &str, note: Option<String>) {
        self.entries.push(AuditEntry {
            timestamp: Utc::now(),
            action,
            key: key.to_string(),
            note,
        });

        if self.entries.len() > 1_000 {
            let excess = self.entries.len() - 1_000;
            self.entries.drain(..excess);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    /// The secret key (or glob pattern) the action operated on.
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Init,
    Set,
    Get,
    Copy,
    Delete,
    Exec,
    Export,
    Import,
    Rotate,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuditAction::Init => "INIT",
            AuditAction::Set => "SET",
            AuditAction::Get => "GET",
            AuditAction::Copy => "COPY",
            AuditAction::Delete => "DELETE",
            AuditAction::Exec => "EXEC",
            AuditAction::Export => "EXPORT",
            AuditAction::Import => "IMPORT",
            AuditAction::Rotate => "ROTATE",
        };
        write!(f, "{s}")
    }
}

// ── Key validation ────────────────────────────────────────────────────────────

/// Validate a secret key against the allowed character and structure rules.
pub fn validate_key(key: &str) -> crate::error::Result<()> {
    use crate::error::HeistError;

    if key.is_empty() {
        return Err(HeistError::InvalidKey {
            key: key.to_string(),
            reason: "key must not be empty".into(),
        });
    }
    if key.len() > 256 {
        return Err(HeistError::InvalidKey {
            key: key.to_string(),
            reason: "key must not exceed 256 characters".into(),
        });
    }
    if key.starts_with('/') || key.ends_with('/') {
        return Err(HeistError::InvalidKey {
            key: key.to_string(),
            reason: "key must not start or end with '/'".into(),
        });
    }
    if key.contains("//") {
        return Err(HeistError::InvalidKey {
            key: key.to_string(),
            reason: "key must not contain consecutive slashes".into(),
        });
    }

    let segment_re =
        once_cell::sync::Lazy::new(|| regex::Regex::new(r"^[a-zA-Z0-9_.@-]+$").unwrap());

    for segment in key.split('/') {
        if segment.is_empty() {
            return Err(HeistError::InvalidKey {
                key: key.to_string(),
                reason: "empty path segment".into(),
            });
        }
        if !segment_re.is_match(segment) {
            return Err(HeistError::InvalidKey {
                key: key.to_string(),
                reason: format!(
                    "segment '{segment}' contains invalid characters \
                     (allowed: a-z A-Z 0-9 _ . @ -)"
                ),
            });
        }
    }

    Ok(())
}

/// Convert a secret key to an environment-variable name.
pub fn key_to_env(key: &str) -> String {
    key.to_uppercase()
        .replace('/', "_")
        .replace('-', "_")
        .replace('.', "_")
        .replace('@', "_AT_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_keys() {
        for k in ["TOKEN", "aws/access-key", "prod/db/PASSWORD", "x.y.z"] {
            assert!(validate_key(k).is_ok(), "expected '{k}' to be valid");
        }
    }

    #[test]
    fn invalid_keys() {
        for k in ["", "/leading", "trailing/", "dou//ble", &"x".repeat(300)] {
            assert!(validate_key(k).is_err(), "expected '{k}' to be invalid");
        }
    }

    #[test]
    fn key_to_env_conversion() {
        assert_eq!(key_to_env("aws/access-key"), "AWS_ACCESS_KEY");
        assert_eq!(key_to_env("prod/db/PASSWORD"), "PROD_DB_PASSWORD");
    }
}

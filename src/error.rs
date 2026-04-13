use thiserror::Error;

pub type Result<T> = std::result::Result<T, HeistError>;

#[derive(Error, Debug)]
pub enum HeistError {
    #[error("Vault not found at '{path}'. Run `heist init` to create one.")]
    VaultNotFound { path: String },

    #[error("Vault already exists at '{path}'. Use --force to overwrite.")]
    VaultAlreadyExists { path: String },

    #[error("Authentication failed: incorrect master password")]
    AuthenticationFailed,

    #[error("Secret '{key}' not found")]
    SecretNotFound { key: String },

    #[error("Key validation failed for '{key}': {reason}")]
    InvalidKey { key: String, reason: String },

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error — wrong password or corrupted vault")]
    DecryptionError,

    #[error("Vault is corrupted: {0}")]
    CorruptedVault(String),

    #[error("Clipboard error: {0}")]
    ClipboardError(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Import error: {0}")]
    ImportError(String),

    #[error("Export error: {0}")]
    ExportError(String),

    #[error("No secrets found matching the given filter")]
    NoSecretsFound,

    #[error("Command execution failed: {0}")]
    ExecError(String),

    #[error("Password mismatch: the two passwords you entered do not match")]
    PasswordMismatch,

    #[error("Password too short: must be at least 8 characters")]
    PasswordTooShort,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

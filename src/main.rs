//! heist — a secure, encrypted secrets manager for the terminal.
//!
//! # Security model
//!
//! Secrets are stored in a single encrypted file (the "vault").  The vault is
//! protected by a master password that is never written to disk.  The password
//! is stretched into an AES-256 key using Argon2id, and every write uses a
//! fresh random AES-GCM nonce.  An encrypted audit log is maintained inside
//! the same file.
//!
//! # Vault location
//!
//! Default: `~/.heist/vault.heist`
//! Override: `--vault <PATH>` flag or the `HEIST_VAULT` environment variable.

use std::path::PathBuf;

use clap::Parser;
use heist::{
    cli::{Cli, Command},
    commands, error, output, store, vault,
};

use error::HeistError;

fn main() {
    if let Err(e) = run() {
        output::error_msg(&e.to_string());
        match &e {
            HeistError::VaultNotFound { .. } => {
                eprintln!("  Hint: run `heist init` to create a new vault.");
            }
            HeistError::DecryptionError => {
                eprintln!("  Hint: check that you entered the correct master password.");
            }
            HeistError::PasswordTooShort => {
                eprintln!("  Hint: choose a password of at least 8 characters.");
            }
            _ => {}
        }
        std::process::exit(1);
    }
}

fn run() -> error::Result<()> {
    let cli = Cli::parse();
    let vault_path = resolve_vault_path(cli.vault);

    match cli.command {
        Command::Init(args) => commands::init::run(args, &vault_path),
        Command::Set(args) => commands::secret_set::run(args, &vault_path),
        Command::Get(args) => commands::secret_get::run(args, &vault_path),
        Command::List(args) => commands::secret_list::run(args, &vault_path),
        Command::Remove(args) => commands::remove::run(args, &vault_path),
        Command::Copy(args) => commands::secret_copy::run(args, &vault_path),
        Command::Exec(args) => commands::exec::run(args, &vault_path),
        Command::Import(args) => commands::import::run(args, &vault_path),
        Command::Export(args) => commands::export::run(args, &vault_path),
        Command::Log(args) => commands::log::run(args, &vault_path),
        Command::Rotate => commands::rotate::run(&vault_path),
        Command::Info => run_info(&vault_path),
        Command::Completion(args) => commands::completion::run(args),
    }
}

fn run_info(vault_path: &std::path::Path) -> error::Result<()> {
    if !vault_path.exists() {
        return Err(HeistError::VaultNotFound {
            path: vault_path.display().to_string(),
        });
    }

    let password = heist::prompt::get_master_password("Master password: ")?;
    let s = store::Store::open(vault_path, &password)?;

    let content = std::fs::read_to_string(vault_path)?;
    let vf: vault::VaultFile =
        serde_json::from_str(&content).map_err(|e| HeistError::CorruptedVault(e.to_string()))?;

    output::print_vault_info(vault_path, s.secret_count(), vf.created_at);
    Ok(())
}

fn resolve_vault_path(override_path: Option<PathBuf>) -> PathBuf {
    if let Some(p) = override_path {
        return p;
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".heist")
        .join("vault.heist")
}

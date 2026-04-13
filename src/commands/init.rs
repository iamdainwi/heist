use std::path::Path;

use crate::{
    cli::InitArgs,
    error::{HeistError, Result},
    output,
    store::Store,
};

pub fn run(args: InitArgs, vault_path: &Path) -> Result<()> {
    let password = prompt_new_password()?;
    let _store = Store::init(vault_path, &password, args.force)?;

    output::success(&format!("Vault created at {}", vault_path.display()));
    output::info("Use `heist set <KEY>` to store your first secret.");
    Ok(())
}

pub fn prompt_new_password() -> Result<String> {
    // Non-interactive: env var or password file — skip confirmation.
    if let Ok(pw) = std::env::var("HEIST_MASTER_PASSWORD") {
        if !pw.is_empty() {
            if pw.len() < 8 {
                return Err(HeistError::PasswordTooShort);
            }
            return Ok(pw);
        }
    }
    if let Ok(path) = std::env::var("HEIST_PASSWORD_FILE") {
        let pw = std::fs::read_to_string(&path)
            .map(|s| s.lines().next().unwrap_or("").to_string())
            .map_err(HeistError::Io)?;
        if pw.len() < 8 {
            return Err(HeistError::PasswordTooShort);
        }
        return Ok(pw);
    }

    let pw = rpassword::prompt_password("Enter master password: ")
        .map_err(HeistError::Io)?;
    if pw.len() < 8 {
        return Err(HeistError::PasswordTooShort);
    }
    let confirm = rpassword::prompt_password("Confirm master password: ")
        .map_err(HeistError::Io)?;
    if pw != confirm {
        return Err(HeistError::PasswordMismatch);
    }
    Ok(pw)
}

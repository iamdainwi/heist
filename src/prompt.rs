//! Password acquisition strategy, evaluated in order:
//!
//! 1. `HEIST_PASSWORD_FILE` — path to a file whose first line is the password.
//!    Preferred for CI; avoids the password appearing in the process env.
//! 2. `HEIST_MASTER_PASSWORD` — password in the environment directly.
//!    Convenient but less secure (visible via /proc/environ on Linux).
//! 3. Interactive `rpassword` prompt on the controlling terminal.

use std::{env, fs};

use crate::error::{HeistError, Result};

/// Obtain the master password using the strategy described above.
pub fn get_master_password(prompt: &str) -> Result<String> {
    // 1. Password file
    if let Ok(path) = env::var("HEIST_PASSWORD_FILE") {
        let content = fs::read_to_string(&path).map_err(|e| {
            HeistError::Io(std::io::Error::new(
                e.kind(),
                format!("HEIST_PASSWORD_FILE '{path}': {e}"),
            ))
        })?;
        let pw = content.lines().next().unwrap_or("").to_string();
        if pw.is_empty() {
            return Err(HeistError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("HEIST_PASSWORD_FILE '{path}' is empty"),
            )));
        }
        return Ok(pw);
    }

    // 2. Env var
    if let Ok(pw) = env::var("HEIST_MASTER_PASSWORD") {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }

    // 3. Interactive terminal prompt
    rpassword::prompt_password(prompt).map_err(HeistError::Io)
}

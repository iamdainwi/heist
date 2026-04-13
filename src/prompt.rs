//! Master password resolution.
//!
//! Sources checked in priority order: `HEIST_PASSWORD_FILE` env →
//! `HEIST_MASTER_PASSWORD` env → interactive terminal prompt.

use std::{env, fs};

use crate::error::{HeistError, Result};

/// Resolve the master password from the environment or an interactive prompt.
pub fn get_master_password(prompt: &str) -> Result<String> {
    // Password file (CI-preferred).
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

    // Direct env var.
    if let Ok(pw) = env::var("HEIST_MASTER_PASSWORD") {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }

    // Interactive TTY prompt (fallback).
    rpassword::prompt_password(prompt).map_err(HeistError::Io)
}

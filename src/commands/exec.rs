use std::{path::Path, process::Command};

use crate::{
    cli::ExecArgs,
    error::{HeistError, Result},
    store::Store,
    vault::{key_to_env, validate_key, AuditAction},
};

pub fn run(args: ExecArgs, vault_path: &Path) -> Result<()> {
    // Validate all keys before opening the vault.
    for key in &args.keys {
        validate_key(key)?;
    }

    let cmd_parts = args.cmd;
    if cmd_parts.is_empty() {
        return Err(HeistError::ExecError("no command provided".into()));
    }

    let password = prompt_password()?;
    let mut store = Store::open(vault_path, &password)?;

    // Collect (env_name, value) pairs.
    let mut env_vars: Vec<(String, String)> = Vec::with_capacity(args.keys.len());
    for key in &args.keys {
        let secret = store
            .data
            .secrets
            .get(key)
            .ok_or_else(|| HeistError::SecretNotFound { key: key.clone() })?;
        env_vars.push((key_to_env(key), secret.value.clone()));
    }

    // Record audit entry before exec.
    let keys_str = args.keys.join(", ");
    store.audit.record(
        AuditAction::Exec,
        &keys_str,
        Some(format!("cmd={}", cmd_parts[0])),
    );
    store.save()?;

    // Execute.
    let exit_status = Command::new(&cmd_parts[0])
        .args(&cmd_parts[1..])
        .envs(env_vars)
        .status()
        .map_err(|e| {
            HeistError::ExecError(format!("failed to start '{}': {e}", cmd_parts[0]))
        })?;

    // Propagate the child's exit code.
    std::process::exit(exit_status.code().unwrap_or(1));
}

fn prompt_password() -> Result<String> {
    crate::prompt::get_master_password("Master password: ")
}

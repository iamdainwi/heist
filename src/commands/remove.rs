use std::{
    io::{self, Write},
    path::Path,
};

use crate::{
    cli::RemoveArgs,
    error::{HeistError, Result},
    output,
    store::Store,
    vault::AuditAction,
};

pub fn run(args: RemoveArgs, vault_path: &Path) -> Result<()> {
    let password = prompt_password()?;
    let mut store = Store::open(vault_path, &password)?;

    if !store.data.secrets.contains_key(&args.key) {
        return Err(HeistError::SecretNotFound {
            key: args.key.clone(),
        });
    }

    if !args.yes && !confirm_delete(&args.key)? {
        output::info("Aborted.");
        return Ok(());
    }

    store.data.secrets.remove(&args.key);
    store.audit.record(AuditAction::Delete, &args.key, None);
    store.save()?;

    output::success(&format!("Deleted secret '{}'", args.key));
    Ok(())
}

fn confirm_delete(key: &str) -> Result<bool> {
    eprint!("Delete '{}' permanently? [y/N] ", key);
    io::stderr().flush().map_err(HeistError::Io)?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(HeistError::Io)?;

    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn prompt_password() -> Result<String> {
    crate::prompt::get_master_password("Master password: ")
}

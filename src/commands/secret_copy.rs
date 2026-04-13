use std::path::Path;

use crate::{
    cli::CopyArgs,
    error::{HeistError, Result},
    output,
    store::Store,
    vault::AuditAction,
};

pub fn run(args: CopyArgs, vault_path: &Path) -> Result<()> {
    let password = prompt_password()?;
    let mut store = Store::open(vault_path, &password)?;

    let secret = store
        .data
        .secrets
        .get(&args.key)
        .ok_or_else(|| HeistError::SecretNotFound {
            key: args.key.clone(),
        })?
        .clone();

    store
        .audit
        .record(AuditAction::Copy, &args.key, None);
    store.save()?;

    super::secret_get::copy_to_clipboard(&secret.value, args.timeout)?;

    output::success(&format!(
        "Copied '{}' to clipboard. Will clear in {} seconds.",
        args.key, args.timeout
    ));

    Ok(())
}

fn prompt_password() -> Result<String> {
    crate::prompt::get_master_password("Master password: ")
}

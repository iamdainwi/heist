use std::{
    io::{IsTerminal, Read},
    path::Path,
};

use crate::{
    cli::SetArgs,
    error::{HeistError, Result},
    output, prompt,
    store::Store,
    vault::{validate_key, AuditAction, Secret},
};

pub fn run(args: SetArgs, vault_path: &Path) -> Result<()> {
    validate_key(&args.key)?;

    let value = resolve_value(args.value)?;

    let password = prompt_password()?;
    let mut store = Store::open(vault_path, &password)?;

    let is_update = store.data.secrets.contains_key(&args.key);

    if is_update {
        let secret = store.data.secrets.get_mut(&args.key).unwrap();
        secret.update(
            value,
            args.description,
            if args.tags.is_empty() {
                None
            } else {
                Some(args.tags)
            },
        );
        output::success(&format!("Updated secret '{}'", args.key));
    } else {
        let secret = Secret::new(value, args.description, args.tags);
        store.data.secrets.insert(args.key.clone(), secret);
        output::success(&format!("Stored secret '{}'", args.key));
    }

    store.audit.record(
        AuditAction::Set,
        &args.key,
        if is_update {
            Some("updated".into())
        } else {
            None
        },
    );

    store.save()?;
    Ok(())
}

/// Resolve the secret value from `--value`, piped stdin, or an interactive prompt.
fn resolve_value(value_arg: Option<String>) -> Result<String> {
    if let Some(v) = value_arg {
        return Ok(v);
    }

    // Piped stdin.
    if !std::io::stdin().is_terminal() {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(HeistError::Io)?;
        // Strip trailing newline from pipes/heredocs.
        return Ok(buf.trim_end_matches('\n').to_string());
    }

    // Interactive hidden prompt.
    rpassword::prompt_password("Enter secret value: ").map_err(HeistError::Io)
}

fn prompt_password() -> Result<String> {
    prompt::get_master_password("Master password: ")
}

use std::path::Path;

use crate::{cli::ListArgs, error::Result, output, store::Store};

pub fn run(args: ListArgs, vault_path: &Path) -> Result<()> {
    let password = prompt_password()?;
    let store = Store::open(vault_path, &password)?;

    let mut secrets: Vec<(String, &crate::vault::Secret)> = store
        .data
        .secrets
        .iter()
        .filter(|(key, secret)| {
            // Prefix filter.
            let prefix_ok = args
                .prefix
                .as_deref()
                .map(|p| key.starts_with(p))
                .unwrap_or(true);

            // Tag filter (AND semantics).
            let tags_ok = args.tags.iter().all(|t| secret.tags.contains(t));

            prefix_ok && tags_ok
        })
        .map(|(k, v)| (k.clone(), v))
        .collect();

    secrets.sort_by(|a, b| a.0.cmp(&b.0));

    if args.json {
        print_json(&secrets)?;
    } else {
        output::print_secrets_table(&secrets);
    }

    Ok(())
}

fn print_json(secrets: &[(String, &crate::vault::Secret)]) -> Result<()> {
    use crate::error::HeistError;
    use serde_json::{json, Value};

    let obj: serde_json::Map<String, Value> = secrets
        .iter()
        .map(|(k, s)| {
            (
                k.clone(),
                json!({
                    "value": s.value,
                    "description": s.description,
                    "tags": s.tags,
                    "created_at": s.created_at,
                    "updated_at": s.updated_at,
                }),
            )
        })
        .collect();

    let out =
        serde_json::to_string_pretty(&obj).map_err(|e| HeistError::Serialization(e.to_string()))?;
    println!("{out}");
    Ok(())
}

fn prompt_password() -> Result<String> {
    crate::prompt::get_master_password("Master password: ")
}

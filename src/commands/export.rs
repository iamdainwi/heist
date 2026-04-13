use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use crate::{
    cli::{ExportArgs, ExportFormat},
    error::{HeistError, Result},
    output,
    store::Store,
    vault::{AuditAction, Secret},
};

pub fn run(args: ExportArgs, vault_path: &Path) -> Result<()> {
    let password = prompt_password()?;
    let mut store = Store::open(vault_path, &password)?;

    // Filter secrets.
    let mut secrets: Vec<(&String, &Secret)> = store
        .data
        .secrets
        .iter()
        .filter(|(key, secret)| {
            let prefix_ok = args
                .prefix
                .as_deref()
                .map(|p| key.starts_with(p))
                .unwrap_or(true);
            let tags_ok = args.tags.iter().all(|t| secret.tags.contains(t));
            prefix_ok && tags_ok
        })
        .collect();

    if secrets.is_empty() {
        return Err(HeistError::NoSecretsFound);
    }

    secrets.sort_by_key(|(k, _)| k.as_str());

    let rendered = render(&secrets, args.format)?;

    // Record export in audit log.
    store.audit.record(
        AuditAction::Export,
        "*",
        Some(format!(
            "format={:?}, count={}",
            args.format,
            secrets.len()
        )),
    );
    store.save()?;

    // Write output.
    match &args.output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(path, &rendered)?;
            output::success(&format!(
                "Exported {} secret{} to {}",
                secrets.len(),
                if secrets.len() == 1 { "" } else { "s" },
                path.display()
            ));
        }
        None => {
            io::stdout()
                .write_all(rendered.as_bytes())
                .map_err(HeistError::Io)?;
        }
    }

    Ok(())
}

// ── Renderers ─────────────────────────────────────────────────────────────────

fn render(secrets: &[(&String, &Secret)], format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Env => render_env(secrets),
        ExportFormat::Json => render_json(secrets),
        ExportFormat::Yaml => render_yaml(secrets),
    }
}

fn render_env(secrets: &[(&String, &Secret)]) -> Result<String> {
    let mut out = String::new();
    for (key, secret) in secrets {
        // Escape double quotes in the value.
        let escaped = secret.value.replace('"', "\\\"");
        out.push_str(&format!("{key}=\"{escaped}\"\n"));
    }
    Ok(out)
}

fn render_json(secrets: &[(&String, &Secret)]) -> Result<String> {
    use serde_json::{json, Map, Value};

    let mut map = Map::new();
    for (key, secret) in secrets {
        map.insert(
            (*key).clone(),
            json!({
                "value": secret.value,
                "description": secret.description,
                "tags": secret.tags,
                "updated_at": secret.updated_at,
            }),
        );
    }

    serde_json::to_string_pretty(&Value::Object(map))
        .map_err(|e| HeistError::ExportError(e.to_string()))
}

fn render_yaml(secrets: &[(&String, &Secret)]) -> Result<String> {
    use serde_yaml::Mapping;

    let mut map = Mapping::new();
    for (key, secret) in secrets {
        let mut entry = Mapping::new();
        entry.insert("value".into(), secret.value.clone().into());
        if let Some(desc) = &secret.description {
            entry.insert("description".into(), desc.clone().into());
        }
        if !secret.tags.is_empty() {
            entry.insert("tags".into(), secret.tags.clone().into());
        }
        map.insert((*key).clone().into(), entry.into());
    }

    serde_yaml::to_string(&map).map_err(|e| HeistError::ExportError(e.to_string()))
}

fn prompt_password() -> Result<String> {
    crate::prompt::get_master_password("Master password: ")
}

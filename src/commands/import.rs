use std::{collections::HashMap, fs, path::Path};

use crate::{
    cli::{ImportArgs, ImportFormat},
    error::{HeistError, Result},
    output,
    store::Store,
    vault::{validate_key, AuditAction, Secret},
};

pub fn run(args: ImportArgs, vault_path: &Path) -> Result<()> {
    let format = detect_format(&args)?;
    let content = fs::read_to_string(&args.file).map_err(HeistError::Io)?;

    let raw_pairs = parse_input(&content, format)?;

    if raw_pairs.is_empty() {
        output::warn("No secrets found in the input file.");
        return Ok(());
    }

    let password = prompt_password()?;
    let mut store = Store::open(vault_path, &password)?;

    let mut imported = 0usize;
    let mut skipped = 0usize;

    for (raw_key, value) in raw_pairs {
        // Prepend namespace if provided.
        let key = match &args.namespace {
            Some(ns) => format!("{ns}/{raw_key}"),
            None => raw_key.clone(),
        };

        if validate_key(&key).is_err() {
            output::warn(&format!("Skipping invalid key '{key}'"));
            skipped += 1;
            continue;
        }

        if store.data.secrets.contains_key(&key) && !args.overwrite {
            output::warn(&format!("Skipping existing key '{key}' (use --overwrite)"));
            skipped += 1;
            continue;
        }

        let secret = Secret::new(value, None, vec![]);
        store.data.secrets.insert(key, secret);
        imported += 1;
    }

    store.audit.record(
        AuditAction::Import,
        "*",
        Some(format!(
            "file={}, imported={imported}, skipped={skipped}",
            args.file.display()
        )),
    );
    store.save()?;

    output::success(&format!(
        "Imported {imported} secret{} ({skipped} skipped).",
        if imported == 1 { "" } else { "s" }
    ));
    Ok(())
}

// ── Format detection ──────────────────────────────────────────────────────────

fn detect_format(args: &ImportArgs) -> Result<ImportFormat> {
    if let Some(fmt) = args.format {
        return Ok(fmt);
    }
    let ext = args.file.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext.to_lowercase().as_str() {
        "json" => Ok(ImportFormat::Json),
        "yaml" | "yml" => Ok(ImportFormat::Yaml),
        "env" | "" => Ok(ImportFormat::Env),
        other => Err(HeistError::ImportError(format!(
            "cannot detect format from extension '.{other}'; use --format"
        ))),
    }
}

// ── Parsers ───────────────────────────────────────────────────────────────────

fn parse_input(content: &str, format: ImportFormat) -> Result<Vec<(String, String)>> {
    match format {
        ImportFormat::Env => parse_env(content),
        ImportFormat::Json => parse_json(content),
        ImportFormat::Yaml => parse_yaml(content),
    }
}

/// Parse `.env` format (`KEY=VALUE`, `#` comments, quoted values).
fn parse_env(content: &str) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for (lineno, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=').ok_or_else(|| {
            HeistError::ImportError(format!("line {}: missing '=' separator", lineno + 1))
        })?;
        let key = k.trim().to_string();

        let value = strip_quotes(v.trim()).to_string();
        pairs.push((key, value));
    }
    Ok(pairs)
}

/// Parse a flat JSON object into key-value pairs.
fn parse_json(content: &str) -> Result<Vec<(String, String)>> {
    let map: HashMap<String, serde_json::Value> = serde_json::from_str(content)
        .map_err(|e| HeistError::ImportError(format!("JSON parse error: {e}")))?;

    let pairs = map
        .into_iter()
        .map(|(k, v)| {
            let val = match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            (k, val)
        })
        .collect();

    Ok(pairs)
}

/// Parse a flat YAML mapping into key-value pairs.
fn parse_yaml(content: &str) -> Result<Vec<(String, String)>> {
    let map: HashMap<String, serde_yaml::Value> = serde_yaml::from_str(content)
        .map_err(|e| HeistError::ImportError(format!("YAML parse error: {e}")))?;

    let pairs = map
        .into_iter()
        .map(|(k, v)| {
            let val = match v {
                serde_yaml::Value::String(s) => s,
                serde_yaml::Value::Number(n) => n.to_string(),
                serde_yaml::Value::Bool(b) => b.to_string(),
                other => format!("{other:?}"),
            };
            (k, val)
        })
        .collect();

    Ok(pairs)
}

fn strip_quotes(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn prompt_password() -> Result<String> {
    crate::prompt::get_master_password("Master password: ")
}

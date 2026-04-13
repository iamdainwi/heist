//! Terminal output helpers — colours, tables, status messages.
//!
//! All user-visible formatting lives here so that individual commands stay
//! focused on logic rather than presentation.

use chrono::{DateTime, Local, Utc};
use colored::Colorize;
use comfy_table::{presets::UTF8_BORDERS_ONLY, Attribute, Cell, Color, ContentArrangement, Table};

use crate::vault::{AuditEntry, AuditLog, Secret};

// ── Status lines ──────────────────────────────────────────────────────────────

pub fn success(msg: &str) {
    eprintln!("{} {}", "✓".green().bold(), msg);
}

pub fn info(msg: &str) {
    eprintln!("{} {}", "·".cyan(), msg);
}

pub fn warn(msg: &str) {
    eprintln!("{} {}", "!".yellow().bold(), msg);
}

pub fn error_msg(msg: &str) {
    eprintln!("{} {}", "✗".red().bold(), msg);
}

// ── Secret value display ──────────────────────────────────────────────────────

/// Print a secret value to **stdout** (suitable for piping).
pub fn print_value(value: &str) {
    println!("{value}");
}

/// Print a secret with its metadata to stderr and value to stdout.
pub fn print_secret(key: &str, secret: &Secret) {
    eprintln!("{}", key.cyan().bold());
    eprintln!(
        "  {} {}",
        "value:".dimmed(),
        secret.value.green()
    );
    if let Some(desc) = &secret.description {
        eprintln!("  {} {}", "desc: ".dimmed(), desc);
    }
    if !secret.tags.is_empty() {
        eprintln!("  {} {}", "tags: ".dimmed(), secret.tags.join(", ").yellow());
    }
    eprintln!(
        "  {} {}",
        "updated:".dimmed(),
        fmt_local(secret.updated_at)
    );
}

// ── Secret list table ─────────────────────────────────────────────────────────

pub fn print_secrets_table(secrets: &[(String, &Secret)]) {
    if secrets.is_empty() {
        info("No secrets found.");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_BORDERS_ONLY)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("KEY")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("DESCRIPTION")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("TAGS")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("UPDATED")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
        ]);

    let mut sorted = secrets.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    for (key, secret) in &sorted {
        table.add_row(vec![
            Cell::new(key).fg(Color::Green),
            Cell::new(secret.description.as_deref().unwrap_or("—")),
            Cell::new(if secret.tags.is_empty() {
                "—".to_string()
            } else {
                secret.tags.join(", ")
            })
            .fg(Color::Yellow),
            Cell::new(fmt_local(secret.updated_at)).fg(Color::DarkGrey),
        ]);
    }

    eprintln!("{table}");
    eprintln!(
        "  {} secret{}",
        sorted.len().to_string().bold(),
        if sorted.len() == 1 { "" } else { "s" }
    );
}

// ── Audit log table ───────────────────────────────────────────────────────────

pub fn print_audit_table(log: &AuditLog, limit: usize, key_filter: Option<&str>) {
    let entries: Vec<&AuditEntry> = log
        .entries
        .iter()
        .rev()
        .filter(|e| {
            key_filter
                .map(|f| e.key.starts_with(f))
                .unwrap_or(true)
        })
        .take(limit)
        .collect();

    if entries.is_empty() {
        info("No audit log entries found.");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_BORDERS_ONLY)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("TIMESTAMP")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("ACTION")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("KEY")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("NOTE")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
        ]);

    for entry in &entries {
        let action_cell = Cell::new(entry.action.to_string()).fg(action_color(&entry.action));
        table.add_row(vec![
            Cell::new(fmt_local(entry.timestamp)).fg(Color::DarkGrey),
            action_cell,
            Cell::new(&entry.key).fg(Color::Green),
            Cell::new(entry.note.as_deref().unwrap_or("—")),
        ]);
    }

    eprintln!("{table}");
    eprintln!(
        "  Showing {} of {} entr{}",
        entries.len(),
        log.entries.len(),
        if log.entries.len() == 1 { "y" } else { "ies" }
    );
}

// ── Vault info ────────────────────────────────────────────────────────────────

pub fn print_vault_info(path: &std::path::Path, secret_count: usize, created_at: DateTime<Utc>) {
    eprintln!("{}", "Vault information".bold().underline());
    eprintln!("  {} {}", "path:    ".dimmed(), path.display().to_string().green());
    eprintln!("  {} {}", "secrets: ".dimmed(), secret_count.to_string().yellow().bold());
    eprintln!("  {} {}", "created: ".dimmed(), fmt_local(created_at));
    eprintln!("  {} {}", "cipher:  ".dimmed(), "AES-256-GCM");
    eprintln!("  {} {}", "kdf:     ".dimmed(), "Argon2id (m=65536, t=3, p=4)");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fmt_local(dt: DateTime<Utc>) -> String {
    let local: DateTime<Local> = dt.into();
    local.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn action_color(action: &crate::vault::AuditAction) -> Color {
    use crate::vault::AuditAction::*;
    match action {
        Set | Import | Init => Color::Green,
        Get | Copy | Exec => Color::Cyan,
        Delete => Color::Red,
        Export | Rotate => Color::Yellow,
    }
}

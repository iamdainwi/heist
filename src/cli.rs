//! CLI argument definitions (clap).
//!
//! Top-level entry point is [`Cli`]; subcommands are enumerated in [`Command`].

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

/// heist — a secure, encrypted secrets manager for the terminal.
#[derive(Parser, Debug)]
#[command(
    name = "heist",
    version,
    author,
    about = "A secure, encrypted secrets manager for the terminal.",
    long_about = None,
    propagate_version = true,
)]
pub struct Cli {
    /// Path to the vault file.
    ///
    /// Defaults to `~/.heist/vault.heist`. Can also be set via the
    /// `HEIST_VAULT` environment variable.
    #[arg(
        long,
        env = "HEIST_VAULT",
        global = true,
        value_name = "FILE",
        help = "Path to vault file [env: HEIST_VAULT]"
    )]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Initialise a new vault.
    Init(InitArgs),
    /// Store or update a secret.
    Set(SetArgs),
    /// Retrieve a secret value.
    Get(GetArgs),
    /// List secrets.
    #[command(alias = "ls")]
    List(ListArgs),
    /// Delete a secret.
    #[command(alias = "rm")]
    Remove(RemoveArgs),
    /// Copy a secret value to the clipboard.
    #[command(alias = "cp")]
    Copy(CopyArgs),
    /// Execute a command with secrets injected as environment variables.
    Exec(ExecArgs),
    /// Import secrets from a file.
    Import(ImportArgs),
    /// Export secrets to stdout or a file.
    Export(ExportArgs),
    /// Display the encrypted audit log.
    Log(LogArgs),
    /// Rotate the master password (re-encrypts the vault with a new key).
    Rotate,
    /// Display vault metadata.
    Info,
    /// Print a shell completion script.
    Completion(CompletionArgs),
}

// ── init ──────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Overwrite an existing vault without prompting.
    #[arg(long, short)]
    pub force: bool,
}

// ── set ───────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct SetArgs {
    /// Secret key (e.g. `aws/access-key`, `DATABASE_URL`).
    pub key: String,

    /// Secret value.  If omitted, it is read from stdin (preferred for
    /// sensitive values — avoids shell history).
    #[arg(short, long, value_name = "VALUE")]
    pub value: Option<String>,

    /// Human-readable description of this secret.
    #[arg(short, long, value_name = "TEXT")]
    pub description: Option<String>,

    /// Comma-separated tags (e.g. `prod,aws,infra`).
    #[arg(short, long, value_name = "TAG1,TAG2,...", value_delimiter = ',')]
    pub tags: Vec<String>,
}

// ── get ───────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Secret key.
    pub key: String,

    /// Copy the value to the clipboard instead of printing it.
    #[arg(short, long)]
    pub clip: bool,

    /// Seconds before the clipboard is cleared (only with --clip).
    #[arg(long, default_value = "45", value_name = "SECS")]
    pub timeout: u64,

    /// Print metadata alongside the value.
    #[arg(short, long)]
    pub meta: bool,
}

// ── list ──────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Filter secrets whose key starts with this prefix/namespace.
    #[arg(value_name = "PREFIX")]
    pub prefix: Option<String>,

    /// Filter by tag (repeatable).
    #[arg(short, long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,

    /// Output as JSON array.
    #[arg(long)]
    pub json: bool,
}

// ── remove ────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Secret key.
    pub key: String,

    /// Skip the confirmation prompt.
    #[arg(short, long)]
    pub yes: bool,
}

// ── copy ──────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct CopyArgs {
    /// Secret key.
    pub key: String,

    /// Seconds before the clipboard is cleared automatically.
    #[arg(long, default_value = "45", value_name = "SECS")]
    pub timeout: u64,
}

// ── exec ──────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct ExecArgs {
    /// One or more secret keys to inject as environment variables.
    ///
    /// Each key is uppercased and `/`, `-`, `.` are replaced with `_`.
    /// Example: `aws/access-key` → `AWS_ACCESS_KEY`.
    #[arg(value_name = "KEY", required = true, num_args = 1..)]
    pub keys: Vec<String>,

    /// The command and its arguments to execute.
    #[arg(last = true, required = true, value_name = "CMD")]
    pub cmd: Vec<String>,
}

// ── import ────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Path to the file to import from.
    pub file: PathBuf,

    /// Input format.  Detected from file extension when omitted.
    #[arg(short, long, value_name = "FORMAT")]
    pub format: Option<ImportFormat>,

    /// Namespace prefix to prepend to all imported keys (e.g. `prod`).
    #[arg(short, long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Overwrite existing secrets without prompting.
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Env,
    Json,
    Yaml,
}

// ── export ────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output format.
    #[arg(short, long, default_value = "env", value_name = "FORMAT")]
    pub format: ExportFormat,

    /// Write to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Filter secrets whose key starts with this prefix.
    #[arg(value_name = "PREFIX")]
    pub prefix: Option<String>,

    /// Filter by tag (repeatable).
    #[arg(short, long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Env,
    Json,
    Yaml,
}

// ── log ───────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct LogArgs {
    /// Maximum number of entries to display.
    #[arg(short, long, default_value = "50", value_name = "N")]
    pub limit: usize,

    /// Filter entries by secret key prefix.
    #[arg(short, long, value_name = "KEY")]
    pub key: Option<String>,
}

// ── completion ────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct CompletionArgs {
    /// Target shell.
    pub shell: Shell,
}

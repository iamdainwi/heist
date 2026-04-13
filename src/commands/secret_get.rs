use std::path::Path;

use crate::{
    cli::GetArgs,
    error::{HeistError, Result},
    output, prompt,
    store::Store,
    vault::AuditAction,
};

pub fn run(args: GetArgs, vault_path: &Path) -> Result<()> {
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
        .record(AuditAction::Get, &args.key, None);
    store.save()?;

    if args.clip {
        copy_to_clipboard(&secret.value, args.timeout)?;
        output::success(&format!(
            "Copied '{}' to clipboard. Clears in {} seconds.",
            args.key, args.timeout
        ));
    } else if args.meta {
        output::print_secret(&args.key, &secret);
        // Also print value to stdout for piping.
        output::print_value(&secret.value);
    } else {
        output::print_value(&secret.value);
    }

    Ok(())
}

pub(crate) fn copy_to_clipboard(value: &str, timeout_secs: u64) -> Result<()> {
    use arboard::Clipboard;
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    };

    let mut ctx = Clipboard::new()
        .map_err(|e| HeistError::ClipboardError(e.to_string()))?;
    ctx.set_text(value.to_string())
        .map_err(|e| HeistError::ClipboardError(e.to_string()))?;

    // Spawn a background thread to clear the clipboard after `timeout_secs`.
    let value_owned = value.to_string();
    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(timeout_secs));
        if done_clone.load(Ordering::SeqCst) {
            return;
        }
        // Only clear if the clipboard still holds our value (user may have
        // copied something else in the meantime).
        if let Ok(mut ctx2) = Clipboard::new() {
            if ctx2.get_text().ok().as_deref() == Some(&value_owned) {
                let _ = ctx2.set_text(String::new());
            }
        }
    });

    // Register a Ctrl-C handler that marks the background thread done.
    ctrlc::set_handler(move || {
        done.store(true, Ordering::SeqCst);
        std::process::exit(0);
    })
    .ok(); // Ignore if a handler is already set.

    Ok(())
}

fn prompt_password() -> Result<String> {
    prompt::get_master_password("Master password: ")
}

use std::path::Path;

use crate::{
    cli::LogArgs,
    error::Result,
    output,
    store::Store,
};

pub fn run(args: LogArgs, vault_path: &Path) -> Result<()> {
    let password = prompt_password()?;
    let store = Store::open(vault_path, &password)?;

    output::print_audit_table(&store.audit, args.limit, args.key.as_deref());
    Ok(())
}

fn prompt_password() -> Result<String> {
    crate::prompt::get_master_password("Master password: ")
}

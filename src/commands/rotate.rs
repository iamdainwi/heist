use std::path::Path;

use crate::{
    error::Result,
    output, prompt,
    store::Store,
};

pub fn run(vault_path: &Path) -> Result<()> {
    output::info("Rotating master password...");
    let old_pw = prompt::get_master_password("Current master password: ")?;

    let mut store = Store::open(vault_path, &old_pw)?;

    let new_pw = super::init::prompt_new_password()?;
    store.rotate_password(&new_pw)?;

    output::success("Master password rotated. Vault re-encrypted with new key.");
    Ok(())
}

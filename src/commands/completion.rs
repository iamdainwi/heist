use std::io;

use clap::CommandFactory;
use clap_complete::generate;

use crate::{cli::{Cli, CompletionArgs}, error::Result};

pub fn run(args: CompletionArgs) -> Result<()> {
    let mut cmd = Cli::command();
    generate(args.shell, &mut cmd, "heist", &mut io::stdout());
    Ok(())
}

//! `redoubtful run`: execute a command inside the sandbox.
//!
//! The sandbox is not yet implemented; for now this simply runs the command
//! on the host so we can build up the CLI surface incrementally.

use tokio::process::Command;

use crate::prelude::*;

/// Arguments to `redoubtful run`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The command to execute, e.g. `redoubtful run cargo build`.
    #[arg(value_name = "COMMAND")]
    pub command: String,

    /// Arguments to pass to the command. Hyphen-prefixed args pass through
    /// as-is.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ARGS"
    )]
    pub args: Vec<String>,
}

/// Execute a command. In v1 this will wrap the command in pasta + bwrap;
/// for now it just runs on the host so the CLI can be fleshed out.
#[instrument(level = "debug", name = "run", skip_all)]
pub async fn cmd_run(args: Args) -> Result<()> {
    let Args { command, args } = args;
    debug!(command, ?args, "executing command (no sandbox yet)");

    let status = Command::new(&command)
        .args(&args)
        .status()
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to run `{command}`"))?;

    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(Error::Exit(code)),
        None => Err(miette!("`{command}` was terminated by a signal").into()),
    }
}

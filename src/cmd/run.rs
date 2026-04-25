//! `redoubtful run`: execute a command inside the sandbox.

use std::os::unix::process::ExitStatusExt as _;

use tokio::process::Command;

use crate::mounts::{current_dir, default_mount_list, home_dir};
use crate::prelude::*;
use crate::sandbox::bwrap_argv;

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

/// Execute `<command> [args...]` inside a bwrap sandbox.
///
/// v0: hides $HOME with a tmpfs and re-exposes $PWD at its real path.
/// No pasta yet — host network is inherited.
#[instrument(level = "debug", name = "run", skip_all)]
pub async fn cmd_run(args: Args) -> Result<()> {
    let Args { command, args } = args;
    debug!(command, ?args, "executing command in sandbox");

    let home = home_dir()?;
    let cwd = current_dir()?;
    let mounts = default_mount_list(&home, &cwd);
    let bwrap_args = bwrap_argv(&mounts, &cwd, &command, &args);

    let status = Command::new("bwrap")
        .args(&bwrap_args)
        .status()
        .await
        .map_err(|e| Error::could_not_run("bwrap", e))?;

    // We invoke bwrap as the immediate child, but the user thinks of
    // their command as the thing that ran — so error variants below
    // include both, for clarity.
    let cmd_summary = format!("bwrap {}", command);
    match (status.code(), status.signal()) {
        (Some(0), _) => Ok(()),
        (Some(code), _) => Err(Error::exit(cmd_summary, code)),
        (None, Some(signal)) => Err(Error::signal(cmd_summary, signal)),
        (None, None) => {
            warn!(
                "process terminated without exit code or signal; treating as exit code 1"
            );
            Err(Error::exit(cmd_summary, 1))
        }
    }
}

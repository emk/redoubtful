//! `redoubtful check`: validate that the host can run the sandbox.
//!
//! Always prints the full report to stdout and exits non-zero if
//! any check failed. The same machinery powers `redoubtful run`'s
//! preflight (see `cmd::run`) — there, the report is suppressed on
//! all-pass and emitted to stderr only on failure.

use crate::check::{any_failed, print_report_to_stderr, run_all_checks};
use crate::prelude::*;

/// Arguments to `redoubtful check`. Empty for now; reserved for
/// future flags like `--json`.
#[derive(Debug, clap::Args)]
pub struct Args {}

/// Run the preflight checks and print a full report.
///
/// Output goes to **stderr**, matching `redoubtful run`'s preflight
/// failure path. The check report is diagnostic, not data — nobody
/// pipes `redoubtful check` into `jq` — so stderr is the right
/// channel and keeps stdout free for a future `--json` mode.
#[instrument(level = "debug", name = "check", skip_all)]
pub async fn cmd_check(_args: Args) -> Result<()> {
    let results = run_all_checks().await?;
    print_report_to_stderr(&results)?;
    if any_failed(&results) {
        Err(Error::exit("redoubtful check", 1))
    } else {
        Ok(())
    }
}

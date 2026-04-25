//! `redoubtful mounts`: print the sandbox's mount inventory.
//!
//! Used by humans for "what's actually in there?" debugging, and by
//! the integration test suite as the source of truth for the
//! `run_hides_unexpected_paths_in_home` assertion. Emitting the
//! same inventory the sandbox builder consumes means the test asks
//! the binary "what should be visible?" rather than hardcoding an
//! answer that can drift from the implementation.

use std::io::{self, Write as _};

use crate::mounts::{current_dir, default_mount_list, home_dir};
use crate::prelude::*;

/// Arguments to `redoubtful mounts`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Emit one JSON object per mount, one per line. Currently the
    /// only supported output format; required as a forward-compat
    /// hook so we can add default textual output later.
    #[arg(long, required = true)]
    pub jsonl: bool,
}

/// Print the sandbox's mount inventory.
#[instrument(level = "debug", name = "mounts", skip_all)]
pub async fn cmd_mounts(_args: Args) -> Result<()> {
    let home = home_dir()?;
    let cwd = current_dir()?;
    let mounts = default_mount_list(&home, &cwd);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for m in &mounts {
        // `serde_json::to_string` is infallible for [`Mount`] (no
        // maps with non-string keys, no float NaN/Inf, no custom
        // serializers). If this trips, it's a programmer error in
        // the type definition, not user input.
        #[allow(clippy::expect_used)]
        let line =
            serde_json::to_string(m).expect("Mount serializes infallibly");
        writeln!(out, "{line}").map_err(Error::could_not_write_stdout)?;
    }
    Ok(())
}

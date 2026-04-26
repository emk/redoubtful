//! `redoubtful mounts`: print the sandbox's mount inventory.
//!
//! Used by humans for "what's actually in there?" debugging, and by
//! the integration test suite as the source of truth for the
//! `run_hides_unexpected_paths_in_home` assertion. Emitting the
//! same inventory the sandbox builder consumes means the test asks
//! the binary "what should be visible?" rather than hardcoding an
//! answer that can drift from the implementation.
//!
//! `MountOpts` is flattened in here so `mounts --jsonl -m /foo`
//! reflects user-added mounts too — otherwise the audit/test
//! allowlist would silently miss anything passed via `-m`/`--mount-rw`
//! at `run` time.

use std::io::{self, Write as _};

use crate::mounts::{MountList, MountOpts, current_dir, home_dir};
use crate::prelude::*;

/// Arguments to `redoubtful mounts`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Emit one JSON object per mount, one per line. Currently the
    /// only supported output format; required as a forward-compat
    /// hook so we can add default textual output later.
    #[arg(long, required = true)]
    pub jsonl: bool,

    /// `-m, --mount` and `--mount-rw` flags, mirrored from `run`
    /// so the inventory output reflects whatever mounts the user
    /// would get with the same flags.
    #[command(flatten)]
    pub mount_opts: MountOpts,
}

/// Print the sandbox's mount inventory.
#[instrument(level = "debug", name = "mounts", skip_all)]
pub async fn cmd_mounts(args: Args) -> Result<()> {
    let Args {
        jsonl: _,
        mount_opts,
    } = args;

    // Validate first so a bad CLI mount fails before any output —
    // matches `run`'s behavior so the two stay in sync.
    mount_opts.validate()?;

    let home = home_dir()?;
    let cwd = current_dir()?;
    let mut mounts = MountList::default_baseline(&home, &cwd);
    mount_opts.apply(&mut mounts);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for m in mounts.iter() {
        // `serde_json::to_string` is infallible for `Mount` (no
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

//! `redoubtful forwards`: print the sandbox's TCP forward inventory.
//!
//! Mirror of [`crate::cmd::mounts`] for the network side: emits the
//! same forward list `redoubtful run` would configure for a given
//! set of `-f`/`--forward` flags. Tests and humans both consume
//! this as the source of truth for "what host ports does the
//! sandbox actually see?".

use std::io::{self, Write as _};

use crate::forward::{ForwardList, ForwardOpts};
use crate::prelude::*;

/// Arguments to `redoubtful forwards`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Emit one JSON object per forward, one per line. Currently
    /// the only supported output format; required as a forward-compat
    /// hook so we can add default textual output later.
    #[arg(long, required = true)]
    pub jsonl: bool,

    /// `-f, --forward` flags, mirrored from `run`.
    #[command(flatten)]
    pub forward_opts: ForwardOpts,
}

/// Print the sandbox's forward inventory.
#[instrument(level = "debug", name = "forwards", skip_all)]
pub async fn cmd_forwards(args: Args) -> Result<()> {
    let Args {
        jsonl: _,
        forward_opts,
    } = args;

    let mut forwards = ForwardList::new();
    forward_opts.apply(&mut forwards);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for f in forwards.iter() {
        // `serde_json::to_string` is infallible for `Forward` (no
        // maps with non-string keys, no float NaN/Inf, no custom
        // serializers). If this trips, it's a programmer error in
        // the type definition, not user input.
        #[allow(clippy::expect_used)]
        let line =
            serde_json::to_string(f).expect("Forward serializes infallibly");
        writeln!(out, "{line}").map_err(Error::could_not_write_stdout)?;
    }
    Ok(())
}

//! `redoubtful show`: print the sandbox config `run` would build.
//!
//! Combined audit/inspector for mounts + TCP forwards. Tests and humans
//! both consume this as the source of truth for "what would
//! `run -m … -f …` actually configure?". Mirroring `run`'s setup
//! (same `MountOpts`/`ForwardOpts`, same baseline construction) means
//! the answer can't drift from what `run` actually builds.

use std::io::{self, Write as _};

use serde::Serialize;

use crate::env::{EnvList, EnvOpts};
use crate::forward::{ForwardList, ForwardOpts};
use crate::mounts::{MountList, MountOpts, current_dir, home_dir};
use crate::prelude::*;

/// Arguments to `redoubtful show`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Emit a JSON object describing the sandbox config. Currently
    /// the only supported output format; required as a forward-compat
    /// hook so we can add a default textual mode later.
    #[arg(long, required = true)]
    pub json: bool,

    /// `-m, --mount` and `--readonly` flags, mirrored from `run`
    /// so the inventory output reflects whatever mounts the user
    /// would get with the same flags.
    #[command(flatten)]
    pub mount_opts: MountOpts,

    /// `-f, --forward` flags, mirrored from `run`.
    #[command(flatten)]
    pub forward_opts: ForwardOpts,

    /// `-e, --env` and `--path` flags, mirrored from `run`.
    #[command(flatten)]
    pub env_opts: EnvOpts,
}

/// Top-level JSON envelope: one object holding all inventories.
#[derive(Serialize)]
struct Output<'a> {
    mounts: &'a MountList,
    forwards: &'a ForwardList,
    env: &'a EnvList,
}

/// Print the sandbox config `run` would build.
#[instrument(level = "debug", name = "show", skip_all)]
pub async fn cmd_show(args: Args) -> Result<()> {
    let Args {
        json: _,
        mount_opts,
        forward_opts,
        env_opts,
    } = args;

    // Validate first so a bad CLI mount fails before any output —
    // matches `run`'s behavior so the two stay in sync.
    mount_opts.validate()?;

    let home = home_dir()?;
    let cwd = current_dir()?;
    let mut mounts =
        MountList::default_baseline(&home, &cwd, mount_opts.cwd_access());
    mount_opts.apply(&mut mounts);

    let mut forwards = ForwardList::default_baseline();
    forward_opts.apply(&mut forwards);

    // Mirror `cmd_run`'s env construction so `show --json` describes
    // exactly what `run` would emit at this same instant — same
    // `home` path goes into `default_baseline` so the env and the
    // mount layer agree on `$HOME`.
    let mut env = EnvList::default_baseline(
        &home,
        env_opts.path.as_deref(),
        &env_opts.path_add,
    );
    env_opts.apply(&mut env);

    let body = Output {
        mounts: &mounts,
        forwards: &forwards,
        env: &env,
    };
    // `serde_json::to_string_pretty` is infallible for `Output` (no
    // maps with non-string keys, no float NaN/Inf, no custom
    // serializers). If this trips, it's a programmer error in the
    // type definition, not user input.
    #[allow(clippy::expect_used)]
    let s = serde_json::to_string_pretty(&body)
        .expect("Output serializes infallibly");

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{s}").map_err(Error::could_not_write_stdout)?;
    Ok(())
}

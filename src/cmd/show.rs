//! `redoubtful show`: print the sandbox config `run` would build.
//!
//! Combined audit/inspector for mounts + TCP forwards. Tests and humans
//! both consume this as the source of truth for "what would
//! `run -m … -f …` actually configure?". Mirroring `run`'s setup
//! (same [`crate::config::config_file::ConfigFile::finalize_config_with_cli`]
//! pipeline) means the answer can't drift from what `run` actually builds.

use std::io::{self, Write as _};

use serde::Serialize;

use crate::{
    config::{
        config_file::ConfigFile,
        env_vars::EnvVars,
        forwards::Forwards,
        mounts::Mounts,
        profile::{Profile, ProfileDecl},
    },
    prelude::*,
};

/// Arguments to `redoubtful show`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Emit a JSON object describing the sandbox config. Currently
    /// the only supported output format; required as a forward-compat
    /// hook so we can add a default textual mode later.
    #[arg(long, required = true)]
    pub json: bool,

    /// The crate to use
    #[clap(flatten)]
    pub profile: ProfileDecl,
}

/// Top-level JSON envelope: one object holding all inventories.
#[derive(Serialize)]
struct Output<'a> {
    mounts: &'a Mounts,
    forwards: &'a Forwards,
    env: &'a EnvVars,
}

/// Print the sandbox config `run` would build.
#[instrument(level = "debug", name = "show", skip_all)]
pub async fn cmd_show(args: Args) -> Result<()> {
    let Args { json: _, profile } = args;
    debug!(?profile, "show sandbox config");

    // [`ConfigFile::finalize_config_with_cli`] is shared with
    // `cmd_run` so `show -p X` describes exactly what `run -p X`
    // would build, including the up-front `validate()` pass on every
    // resolved profile (TOML + CLI).
    let Profile {
        mounts,
        forwards,
        env,
    } = ConfigFile::finalize_config_with_cli(&profile)?;

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

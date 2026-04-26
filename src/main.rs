//! Entry point for the `redoubtful` sandbox tool.

mod argv;
mod bwrap;
mod cmd;
mod deps;
mod errors;
mod forward;
mod mounts;
mod pasta;
mod prelude;

use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, fmt};

use crate::prelude::*;

/// Run coding agents inside a tight Linux sandbox.
#[derive(Debug, Parser)]
#[command(name = "redoubtful", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Top-level `redoubtful` subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Run a command inside the sandbox.
    Run(cmd::run::Args),

    /// Print the sandbox's mount inventory.
    Mounts(cmd::mounts::Args),

    /// Print the sandbox's TCP forward inventory.
    Forwards(cmd::forwards::Args),
}

// We use `current_thread`, not the multi-thread default, on purpose: the pasta
// lifecycle binding in `cmd::run` uses `PR_SET_PDEATHSIG`, which the kernel
// ties to the *thread* that called `fork()`, not the parent process. With a
// multi-thread runtime, that thread is whichever worker happened to poll the
// spawning task — fine in practice today (tokio workers only exit when the
// runtime drops) but a footgun under any future refactor that introduces
// another runtime, parks/joins workers, or moves the spawn off the main task.
// `current_thread` makes the parent-of-pasta the main thread, which only exits
// when redoubtful itself exits, so the prctl's "fire when parent dies"
// semantics line up with our intent without depending on tokio's
// worker-lifecycle implementation details. We don't lose anything: nothing in
// this binary needs to parallelize across cores.
//
// If we relax this later (e.g. the credential proxy becomes CPU-bound enough to
// want a worker pool), the property the PR_SET_PDEATHSIG site needs is: **the
// OS thread that calls `pasta`'s `Command::spawn()` lives as long as the
// executable does.** Today that's true for tokio worker threads (they're
// destroyed only when the runtime is dropped, which only happens as main
// returns), so the multi-thread default is *also* safe in practice — the reason
// to prefer `current_thread` here is that "the main thread" is a guarantee in
// the language and "tokio workers outlive the runtime" is an implementation
// detail.
#[tokio::main(flavor = "current_thread")]
async fn main() -> miette::Result<()> {
    // Set up logging first.
    init_tracing();

    match run().await {
        Ok(()) => Ok(()),
        // Propagate a child process's exit code verbatim.
        Err(Error::Exit { code, .. }) => std::process::exit(code),
        // Hand other errors to miette's `Termination` impl for pretty
        // diagnostic rendering.
        Err(other) => Err(miette::Report::new(other)),
    }
}

/// Real top-level logic, now that we have logging.
#[instrument(level = "debug", name = "redoubtful", skip_all)]
async fn run() -> Result<()> {
    // Parse our command-line arguments.
    let cli = Cli::parse();
    debug!(?cli, "arguments");

    match cli.command {
        Command::Run(args) => {
            // `redoubtful run` actually launches the sandbox, so probe
            // bwrap/pasta first and bail with a friendly error if they
            // are missing.
            let versions = deps::probe_required().await?;
            debug!(
                bwrap = %versions.bwrap,
                pasta = %versions.pasta,
                "external dependencies found",
            );
            cmd::run::cmd_run(args).await
        }
        // `redoubtful mounts` only inspects what we'd construct, so it
        // doesn't need bwrap/pasta to be installed.
        Command::Mounts(args) => cmd::mounts::cmd_mounts(args).await,
        // Same: `forwards` is a pure inspector.
        Command::Forwards(args) => cmd::forwards::cmd_forwards(args).await,
    }
}

/// Initialize the `tracing` subscriber. Reads `RUST_LOG` if set; otherwise
/// defaults to `info` for this crate and `warn` for everything else. Writes
/// to stderr so it does not pollute sandboxed child-process stdout.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("redoubtful=info,warn"));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

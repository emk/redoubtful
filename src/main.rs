//! Entry point for the `redoubtful` sandbox tool.

mod cmd;
mod deps;
mod errors;
mod mounts;
mod prelude;
mod sandbox;

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
}

#[tokio::main]
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

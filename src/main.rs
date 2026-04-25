//! Entry point for the `redoubtful` sandbox tool.

mod cmd;
mod deps;
mod errors;
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
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    // Set up logging first.
    init_tracing();

    match run().await {
        Ok(()) => Ok(()),
        // Propagate a child process's exit code verbatim.
        Err(Error::Exit(code)) => std::process::exit(code),
        // Hand any other error to `miette`'s `Termination` impl, which
        // renders it via `Report`'s fancy `Debug` and exits non-zero.
        Err(Error::Other(report)) => Err(report),
    }
}

/// Real top-level logic, now that we have logging.
#[instrument(level = "debug", name = "redoubtful", skip_all)]
async fn run() -> Result<()> {
    // Parse our command-line arguments.
    let cli = Cli::parse();
    debug!(?cli, "arguments");

    // Check that our external dependencies are present and log their versions.
    let versions = deps::probe_required().await?;
    debug!(
        bwrap = %versions.bwrap,
        pasta = %versions.pasta,
        "external dependencies found",
    );

    match cli.command {
        Command::Run(args) => cmd::run::cmd_run(args).await,
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

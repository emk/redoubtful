//! Entry point for the `redoubtful` sandbox tool.

mod deps;
mod prelude;

use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

use crate::prelude::*;

/// Run coding agents inside a tight Linux sandbox.
#[derive(Debug, Parser)]
#[command(name = "redoubtful", version, about)]
struct Cli {
    // Subcommands will be added in a later change.
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging first.
    init_tracing();

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
    Ok(())
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

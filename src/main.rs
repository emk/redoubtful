//! Entry point for the `redoubtful` sandbox tool.

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
    init_tracing();
    let _cli = Cli::parse();
    debug!("redoubtful started");
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

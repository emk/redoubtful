//! Sandbox subsystem: argv building, network, isolation, and proxying.
//!
//! The sandbox is assembled from four layers, each with its own module:
//!
//! - [`argv`]: Shared `ArgvBuilder` for constructing `Vec<OsString>` argument
//!   vectors legibly. Used by both [`bwrap`] and [`pasta`].
//! - [`pasta`]: Builds the pasta command line that creates a private network
//!   namespace, connects it to the host via a tap-mode virtual link, and
//!   forwards an explicit allowlist of ports.
//! - [`bwrap`]: Builds the bwrap command line that creates mount/pid/user/ipc/
//!   uts/cgroup namespaces and inherits pasta's network namespace.
//! - [`proxy`]: A tunnel-only HTTPS proxy on host loopback that gives sandboxed
//!   clients a path to the Internet without exposing the host's full network.
//!
//! Process tree:
//!
//! ```text
//! redoubtful → pasta → bwrap → user command
//! ```

pub mod argv;
pub mod bwrap;
pub mod pasta;
pub mod proxy;

pub use bwrap::bwrap_argv;
pub use pasta::pasta_argv;
pub use proxy::{proxy_env_vars, start_proxy};

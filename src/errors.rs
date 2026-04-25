//! Top-level error type.
//!
//! `main` peels off [`Error::Exit`] to propagate a child process's exit code
//! verbatim, and hands [`Error::Other`] back to `miette`'s `Termination`
//! impl for pretty diagnostic rendering. Nothing below `main` needs to know
//! about this distinction — subcommand handlers just return `Ok`, an
//! `Error::Exit`, or (implicitly, via `?`) an `Error::Other`.

use std::fmt;

/// Errors propagated up to `main`.
pub enum Error {
    /// Exit with this code (typically a sandboxed child's exit code).
    Exit(i32),

    /// Any other error; rendered via `miette`.
    Other(miette::Report),
}

impl From<miette::Report> for Error {
    fn from(report: miette::Report) -> Self {
        Error::Other(report)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Exit(code) => write!(f, "Exit({code})"),
            Error::Other(report) => fmt::Debug::fmt(report, f),
        }
    }
}

/// Result type used throughout the crate. Error defaults to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

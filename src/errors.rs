//! Top-level error type.
//!
//! All errors propagated up to `main` are concrete variants of [`Error`],
//! which derives `miette::Diagnostic` for pretty rendering. `main` peels
//! off [`Error::Exit`] to propagate a sandboxed child's exit code verbatim,
//! and wraps any other variant in a `miette::Report` so its `Termination`
//! impl renders the diagnostic. Subcommand handlers just construct the
//! appropriate variant (or propagate one via `?`).

use std::io;
use std::path::PathBuf;

use miette::Diagnostic;

/// Result type used throughout the crate. Error defaults to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors propagated up to `main`.
#[derive(Debug, Diagnostic, thiserror::Error)]
pub enum Error {
    /// Wrapped process exited with this code
    #[error("`{command}` exited with code {code}")]
    Exit {
        /// The command that exited.
        command: String,

        /// The exit code.
        code: i32,
    },

    /// Wrapped process was terminated by a signal.
    #[error("`{command}` was terminated by signal {signal}")]
    Signal {
        /// The command that was terminated.
        command: String,

        /// The signal number.
        signal: i32,
    },

    /// Could not run a command.
    #[error("could not run `{command}`")]
    CouldNotRun {
        /// The command we tried to run.
        command: String,

        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Missing dependency.
    #[error(
        "`{command}` not found. Install the `{package}` package using your system package manager"
    )]
    MissingDependency {
        /// The missing binary.
        command: String,

        /// The package that provides the binary.
        package: String,
    },

    /// Could not get a version string from a dependency.
    #[error("`{command} --version` did not return a version string")]
    CouldNotGetVersion {
        /// The command we tried to get a version string from.
        command: String,
    },

    /// Could not determine the current working directory.
    #[error("could not determine current directory")]
    CouldNotGetCwd {
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// A required environment variable is not set.
    #[error("environment variable `{name}` is not set")]
    MissingEnvVar {
        /// The variable name.
        name: String,
    },

    /// Could not write to standard output.
    #[error("could not write to stdout")]
    CouldNotWriteStdout {
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// A `-m`/`--mount` host path could not be stat'ed.
    /// Stat'd up-front in `MountOpts::validate` so the user gets
    /// a clear diagnostic instead of bwrap's terser failure deep
    /// inside sandbox setup.
    #[error("mount host path `{path}` is not accessible")]
    MissingMountHost {
        /// The host path the user passed.
        path: PathBuf,

        /// The underlying I/O error from `stat`.
        #[source]
        source: io::Error,
    },
}

impl Error {
    /// Create an [`Error::Exit`].
    pub fn exit(command: impl Into<String>, code: i32) -> Self {
        Self::Exit {
            command: command.into(),
            code,
        }
    }

    /// Create an [`Error::Signal`].
    pub fn signal(command: impl Into<String>, signal: i32) -> Self {
        Self::Signal {
            command: command.into(),
            signal,
        }
    }

    /// Create an [`Error::CouldNotRun`].
    pub fn could_not_run(
        command: impl Into<String>,
        source: io::Error,
    ) -> Self {
        Self::CouldNotRun {
            command: command.into(),
            source,
        }
    }

    /// Create an [`Error::MissingDependency`].
    pub fn missing_dependency(
        command: impl Into<String>,
        package: impl Into<String>,
    ) -> Self {
        Self::MissingDependency {
            command: command.into(),
            package: package.into(),
        }
    }

    /// Create an [`Error::CouldNotGetVersion`].
    pub fn could_not_get_version(command: impl Into<String>) -> Self {
        Self::CouldNotGetVersion {
            command: command.into(),
        }
    }

    /// Create an [`Error::CouldNotGetCwd`].
    pub fn could_not_get_cwd(source: io::Error) -> Self {
        Self::CouldNotGetCwd { source }
    }

    /// Create an [`Error::MissingEnvVar`].
    pub fn missing_env_var(name: impl Into<String>) -> Self {
        Self::MissingEnvVar { name: name.into() }
    }

    /// Create an [`Error::CouldNotWriteStdout`].
    pub fn could_not_write_stdout(source: io::Error) -> Self {
        Self::CouldNotWriteStdout { source }
    }

    /// Create an [`Error::MissingMountHost`].
    pub fn missing_mount_host(path: PathBuf, source: io::Error) -> Self {
        Self::MissingMountHost { path, source }
    }
}

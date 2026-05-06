//! Top-level error type.
//!
//! All errors propagated up to `main` are concrete variants of [`Error`],
//! which derives `miette::Diagnostic` for pretty rendering. `main` peels
//! off [`Error::Exit`] to propagate a sandboxed child's exit code verbatim,
//! and wraps any other variant in a `miette::Report` so its `Termination`
//! impl renders the diagnostic. Subcommand handlers just construct the
//! appropriate variant (or propagate one via `?`).

use std::{io, path::PathBuf};

use miette::{Diagnostic, NamedSource, SourceSpan};

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

    /// Missing dependency. The message stays terse so the
    /// preflight report's per-check remediation can vary
    /// independently — see `check::probe_remediation`, which owns
    /// the binary→package mapping for install instructions.
    #[error("`{command}` not found on $PATH")]
    MissingDependency {
        /// The missing binary.
        command: String,
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

    /// Could not determine the path of the running `redoubtful` binary.
    /// We need this to emit an AppArmor profile attached to the right
    /// binary path; without it, any profile we printed would point at
    /// the wrong file. A `current_exe()` failure is also a strong
    /// signal that something is wrong with the host (deleted binary,
    /// missing /proc, exotic execve path) — bail rather than try to
    /// paper over it with a placeholder.
    #[error("could not determine the path of the redoubtful binary")]
    CouldNotGetCurrentExe {
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The redoubtful binary lives at a non-UTF-8 path, so we cannot
    /// substitute it into the AppArmor profile template. AppArmor
    /// profiles are configuration the user pastes verbatim into
    /// `apparmor_parser -r`, not diagnostic text — silently writing
    /// U+FFFD into the path field would produce a profile attached
    /// to the wrong binary, and the user would see the *same* userns
    /// failure on retry with no clue why the remediation didn't take.
    #[error(
        "redoubtful binary path is not valid UTF-8: `{}`; cannot generate AppArmor remediation",
        path.display(),
    )]
    NonUtf8ExePath {
        /// The non-UTF-8 path, preserved byte-for-byte.
        path: PathBuf,
    },

    /// Could not write to standard output.
    #[error("could not write to stdout")]
    CouldNotWriteStdout {
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// A `-m`/`--mount` host path could not be stat'ed.
    /// Stat'd up-front in `MountDecl::validate` so the user gets
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

    /// A `-f`/`--forward` port (or its TOML equivalent) is invalid.
    /// Port 0 is "any port" in TCP land and not a useful forward
    /// target; we reject it before pasta does so the user gets a
    /// clear error rather than a cryptic pasta failure.
    #[error("forward `{field}` value {value} is not a valid TCP port")]
    InvalidForwardPort {
        /// Which port slot rejected it (`"host_port"` or
        /// `"sandbox_port"`).
        field: String,

        /// The offending port value.
        value: u16,
    },

    /// An `-e`/`--env` (or its TOML equivalent) variable name is
    /// invalid. Empty names and NUL-containing names get rejected
    /// up-front so the user gets a clear error rather than a
    /// cryptic bwrap or `execve` failure later.
    #[error("env variable name `{name}` is invalid: {reason}")]
    InvalidEnvName {
        /// The offending name as it appeared.
        name: String,

        /// Why we rejected it.
        reason: String,
    },

    /// A path inside a TOML profile is malformed for the
    /// limited normalization redoubtful supports: only a leading
    /// `~/` (expanded against `$HOME`), or an already-absolute
    /// path. Anything else — `~user/foo`, `$VAR`, a relative
    /// `./foo` — gets rejected with a friendly diagnostic instead
    /// of silently mishandled. The user's mental model is "config
    /// paths look like `~/x` or `/x`, period."
    ///
    /// `path` is a [`PathBuf`] (not `String`) so a non-UTF-8 path —
    /// rare in TOML, but possible via [`std::os::unix::ffi`]
    /// round-trips elsewhere — is preserved byte-for-byte in the
    /// stored error. The lossy [`PathBuf::display`] hop in the
    /// `#[error]` formatter is policy-permitted because that's
    /// user-facing diagnostic output.
    #[error("invalid path `{}` in config: {reason}", path.display())]
    ConfigInvalidPath {
        /// The offending path as it appeared in the config.
        path: PathBuf,

        /// Why we rejected it (e.g. "relative paths are not
        /// supported", "`~user/` is not supported").
        reason: String,
    },

    /// Could not write the embedded default config to its
    /// expected location during the first-run dump. Permission
    /// denied, parent dir not creatable, read-only home, etc. We
    /// surface the OS error directly rather than letting it bubble
    /// up as a vaguer "I/O failed" — the user often needs to do
    /// something specific (chmod, mkdir, mount the home volume rw)
    /// to unstick this.
    #[error("could not write config file `{}`", path.display())]
    CouldNotWriteConfig {
        /// The path we tried to write.
        path: PathBuf,

        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Could not read the user's TOML config file.
    /// Distinguished from a parse error so missing-file vs
    /// permission-denied vs malformed-syntax all surface
    /// independently in the diagnostic.
    #[error("could not read config file `{}`", path.display())]
    CouldNotReadConfig {
        /// The path we tried to read.
        path: PathBuf,

        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// TOML config file failed to parse or didn't match the
    /// `Config` schema. Wraps a boxed [`ConfigParseError`] so the
    /// large `NamedSource<String>` payload doesn't bloat every
    /// `Result<T, Error>` return type past clippy's
    /// `result_large_err` threshold (the source-text copy alone
    /// pushes the variant well over 128 bytes).
    #[error(transparent)]
    #[diagnostic(transparent)]
    ConfigParse(#[from] Box<ConfigParseError>),

    /// `-p NAME` (or a `uses = [...]` reference) named a profile
    /// that's not defined in the loaded config. The path is
    /// surfaced so the user knows *which* file we looked in —
    /// otherwise the error is ambiguous between "I have no config
    /// at all" and "my config doesn't define this name."
    #[error(
        "unknown profile `{name}` (not defined in `{}`)",
        config_path.display()
    )]
    UnknownProfile {
        /// The profile name as the user requested it.
        name: String,
        /// Path to the config file we resolved against.
        config_path: PathBuf,
    },

    /// A profile was reached more than once during resolution.
    /// Strict no-repeats per `plans/CONFIG.md`: a profile included
    /// via two paths (whether via the CLI's repeated `-p` or via a
    /// shared `uses` ancestor) is a config error, not a diamond
    /// to silently merge. Forces the user to be explicit about
    /// which path they meant.
    #[error("profile `{name}` was already included earlier in the resolution")]
    RepeatedProfile {
        /// The profile name that was reached twice.
        name: String,
        /// Path to the config file we resolved against.
        config_path: PathBuf,
    },

    /// Could not read the secrets file.
    #[error("could not read secrets file `{}`", path.display())]
    CouldNotReadSecrets {
        /// The path we tried to read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Could not parse the secrets file.
    #[error("could not parse secrets file `{}`", path.display())]
    CouldNotParseSecrets {
        /// The path we tried to parse.
        path: PathBuf,
        /// The underlying parse error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Could not write the default secrets file during auto-init.
    #[error("could not write secrets file `{}`", path.display())]
    CouldNotWriteSecrets {
        /// The path we tried to write.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// A Handlebars template failed to render. This includes
    /// strict-mode violations (referencing undefined variables)
    /// and other rendering failures.
    #[allow(dead_code)]
    #[error("template error: {message}")]
    TemplateRender {
        /// The error message from the template engine.
        message: String,
    },

    /// The proxy host is empty.
    #[error("proxy host is empty")]
    ProxyEmptyHost,

    /// The proxy port is not a valid port number.
    #[error("proxy port `{port}` is not a valid port number")]
    ProxyInvalidPort {
        /// The offending port string.
        port: String,
    },

    /// The proxy action is invalid (expected `allow` or `deny`).
    #[error("proxy action `{action}` is invalid (expected `allow` or `deny`)")]
    ProxyInvalidAction {
        /// The offending action string.
        action: String,
    },

    /// The proxy specification has invalid syntax.
    #[error("proxy `{spec}` is invalid: {reason}")]
    ProxyInvalidSyntax {
        /// The offending specification.
        spec: String,
        /// Why we rejected it.
        reason: String,
    },
}

/// Boxed payload for [`Error::ConfigParse`].
///
/// Lives as its own diagnostic struct so the `#[source_code]` and
/// `#[label]` attributes apply directly (miette doesn't lift them
/// through `#[diagnostic(transparent)]` if they live on the inner
/// type — but it does delegate the whole `Diagnostic` impl, which
/// is what we want). Carries the file content (as a
/// `NamedSource<String>` so miette renders the file name in the
/// underline) and an optional byte span pulled from the toml crate.
#[derive(Debug, Diagnostic, thiserror::Error)]
#[error("invalid config in `{}`: {message}", path.display())]
pub struct ConfigParseError {
    /// The path that failed to parse — surfaced in the message so
    /// the user can find the file even if the span pointer gets
    /// lost (e.g. when miette renders without ANSI on a pipe).
    pub path: PathBuf,

    /// The full file content, attached so miette can render a span
    /// underline at `span`.
    #[source_code]
    pub src: NamedSource<String>,

    /// Byte span miette should highlight. `None` for errors the
    /// toml crate didn't pinpoint (rare in practice).
    #[label("{message}")]
    pub span: Option<SourceSpan>,

    /// Bare human-readable message from `toml::de::Error::message()`.
    /// Used as the underline label *and* as the suffix of the
    /// outer `#[error(...)]` format.
    pub message: String,
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
    pub fn missing_dependency(command: impl Into<String>) -> Self {
        Self::MissingDependency {
            command: command.into(),
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

    /// Create an [`Error::CouldNotGetCurrentExe`].
    pub fn could_not_get_current_exe(source: io::Error) -> Self {
        Self::CouldNotGetCurrentExe { source }
    }

    /// Create an [`Error::NonUtf8ExePath`].
    pub fn non_utf8_exe_path(path: PathBuf) -> Self {
        Self::NonUtf8ExePath { path }
    }

    /// Create an [`Error::CouldNotWriteStdout`].
    pub fn could_not_write_stdout(source: io::Error) -> Self {
        Self::CouldNotWriteStdout { source }
    }

    /// Create an [`Error::MissingMountHost`].
    pub fn missing_mount_host(path: PathBuf, source: io::Error) -> Self {
        Self::MissingMountHost { path, source }
    }

    /// Create an [`Error::InvalidForwardPort`].
    pub fn invalid_forward_port(field: String, value: u16) -> Self {
        Self::InvalidForwardPort { field, value }
    }

    /// Create an [`Error::InvalidEnvName`].
    pub fn invalid_env_name(name: String, reason: String) -> Self {
        Self::InvalidEnvName { name, reason }
    }

    /// Create an [`Error::CouldNotReadConfig`].
    pub fn could_not_read_config(path: PathBuf, source: io::Error) -> Self {
        Self::CouldNotReadConfig { path, source }
    }

    /// Create an [`Error::CouldNotWriteConfig`].
    pub fn could_not_write_config(path: PathBuf, source: io::Error) -> Self {
        Self::CouldNotWriteConfig { path, source }
    }

    /// Create an [`Error::ConfigInvalidPath`].
    pub fn config_invalid_path(
        path: impl Into<PathBuf>,
        reason: impl Into<String>,
    ) -> Self {
        Self::ConfigInvalidPath {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create an [`Error::UnknownProfile`].
    pub fn unknown_profile(
        name: impl Into<String>,
        config_path: PathBuf,
    ) -> Self {
        Self::UnknownProfile {
            name: name.into(),
            config_path,
        }
    }

    /// Create an [`Error::RepeatedProfile`].
    pub fn repeated_profile(
        name: impl Into<String>,
        config_path: PathBuf,
    ) -> Self {
        Self::RepeatedProfile {
            name: name.into(),
            config_path,
        }
    }

    /// Create an [`Error::ConfigParse`] from a `toml::de::Error`.
    /// Pulls the byte span out of the toml error and the message
    /// from `e.message()` so the toml crate's noisy `Display` wrapper
    /// (which embeds its own caret diagram) doesn't end up
    /// double-rendered next to miette's underline.
    pub fn config_parse(
        path: PathBuf,
        source_text: String,
        e: &toml::de::Error,
    ) -> Self {
        let span = e.span().map(|r| {
            // `r.start` and `r.end` are both `usize`; `SourceSpan`
            // is `(offset, length)` and `saturating_sub` keeps us
            // out of arithmetic-overflow lints in the (impossible)
            // `end < start` case.
            SourceSpan::from((r.start, r.end.saturating_sub(r.start)))
        });
        Self::ConfigParse(Box::new(ConfigParseError {
            src: NamedSource::new(path.display().to_string(), source_text),
            path,
            span,
            message: e.message().to_owned(),
        }))
    }

    /// Create an [`Error::CouldNotReadSecrets`].
    pub fn could_not_read_secrets(path: PathBuf, source: io::Error) -> Self {
        Self::CouldNotReadSecrets { path, source }
    }

    /// Create an [`Error::CouldNotParseSecrets`].
    pub fn could_not_parse_secrets(
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self::CouldNotParseSecrets { path, source }
    }

    /// Create an [`Error::CouldNotWriteSecrets`].
    pub fn could_not_write_secrets(path: PathBuf, source: io::Error) -> Self {
        Self::CouldNotWriteSecrets { path, source }
    }

    /// Create an [`Error::TemplateRender`].
    #[allow(dead_code)]
    pub fn template_render(message: String) -> Self {
        Self::TemplateRender { message }
    }

    /// Create an [`Error::ProxyInvalidPort`].
    pub fn proxy_invalid_port(port: String) -> Self {
        Self::ProxyInvalidPort { port }
    }

    /// Create an [`Error::ProxyInvalidAction`].
    pub fn proxy_invalid_action(action: String) -> Self {
        Self::ProxyInvalidAction { action }
    }

    /// Create an [`Error::ProxyInvalidSyntax`].
    pub fn proxy_invalid_syntax(spec: String, reason: String) -> Self {
        Self::ProxyInvalidSyntax { spec, reason }
    }
}

//! Configuration files and command-line arguments.
//!
//! Configuration is resolved in two phases:
//!
//! 1. We use [`Decl`] to validate and resolve the configuration
//!    file/CLI types into more concrete `Resolved` types that can be
//!    used to actually configure a sandbox.
//! 2. We use [`Finalize`] to merge resolved values from multiple
//!    sources right-biased (the right-hand side wins on collision)
//!    and to bake the per-domain baseline (system mounts, canonical
//!    PATH, etc.) underneath the merged user contributions.

use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
};

use crate::prelude::*;

pub mod config_file;
pub mod env_var;
pub mod env_vars;
pub mod forward;
pub mod forwards;
pub mod mount;
pub mod mounts;
pub mod profile;
pub mod resolve_context;

/// Trait for **declared** configuration, as specified by the user.
pub trait Decl {
    /// The resolved output type.
    type Resolved;

    /// Validate the configuration as much as possible, showing helpful error
    /// messages to the user (instead of failing cryptically later).
    fn validate(&self) -> Result<()>;

    /// Resolve the value from the environment using `ctx` (which
    /// contains things like our Handlebars renderer and secrets).
    fn resolve(
        &self,
        ctx: &resolve_context::ResolveContext,
    ) -> Result<Self::Resolved>;
}

/// Trait for taking a resolved configuration from [`Decl::resolve`] and finalizing it.
/// This is not implemented for all [`Decl::Resolved`] types, just the higher-level
/// types that need more complex merging.
///
/// The basic strategy is:
///
/// - Merge multiple values using [`Finalize::merge_all_right_biased`].
/// - Call [`Finalize::finalize`] on the merged value to set up any base
///   configuration and combined it with the merged value.
///
/// This is a bit complex, mostly due to handling things like `--readonly`
/// and `--path-add`, which exist in the user-provided configuration, but actually
/// customize how the base configuration gets built.
pub trait Finalize: Default + Sized {
    /// Combine two values, preferring `other` over `self`. Typically, when merging
    /// profiles or other configuration, we favor the right argument.
    fn merge_right_biased(&self, other: &Self) -> Self;

    /// Merge all values using [`merge_right_biased`].
    fn merge_all_right_biased(values: &[Self]) -> Self {
        values
            .iter()
            .fold(Self::default(), |acc, v| acc.merge_right_biased(v))
    }

    /// Base configuration, which is automatically present even with an empty
    /// user-provided configuration. Parts of the base configuration may
    /// actually be customized by options provided by the user, such as
    /// additions to PATH or customizing various standard mount points.
    fn base_config(&self) -> Self;

    /// Clear any extra fields from the configuration. These are typically fields
    /// that were actually used to customize the base configuration, and which are no longer needed, such as additions to the PATH.
    fn clear_extra_fields(&mut self) {}

    /// Finalize the configuration. This creates a base configuration,
    /// clears any extra fields, and then merges this configuration over
    /// the base configuration.
    fn finalize(mut self) -> Self {
        let base = self.base_config();
        self.clear_extra_fields();
        base.merge_right_biased(&self)
    }
}

/// Apply the limited config-time tilde expansion in-place.
///
/// Each path-bearing Decl type implements this to expand any `~/`
/// against `home` and reject unhandled forms. `ProfileDecl`'s impl
/// delegates to its `MountDecls` and `EnvVarDecls` children, which
/// in turn delegate to their per-element impls — so each domain owns
/// its own normalization. CLI input bypasses normalization entirely:
/// the shell already expanded `~/` before our argv reached us, so
/// re-running the expansion would be a footgun.
///
/// Only `~/` (with the trailing slash) and bare `~` are expanded;
/// `~user/`, `$VAR`, relative `./foo` all error so the user's mental
/// model stays "config paths look like `~/x` or `/x`, period." See
/// [`expand_tilde`] for the per-path rules.
pub trait NormalizeConfigPaths {
    /// Walk `self`, expanding `~/` against `home` everywhere a path
    /// can appear and rejecting any unhandled form.
    fn normalize_config_paths(&mut self, home: &Path) -> Result<()>;
}

/// Resolve a single config path, expanding `~/` against `home` and
/// rejecting unhandled patterns.
///
/// Rules (in order):
/// - bare `~` → `home`
/// - leading `~/` → `home/<rest>`
/// - any other leading `~` (e.g. `~bob/foo`) → error: not supported
/// - leading `/` → unchanged (already absolute)
/// - anything else → error: relative paths not supported
///
/// Dispatch is on raw bytes via [`std::os::unix::ffi::OsStrExt`] so a
/// non-UTF-8 input round-trips byte-for-byte: every special case we
/// care about (`~`, `~/`, `~user`, `/`) is a single ASCII byte, and
/// the bytes after that are passed to [`Path::join`] / preserved in
/// [`Error::ConfigInvalidPath`] without any UTF-8 conversion. Linux
/// is the only target ([`std::os::unix`] applies), which matches the
/// rest of the crate.
pub(crate) fn expand_tilde(p: &Path, home: &Path) -> Result<PathBuf> {
    let bytes = p.as_os_str().as_bytes();
    if bytes == b"~" {
        return Ok(home.to_path_buf());
    }
    if let Some(rest) = bytes.strip_prefix(b"~/") {
        // `home.join(rest)` would treat an absolute `rest` as a
        // replacement, but `rest` came after a literal `/` so it's
        // never absolute — `join` does the right thing.
        return Ok(home.join(OsStr::from_bytes(rest)));
    }
    if bytes.starts_with(b"~") {
        return Err(Error::config_invalid_path(
            p.to_path_buf(),
            "only `~/` is supported (no `~user/`, `~+`, etc.)",
        ));
    }
    if bytes.starts_with(b"/") {
        return Ok(p.to_path_buf());
    }
    Err(Error::config_invalid_path(
        p.to_path_buf(),
        "relative paths are not supported; use `~/...` or an absolute path",
    ))
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

    use super::*;

    fn fake_home() -> &'static Path {
        Path::new("/home/test")
    }

    #[test]
    fn expand_tilde_handles_supported_forms() {
        let h = fake_home();
        assert_eq!(expand_tilde(Path::new("~"), h).unwrap(), h);
        assert_eq!(
            expand_tilde(Path::new("~/foo"), h).unwrap(),
            PathBuf::from("/home/test/foo"),
        );
        assert_eq!(
            expand_tilde(Path::new("/already/abs"), h).unwrap(),
            PathBuf::from("/already/abs"),
        );
    }

    #[test]
    fn expand_tilde_rejects_unhandled_patterns() {
        let h = fake_home();
        let err = expand_tilde(Path::new("~bob/foo"), h)
            .expect_err("~user/ is unsupported");
        assert!(matches!(err, Error::ConfigInvalidPath { .. }));

        let err = expand_tilde(Path::new("relative/path"), h)
            .expect_err("relative path is unsupported");
        assert!(matches!(err, Error::ConfigInvalidPath { .. }));
    }

    #[test]
    fn expand_tilde_preserves_non_utf8_absolute_path() {
        // A `/`-prefixed path with a stray 0xff byte must come out
        // byte-identical: dispatch is on raw bytes, no UTF-8 hop.
        let h = fake_home();
        let raw: Vec<u8> = b"/\xff/foo".to_vec();
        let p = PathBuf::from(OsString::from_vec(raw.clone()));
        let got = expand_tilde(&p, h).expect("absolute non-UTF-8 path is fine");
        assert_eq!(got.as_os_str().as_bytes(), raw.as_slice());
    }

    #[test]
    fn expand_tilde_preserves_non_utf8_under_home() {
        // `~/<non-UTF-8>` must join cleanly: the post-`~/` bytes
        // are passed through `OsStr::from_bytes` and joined onto
        // `home`, surviving end-to-end.
        let h = fake_home();
        let raw: Vec<u8> = b"~/\xff/bin".to_vec();
        let p = PathBuf::from(OsString::from_vec(raw));
        let got = expand_tilde(&p, h).expect("~/non-UTF-8 should expand");
        let expected: Vec<u8> = b"/home/test/\xff/bin".to_vec();
        assert_eq!(got.as_os_str().as_bytes(), expected.as_slice());
    }

    #[test]
    fn expand_tilde_error_preserves_non_utf8_bytes() {
        // A non-UTF-8 input that fails to match any supported form
        // must round-trip byte-for-byte through the error variant
        // — `Error::ConfigInvalidPath.path` is a `PathBuf` for
        // exactly this reason.
        let h = fake_home();
        let raw: Vec<u8> = b"\xffrelative".to_vec();
        let p = PathBuf::from(OsString::from_vec(raw.clone()));
        let err =
            expand_tilde(&p, h).expect_err("non-UTF-8 relative is unhandled");
        match err {
            Error::ConfigInvalidPath { path, .. } => {
                assert_eq!(path.as_os_str().as_bytes(), raw.as_slice());
            }
            other => panic!("expected ConfigInvalidPath, got {other:?}"),
        }
    }
}

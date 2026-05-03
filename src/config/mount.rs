//! A single filesystem mount inside the sandbox.
//!
//! Pipeline: the user-facing [`MountDecl`] (CLI/TOML) resolves via
//! [`Decl::resolve`] into a runtime [`Mount`]. The plural pieces
//! ([`MountDecls`][crate::config::mounts::MountDecls],
//! [`Mounts`][crate::config::mounts::Mounts], and the
//! [`Finalize`][crate::config::Finalize] impl) live in
//! [`crate::config::mounts`].
//!
//! Each [`Mount`] records *what* is exposed and *how* (`--ro-bind`,
//! `--bind`, `--tmpfs`, etc.). Bwrap's flag-name translation lives in
//! [`crate::sandbox::bwrap`].
//!
//! References (cited by URL throughout `mounts.rs` too):
//!
//!   bwrap(1) manpage:
//!     <https://man.archlinux.org/man/bwrap.1.en>
//!   containers/bubblewrap canonical demo script:
//!     <https://github.com/containers/bubblewrap/blob/main/demos/bubblewrap-shell.sh>
//!   sloonz, "Sandboxing Applications with Bubblewrap" (parts 1+2):
//!     <https://sloonz.github.io/posts/sandboxing-1/>
//!     <https://sloonz.github.io/posts/sandboxing-2/>
//!   The case for the /usr merge:
//!     <https://www.freedesktop.org/wiki/Software/systemd/TheCaseForTheUsrMerge/>
//!   Project architecture spec:
//!     `specs/ARCHITECTURE.md`

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use toml::Spanned;

use crate::{
    config::{Decl, NormalizeConfigPaths},
    prelude::*,
};

/// A single bind-mount specification: a host path, the sandbox path
/// it should appear at, and whether to expose it read-only (the
/// default) or read-write.
///
/// Same type for CLI and TOML inputs. `host` carries a `Spanned`
/// wrapper so a downstream validation error (e.g. missing host
/// path on disk) can render with miette pointing at the exact line
/// of the config that introduced the mount; CLI-sourced specs use a
/// `0..0` sentinel span. Optional fields use serde defaults — see
/// [`Self::sandbox_path`] and [`Self::access_mode`] for the
/// "absent → derive from host / Ro" resolution.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountDecl {
    /// Absolute path on the host being bind-mounted in.
    pub host: Spanned<PathBuf>,

    /// Absolute path inside the sandbox where it should appear.
    /// `None` means "use the same path as `host`".
    #[serde(default)]
    pub sandbox: Option<Spanned<PathBuf>>,

    /// Whether the mount is read-only or read-write. `None` means
    /// the default (read-only).
    #[serde(default)]
    pub access: Option<MountAccess>,
}

impl MountDecl {
    /// The sandbox path this mount lands at — falling back to `host`
    /// when no explicit sandbox path was given.
    pub fn sandbox_path(&self) -> &Path {
        self.sandbox
            .as_ref()
            .map(Spanned::get_ref)
            .map(PathBuf::as_path)
            .unwrap_or_else(|| self.host.get_ref().as_path())
    }

    /// The effective access mode (defaults to `Ro` when absent).
    pub fn access_mode(&self) -> MountAccess {
        self.access.unwrap_or(MountAccess::Ro)
    }
}

impl FromStr for MountDecl {
    type Err = String;

    /// Parse a `HOST_PATH[:SANDBOX_PATH[:rw|:ro]]` mount specification.
    ///
    /// If only one path is given, the sandbox path defaults to the
    /// host path. The optional third part must be exactly `ro` or
    /// `rw`; if omitted, the default is read-only. Four-or-more-colon
    /// syntax is reserved for future extensions. Both path halves
    /// must be absolute (`/`-prefixed); relative paths are nonsense
    /// for bind mounts and the early failure is more helpful than
    /// bwrap's later one. CLI-sourced specs carry a `0..0` span on
    /// `host` (no source file to point at).
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(4, ':').collect();
        let (host, sandbox, access) = match parts.as_slice() {
            [single] => (*single, None, None),
            [host, sandbox] => (*host, Some(*sandbox), None),
            [host, sandbox, access] => {
                let access = match *access {
                    "ro" => MountAccess::Ro,
                    "rw" => MountAccess::Rw,
                    other => {
                        return Err(format!(
                            "mount access {other:?} must be `ro` or `rw`"
                        ));
                    }
                };
                (*host, Some(*sandbox), Some(access))
            }
            _ => {
                return Err(format!(
                    "mount spec {s:?} contains more than two `:`; \
                     additional colons are reserved for future use"
                ));
            }
        };
        if host.is_empty() {
            return Err(format!("mount spec {s:?} has empty host path"));
        }
        if !host.starts_with('/') {
            return Err(format!(
                "mount host path {host:?} must be absolute (start with `/`)"
            ));
        }
        if let Some(sb) = sandbox {
            if sb.is_empty() {
                return Err(format!("mount spec {s:?} has empty sandbox path"));
            }
            if !sb.starts_with('/') {
                return Err(format!(
                    "mount sandbox path {sb:?} must be absolute (start with `/`)"
                ));
            }
        }
        Ok(MountDecl {
            host: Spanned::new(0..0, PathBuf::from(host)),
            sandbox: sandbox.map(|s| Spanned::new(0..0, PathBuf::from(s))),
            access,
        })
    }
}

impl NormalizeConfigPaths for MountDecl {
    /// Expand `~/` in `host` and (if set) `sandbox` against `home`.
    /// `Spanned::get_mut` rewrites in place, preserving the byte
    /// range so a later validation error still points at the right
    /// line. `access` carries no path data.
    fn normalize_config_paths(&mut self, home: &Path) -> Result<()> {
        let host_inner = self.host.get_mut();
        *host_inner = super::expand_tilde(host_inner.as_path(), home)?;
        if let Some(sandbox) = self.sandbox.as_mut() {
            let sandbox_inner = sandbox.get_mut();
            *sandbox_inner =
                super::expand_tilde(sandbox_inner.as_path(), home)?;
        }
        Ok(())
    }
}

impl Decl for MountDecl {
    type Resolved = Mount;

    /// Validate that the host path exists on disk. Runs after
    /// `NormalizeConfigPaths` (so `~/` is already expanded) for both
    /// CLI and profile-sourced mounts. Without this, the user gets
    /// bwrap's terser `Can't find source path` failure deep inside
    /// sandbox setup.
    fn validate(&self) -> Result<()> {
        std::fs::metadata(self.host.get_ref()).map_err(|e| {
            Error::missing_mount_host(self.host.get_ref().clone(), e)
        })?;
        Ok(())
    }

    fn resolve(&self) -> Result<Self::Resolved> {
        Ok(Mount {
            sandbox: self.sandbox_path().to_owned(),
            kind: MountKind::Mount {
                host: self.host.get_ref().clone(),
                access: self.access_mode(),
            },
        })
    }
}

/// A single resolved filesystem mount inside the sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct Mount {
    /// Absolute path inside the sandbox where this mount appears.
    pub sandbox: PathBuf,

    /// Kind of mount (with any host path, symlink target, or access
    /// mode it carries). Flattened so JSONL lines look like
    /// `{"sandbox": "...", "kind": "mount", "host": "...", "access": "ro"}`.
    #[serde(flatten)]
    pub kind: MountKind,
}

/// The subset of bwrap mount kinds we use.
///
/// The `Mount` variant covers both access modes the CLI exposes
/// (`-m, --mount HOST[:SANDBOX[:rw|:ro]]`) via its [`MountAccess`]
/// field; the bwrap flag-name translation (`--bind`/`--ro-bind`)
/// lives in [`crate::sandbox::bwrap`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MountKind {
    /// Bind mount from the host. Translated to bwrap `--bind` (rw)
    /// or `--ro-bind` (ro) depending on `access`.
    Mount {
        /// Host path being bound.
        host: PathBuf,
        /// Whether the mount is read-only or read-write.
        access: MountAccess,
    },
    /// Symlink at `sandbox` pointing to `target` (`--symlink`).
    Symlink {
        /// Target the symlink points at.
        target: String,
    },
    /// Fresh tmpfs (`--tmpfs`).
    Tmpfs,
    /// Minimal device set (`--dev`): null, zero, full, random,
    /// urandom, tty, `/dev/pts`, `/dev/shm`.
    Dev,
    /// Fresh procfs (`--proc`).
    Proc,
}

/// Whether a bind mount exposes the host path read-only or read-write.
///
/// Encoded in the `:rw|:ro` suffix of `-m, --mount` for CLI mounts,
/// in `--readonly` for the cwd bind, the `access` field of the
/// JSONL emitted by `redoubtful mounts --jsonl`, and the `access`
/// key of TOML mount specs in `[profile.NAME]` blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MountAccess {
    /// Read-only — translated to bwrap `--ro-bind`. The default for
    /// `-m` if no suffix is given.
    Ro,
    /// Read-write — translated to bwrap `--bind`. **Use sparingly**
    /// — a writeable mount is a hole in the sandbox by design.
    Rw,
}

impl MountAccess {
    /// The cwd-bind access mode given a merged `readonly` toggle.
    ///
    /// Single source of truth for the rule "absent or false →
    /// read-write, true → read-only" so `cmd_run` and `cmd_show`
    /// don't drift. `Option<bool>` (rather than plain `bool`)
    /// because callers fold a profile-level `readonly` together
    /// with `--readonly`/`--readonly=false`/(absent) before
    /// landing here.
    pub fn from_readonly(readonly: Option<bool>) -> Self {
        if readonly.unwrap_or(false) {
            Self::Ro
        } else {
            Self::Rw
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> std::result::Result<MountDecl, String> {
        s.parse()
    }

    #[test]
    fn mount_decl_accepts_single_path() {
        let spec = parse("/home/u/.gitconfig").expect("parses");
        assert_eq!(spec.host.get_ref(), &PathBuf::from("/home/u/.gitconfig"),);
        // No explicit sandbox path → fallback to host.
        assert!(spec.sandbox.is_none());
        assert_eq!(spec.sandbox_path(), Path::new("/home/u/.gitconfig"));
        assert_eq!(spec.access_mode(), MountAccess::Ro);
    }

    #[test]
    fn mount_decl_accepts_host_colon_sandbox() {
        let spec = parse("/host/x:/sandbox/y").expect("parses");
        assert_eq!(spec.host.get_ref(), &PathBuf::from("/host/x"));
        assert_eq!(spec.sandbox_path(), Path::new("/sandbox/y"));
        assert_eq!(spec.access_mode(), MountAccess::Ro);
    }

    #[test]
    fn mount_decl_accepts_explicit_rw_and_ro_suffix() {
        let rw = parse("/host/x:/sandbox/y:rw").expect("parses :rw");
        assert_eq!(rw.access_mode(), MountAccess::Rw);
        let ro = parse("/host/x:/sandbox/y:ro").expect("parses :ro");
        assert_eq!(ro.access_mode(), MountAccess::Ro);
    }

    #[test]
    fn mount_decl_rejects_invalid_access_token() {
        let err = parse("/host/x:/sandbox/y:wat")
            .expect_err("bogus access token should be rejected");
        assert!(err.contains("\"wat\""), "{err}");
        assert!(err.contains("ro") && err.contains("rw"), "{err}");
    }

    #[test]
    fn mount_decl_rejects_too_many_colons() {
        // Three colons is now valid (it's the access suffix); four is not.
        let err = parse("/host/x:/sandbox/y:rw:extra")
            .expect_err("four-segment spec should be rejected");
        assert!(err.contains("more than two `:`"), "{err}");
    }

    #[test]
    fn mount_decl_rejects_relative_paths() {
        assert!(parse("relative/path").is_err());
        assert!(parse("/abs:relative").is_err());
        assert!(parse("relative:/abs").is_err());
    }

    #[test]
    fn mount_decl_resolve_yields_mount() {
        // Single-path: host == sandbox, default ro.
        let single = parse("/etc/gitconfig")
            .unwrap()
            .resolve()
            .expect("resolves");
        assert_eq!(single.sandbox, PathBuf::from("/etc/gitconfig"));
        match single.kind {
            MountKind::Mount { host, access } => {
                assert_eq!(host, PathBuf::from("/etc/gitconfig"));
                assert_eq!(access, MountAccess::Ro);
            }
            other => panic!("expected MountKind::Mount, got {other:?}"),
        }

        // Explicit sandbox + rw.
        let remap = parse("/host/x:/sandbox/y:rw")
            .unwrap()
            .resolve()
            .expect("resolves");
        assert_eq!(remap.sandbox, PathBuf::from("/sandbox/y"));
        match remap.kind {
            MountKind::Mount { host, access } => {
                assert_eq!(host, PathBuf::from("/host/x"));
                assert_eq!(access, MountAccess::Rw);
            }
            other => panic!("expected MountKind::Mount, got {other:?}"),
        }
    }

    #[test]
    fn cli_constructed_mount_decl_uses_zero_span() {
        // `FromStr` produces a `0..0` sentinel span — span attribution
        // applies to TOML-sourced specs, not CLI ones.
        let spec: MountDecl = "/etc/gitconfig".parse().expect("parses");
        let span = spec.host.span();
        assert_eq!(span.start, 0);
        assert_eq!(span.end, 0);
    }

    #[test]
    fn normalize_config_paths_expands_host_and_sandbox() {
        let mut spec = MountDecl {
            host: Spanned::new(0..0, PathBuf::from("~/.gitconfig")),
            sandbox: Some(Spanned::new(
                0..0,
                PathBuf::from("~/sandbox/.gitconfig"),
            )),
            access: None,
        };
        spec.normalize_config_paths(Path::new("/home/test"))
            .expect("normalizes");
        assert_eq!(
            spec.host.get_ref(),
            &PathBuf::from("/home/test/.gitconfig"),
        );
        assert_eq!(
            spec.sandbox.as_ref().unwrap().get_ref(),
            &PathBuf::from("/home/test/sandbox/.gitconfig"),
        );
    }

    #[test]
    fn normalize_config_paths_propagates_invalid_host() {
        let mut spec = MountDecl {
            host: Spanned::new(0..0, PathBuf::from("relative/path")),
            sandbox: None,
            access: None,
        };
        let err = spec
            .normalize_config_paths(Path::new("/home/test"))
            .expect_err("relative path must error");
        assert!(matches!(err, Error::ConfigInvalidPath { .. }));
    }

    #[test]
    fn cwd_access_from_readonly_resolves_all_three_states() {
        // `None` (flag absent) is the historical "read-write" default.
        assert_eq!(MountAccess::from_readonly(None), MountAccess::Rw);
        // Explicit `Some(true)` → read-only. The bare `--readonly`
        // CLI form lands here, as does a profile that sets
        // `readonly = true`.
        assert_eq!(MountAccess::from_readonly(Some(true)), MountAccess::Ro);
        // Explicit `Some(false)` matches the absent case — the
        // merge fold can produce `Some(false)` when one profile
        // turns readonly off after another turned it on, so we
        // treat that as "read-write" too.
        assert_eq!(MountAccess::from_readonly(Some(false)), MountAccess::Rw);
    }
}

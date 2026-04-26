//! The list of filesystem mounts that make up the sandbox.
//!
//! This is the security-critical inventory of every place inside
//! the sandbox where data is exposed to or from the host. Both
//! [`crate::bwrap::bwrap_argv`] and the `redoubtful mounts`
//! subcommand consume the *same* inventory, so a reviewer (or the
//! test suite) can audit it without reconstructing what the bwrap
//! argv means.
//!
//! Each [`Mount`] records *what* is exposed, *how* (`--ro-bind`,
//! `--bind`, `--tmpfs`, etc.), and *where it came from* (the
//! [`MountSource`]). The source field is intentionally extensible:
//! today the sources are [`MountSource::Default`] (the hardcoded
//! baseline), [`MountSource::Cwd`] (the project dir), and
//! [`MountSource::Cli`] (CLI flags); later, configs and named
//! profiles will add their own.
//!
//! References (cited by URL throughout):
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
//!
//! This file favors "comment overkill", in order to preserve security
//! justifications and original reference information for our decisions.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Serialize;

use crate::prelude::*;

/// A single filesystem mount inside the sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct Mount {
    /// Absolute path inside the sandbox where this mount appears.
    pub sandbox: PathBuf,

    /// Kind of mount (with any host path, symlink target, or access
    /// mode it carries). Flattened so JSONL lines look like
    /// `{"sandbox": "...", "kind": "mount", "host": "...", "access": "ro", "source": "..."}`.
    #[serde(flatten)]
    pub kind: MountKind,

    /// Where this mount came from. Lets `redoubtful mounts --jsonl`
    /// distinguish the hardcoded baseline from CLI flags or future
    /// config-file entries.
    pub source: MountSource,
}

/// The subset of bwrap mount kinds we use.
///
/// The `Mount` variant covers both access modes the CLI exposes
/// (`-m, --mount HOST[:SANDBOX[:rw|:ro]]`) via its [`MountAccess`]
/// field; the bwrap flag-name translation (`--bind`/`--ro-bind`)
/// lives in [`crate::bwrap`].
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
/// in `--readonly` for the cwd bind, and in the `access` field of
/// the JSONL emitted by `redoubtful mounts --jsonl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MountAccess {
    /// Read-only — translated to bwrap `--ro-bind`. The default for
    /// `-m` if no suffix is given.
    Ro,
    /// Read-write — translated to bwrap `--bind`. **Use sparingly**
    /// — a writeable mount is a hole in the sandbox by design.
    Rw,
}

/// Provenance of a mount — extensible.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountSource {
    /// Hardcoded baseline mount from this module.
    Default,
    /// The project directory the user invoked us from (`$PWD`).
    Cwd,
    /// Added via a `-m`/`--mount` CLI flag.
    Cli,
    // Future: Config { path: PathBuf }, NamedProfile { name: String }, etc.
}

/// The ordered list of mounts that makes up the sandbox.
///
/// A newtype around `Vec<Mount>`, owning two invariants that would
/// otherwise live as comments at every call site:
///
/// - **Order is load-bearing.** bwrap processes mounts in argv order
///   and a later mount overlays an earlier one. The default baseline
///   places `--tmpfs $HOME` before `--bind $PWD $PWD` so the project
///   bind punches through the tmpfs (see [`MountList::default_baseline`]).
/// - **CLI mounts are appended after defaults.** They land *after*
///   the `$HOME` tmpfs, so `-m ~/.gitconfig` punches through the
///   tmpfs the same way the cwd bind does. Order between multiple
///   CLI mounts matches CLI order.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(transparent)]
pub struct MountList(Vec<Mount>);

impl MountList {
    /// An empty mount list. Use [`MountList::default_baseline`] for
    /// the standard sandbox baseline; this constructor exists for
    /// tests.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// The hardcoded mount baseline every sandbox starts from:
    /// read-only `/usr` (with the standard top-level symlinks),
    /// `/dev` `/proc` `/tmp`, then `--tmpfs $HOME` followed by a
    /// `$PWD $PWD` bind whose access mode comes from `cwd_access`
    /// (read-write by default; read-only via `--readonly`).
    ///
    /// Order is load-bearing — the `$HOME` tmpfs must precede the
    /// `$PWD` bind so the bind punches through the tmpfs rather than
    /// the other way around.
    pub fn default_baseline(
        home: &Path,
        cwd: &Path,
        cwd_access: MountAccess,
    ) -> Self {
        let mut list = Self::new();

        // ----- Read-only system filesystem -----
        //
        // All binaries and libraries live under /usr on every modern
        // merged-/usr distro (Fedora, Debian/Ubuntu, Arch). We ro-bind
        // /usr once and replace the legacy top-level dirs with
        // symlinks into /usr/*, mirroring those distros' real /.
        // Symlinking (rather than ro-binding each one) keeps the
        // sandbox's root tmpfs lean.
        //
        //   <https://github.com/containers/bubblewrap/blob/main/demos/bubblewrap-shell.sh>
        //   <https://sloonz.github.io/posts/sandboxing-1/>
        //   <https://www.freedesktop.org/wiki/Software/systemd/TheCaseForTheUsrMerge/>
        //
        // /etc is intentionally NOT exposed in v0. Every file we
        // expose from /etc carries consequences that need to be
        // reasoned about (e.g. /etc/passwd leaks the host username,
        // real name from GECOS, login shell, and home path;
        // /etc/nsswitch.conf plus /etc/passwd lets `getpwuid()`
        // succeed and changes a lot of glibc behavior). Future steps
        // add specific /etc/* paths as concrete features land that
        // need them (TLS → /etc/ssl/certs/; git → /etc/gitconfig;
        // user-aware tooling → a synthetic /etc/passwd written via
        // FD à la the bwrap demo).
        list.mount("/usr", "/usr", MountAccess::Ro, MountSource::Default);
        list.symlink("/bin", "usr/bin", MountSource::Default);
        list.symlink("/sbin", "usr/sbin", MountSource::Default);
        list.symlink("/lib", "usr/lib", MountSource::Default);
        list.symlink("/lib64", "usr/lib64", MountSource::Default);

        // ----- /dev, /proc, /tmp -----
        //
        // --dev creates a minimal device set (null, zero, full,
        // random, urandom, tty, /dev/pts, /dev/shm) — *not* a host
        // bind. Block and character devices on the host stay
        // invisible.
        //
        // --proc mounts a fresh procfs that only sees our pid
        // namespace. Combined with --unshare-all (which includes
        // pidns) in bwrap.rs, this is what makes `ps aux` only
        // list sandboxed processes.
        //
        // --tmpfs /tmp gives an ephemeral scratch area isolated from
        // the host /tmp. On shared/multi-user systems the host /tmp
        // is a classic tmpfile-race vector; isolation closes that.
        //
        //   <https://man.archlinux.org/man/bwrap.1.en>
        list.dev("/dev", MountSource::Default);
        list.proc("/proc", MountSource::Default);
        list.tmpfs("/tmp", MountSource::Default);

        // ----- $HOME blanked, $PWD bind-mounted back at its real path -----
        //
        // Threat model: a coding agent running with
        // --dangerously-skip-permissions normally has read access to
        // ~/.ssh/, ~/.aws/, browser cookies, password-manager
        // databases, .env files in random project dirs,
        // ~/.bash_history, etc., and write access to dotfiles like
        // ~/.bashrc that execute on every shell start. We need every
        // byte of $HOME except the project directory to be invisible.
        //
        // The bind uses the same path on both sides so absolute paths
        // recorded by tools (git worktree gitdir pointers,
        // .git/index entries) keep working: paths inside the sandbox
        // match paths outside.
        //
        // Order: this tmpfs must come before the bind below, so the
        // bind overlays it (project dir punches through the tmpfs)
        // rather than the other way around. CLI mounts appended later
        // by [`MountOpts::apply`] are similarly later in the list, so
        // they too punch through.
        //
        // Known limitation: if $PWD == $HOME, the bind would re-
        // expose the real $HOME on top of the tmpfs and defeat the
        // hiding. v0 accepts this; harden later.
        //
        //   `specs/ARCHITECTURE.md` ("Filesystem layout inside the sandbox")
        list.tmpfs(home, MountSource::Default);
        list.mount(cwd, cwd, cwd_access, MountSource::Cwd);

        list
    }

    /// Append a bind mount with the given [`MountAccess`].
    pub fn mount(
        &mut self,
        sandbox: impl Into<PathBuf>,
        host: impl Into<PathBuf>,
        access: MountAccess,
        source: MountSource,
    ) -> &mut Self {
        self.0.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Mount {
                host: host.into(),
                access,
            },
            source,
        });
        self
    }

    /// Append a symlink (`sandbox` points at `target`).
    pub fn symlink(
        &mut self,
        sandbox: impl Into<PathBuf>,
        target: impl Into<String>,
        source: MountSource,
    ) -> &mut Self {
        self.0.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Symlink {
                target: target.into(),
            },
            source,
        });
        self
    }

    /// Append a tmpfs mount.
    pub fn tmpfs(
        &mut self,
        sandbox: impl Into<PathBuf>,
        source: MountSource,
    ) -> &mut Self {
        self.0.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Tmpfs,
            source,
        });
        self
    }

    /// Append a `--dev` minimal device set.
    pub fn dev(
        &mut self,
        sandbox: impl Into<PathBuf>,
        source: MountSource,
    ) -> &mut Self {
        self.0.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Dev,
            source,
        });
        self
    }

    /// Append a fresh procfs.
    pub fn proc(
        &mut self,
        sandbox: impl Into<PathBuf>,
        source: MountSource,
    ) -> &mut Self {
        self.0.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Proc,
            source,
        });
        self
    }

    /// Iterate over the mounts in declaration order. Order matters
    /// — see the type-level docs.
    pub fn iter(&self) -> std::slice::Iter<'_, Mount> {
        self.0.iter()
    }

    /// Number of mounts in the list. Used for tracing fields.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// A single CLI-supplied bind-mount specification: a host path,
/// the sandbox path it should appear at, and whether to expose it
/// read-only (the default) or read-write.
///
/// Parses from `HOST_PATH[:SANDBOX_PATH[:rw|:ro]]` via [`FromStr`],
/// which clap picks up automatically.
#[derive(Debug, Clone)]
pub struct MountSpec {
    /// Absolute path on the host being bind-mounted in.
    pub host: PathBuf,

    /// Absolute path inside the sandbox where it should appear.
    pub sandbox: PathBuf,

    /// Whether the mount is read-only or read-write.
    pub access: MountAccess,
}

impl FromStr for MountSpec {
    type Err = String;

    /// Parse a `HOST_PATH[:SANDBOX_PATH[:rw|:ro]]` mount specification.
    ///
    /// If only one path is given, the sandbox path equals the host
    /// path (the common case for `-m ~/.gitconfig`). The optional
    /// third part must be exactly `ro` or `rw`; if omitted, the
    /// default is read-only. Four-or-more-colon syntax is reserved
    /// for future extensions. Both path halves must be absolute
    /// (`/`-prefixed); relative paths are nonsense for bind mounts
    /// and the early failure is more helpful than bwrap's later one.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(4, ':').collect();
        let (host, sandbox, access) = match parts.as_slice() {
            [single] => (*single, *single, MountAccess::Ro),
            [host, sandbox] => (*host, *sandbox, MountAccess::Ro),
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
                (*host, *sandbox, access)
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
        if sandbox.is_empty() {
            return Err(format!("mount spec {s:?} has empty sandbox path"));
        }
        if !host.starts_with('/') {
            return Err(format!(
                "mount host path {host:?} must be absolute (start with `/`)"
            ));
        }
        if !sandbox.starts_with('/') {
            return Err(format!(
                "mount sandbox path {sandbox:?} must be absolute (start with `/`)"
            ));
        }
        Ok(MountSpec {
            host: PathBuf::from(host),
            sandbox: PathBuf::from(sandbox),
            access,
        })
    }
}

/// Shared CLI options for mount flags.
///
/// Flattened with `#[command(flatten)]` into any subcommand that
/// builds a [`MountList`] (`run`, `mounts`). Keeps the flag
/// definitions in one place so the audit/test allowlist stays in
/// sync with the runtime.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct MountOpts {
    /// Bind a host path into the sandbox. Repeatable. Format:
    /// `HOST_PATH[:SANDBOX_PATH[:rw|:ro]]`. Default access is
    /// read-only; pass `:rw` to allow the sandboxed process to
    /// modify the host path. **Use `:rw` sparingly** — a writeable
    /// mount is a hole in the sandbox by design.
    #[arg(
        short = 'm',
        long = "mount",
        value_name = "HOST_PATH[:SANDBOX_PATH[:rw|:ro]]"
    )]
    pub mount: Vec<MountSpec>,

    /// Mount the working directory read-only instead of read-write.
    /// Useful for exploratory agents that should be able to read the
    /// project but not modify it. Does not affect `-m` mounts —
    /// those carry their own access mode in the spec.
    #[arg(long = "readonly")]
    pub readonly: bool,
}

impl MountOpts {
    /// Stat every host path up-front and return a friendly error if
    /// any are missing. Without this, the user gets bwrap's terser
    /// `Can't find source path` failure deep inside sandbox setup.
    pub fn validate(&self) -> Result<()> {
        for spec in &self.mount {
            std::fs::metadata(&spec.host)
                .map_err(|e| Error::missing_mount_host(spec.host.clone(), e))?;
        }
        Ok(())
    }

    /// The access mode the cwd bind should use given `--readonly`.
    /// Pass to [`MountList::default_baseline`].
    pub fn cwd_access(&self) -> MountAccess {
        if self.readonly {
            MountAccess::Ro
        } else {
            MountAccess::Rw
        }
    }

    /// Append CLI mounts to a [`MountList`] in CLI order. Each
    /// mount's access mode (ro vs rw) comes from its own
    /// [`MountSpec::access`], which means later `-m` flags overlay
    /// earlier ones the same way bwrap argv-order does.
    pub fn apply(&self, list: &mut MountList) {
        for spec in &self.mount {
            list.mount(
                spec.sandbox.clone(),
                spec.host.clone(),
                spec.access,
                MountSource::Cli,
            );
        }
    }
}

/// Read `$HOME` from the environment as a path.
pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| Error::missing_env_var("HOME"))
}

/// Read the current working directory.
pub fn current_dir() -> Result<PathBuf> {
    std::env::current_dir().map_err(Error::could_not_get_cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_list_orders_home_tmpfs_before_cwd_bind() {
        let home = Path::new("/home/u");
        let cwd = Path::new("/home/u/proj");
        let mounts = MountList::default_baseline(home, cwd, MountAccess::Rw);

        let home_idx = mounts
            .iter()
            .position(|m| {
                m.sandbox == home && matches!(m.kind, MountKind::Tmpfs)
            })
            .expect("home tmpfs entry");
        let cwd_idx = mounts
            .iter()
            .position(|m| {
                m.sandbox == cwd
                    && matches!(
                        m.kind,
                        MountKind::Mount {
                            access: MountAccess::Rw,
                            ..
                        }
                    )
            })
            .expect("cwd bind entry");
        assert!(
            home_idx < cwd_idx,
            "home tmpfs must precede cwd bind so the bind overlays the tmpfs",
        );
    }

    #[test]
    fn default_baseline_honors_cwd_access_ro() {
        let cwd = Path::new("/home/u/proj");
        let mounts = MountList::default_baseline(
            Path::new("/home/u"),
            cwd,
            MountAccess::Ro,
        );
        let cwd_entry = mounts
            .iter()
            .find(|m| matches!(m.source, MountSource::Cwd))
            .expect("cwd entry");
        assert!(
            matches!(
                cwd_entry.kind,
                MountKind::Mount {
                    access: MountAccess::Ro,
                    ..
                }
            ),
            "cwd_access::Ro must produce a Mount{{access:Ro}} entry, got {:?}",
            cwd_entry.kind,
        );
    }

    #[test]
    fn jsonl_serialization_emits_expected_shapes() {
        let mounts = MountList::default_baseline(
            Path::new("/home/u"),
            Path::new("/home/u/proj"),
            MountAccess::Rw,
        );
        let lines: Vec<String> = mounts
            .iter()
            .map(|m| serde_json::to_string(m).expect("serializes"))
            .collect();
        // Spot-check a few representative shapes. The `mount` kind
        // carries an `access` field whose values are lowercased.
        assert!(lines.iter().any(|l| l.contains(r#""kind":"mount""#)));
        assert!(lines.iter().any(|l| l.contains(r#""access":"ro""#)));
        assert!(lines.iter().any(|l| l.contains(r#""access":"rw""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"symlink""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"tmpfs""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"dev""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"proc""#)));
        assert!(lines.iter().any(|l| l.contains(r#""source":"cwd""#)));
        assert!(lines.iter().any(|l| l.contains(r#""source":"default""#)));
    }

    #[test]
    fn cli_mounts_appended_after_default_home_tmpfs() {
        let home = Path::new("/home/u");
        let cwd = Path::new("/home/u/proj");
        let mut mounts =
            MountList::default_baseline(home, cwd, MountAccess::Rw);

        let opts = MountOpts {
            mount: vec![MountSpec {
                host: PathBuf::from("/home/u/.gitconfig"),
                sandbox: PathBuf::from("/home/u/.gitconfig"),
                access: MountAccess::Ro,
            }],
            readonly: false,
        };
        opts.apply(&mut mounts);

        let tmpfs_idx = mounts
            .iter()
            .position(|m| {
                m.sandbox == home && matches!(m.kind, MountKind::Tmpfs)
            })
            .expect("home tmpfs");
        let cli_idx = mounts
            .iter()
            .position(|m| matches!(m.source, MountSource::Cli))
            .expect("cli mount appended");
        assert!(
            tmpfs_idx < cli_idx,
            "CLI mounts must come after the home tmpfs to punch through it",
        );
    }

    #[test]
    fn cwd_access_reflects_readonly_flag() {
        let mut opts = MountOpts::default();
        assert_eq!(opts.cwd_access(), MountAccess::Rw);
        opts.readonly = true;
        assert_eq!(opts.cwd_access(), MountAccess::Ro);
    }

    fn parse(s: &str) -> std::result::Result<MountSpec, String> {
        s.parse()
    }

    #[test]
    fn mount_spec_accepts_single_path() {
        let spec = parse("/home/u/.gitconfig").expect("parses");
        assert_eq!(spec.host, PathBuf::from("/home/u/.gitconfig"));
        assert_eq!(spec.sandbox, PathBuf::from("/home/u/.gitconfig"));
        assert_eq!(spec.access, MountAccess::Ro);
    }

    #[test]
    fn mount_spec_accepts_host_colon_sandbox() {
        let spec = parse("/host/x:/sandbox/y").expect("parses");
        assert_eq!(spec.host, PathBuf::from("/host/x"));
        assert_eq!(spec.sandbox, PathBuf::from("/sandbox/y"));
        assert_eq!(spec.access, MountAccess::Ro);
    }

    #[test]
    fn mount_spec_accepts_explicit_rw_and_ro_suffix() {
        let rw = parse("/host/x:/sandbox/y:rw").expect("parses :rw");
        assert_eq!(rw.access, MountAccess::Rw);
        let ro = parse("/host/x:/sandbox/y:ro").expect("parses :ro");
        assert_eq!(ro.access, MountAccess::Ro);
    }

    #[test]
    fn mount_spec_rejects_invalid_access_token() {
        let err = parse("/host/x:/sandbox/y:wat")
            .expect_err("bogus access token should be rejected");
        assert!(err.contains("\"wat\""), "{err}");
        assert!(err.contains("ro") && err.contains("rw"), "{err}");
    }

    #[test]
    fn mount_spec_rejects_too_many_colons() {
        // Three colons is now valid (it's the access suffix); four is not.
        let err = parse("/host/x:/sandbox/y:rw:extra")
            .expect_err("four-segment spec should be rejected");
        assert!(err.contains("more than two `:`"), "{err}");
    }

    #[test]
    fn mount_spec_rejects_relative_paths() {
        assert!(parse("relative/path").is_err());
        assert!(parse("/abs:relative").is_err());
        assert!(parse("relative:/abs").is_err());
    }
}

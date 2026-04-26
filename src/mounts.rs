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

    /// Kind of mount (with any host path or symlink target it carries).
    /// Flattened so JSONL lines look like
    /// `{"sandbox": "...", "kind": "mount-ro", "host": "...", "source": "..."}`.
    #[serde(flatten)]
    pub kind: MountKind,

    /// Where this mount came from. Lets `redoubtful mounts --jsonl`
    /// distinguish the hardcoded baseline from CLI flags or future
    /// config-file entries.
    pub source: MountSource,
}

/// The subset of bwrap mount kinds we use.
///
/// Variant names mirror our public CLI surface (`-m, --mount` and
/// `--mount-rw`) rather than bwrap's flag names, since the CLI is
/// what users see; the bwrap flag-name translation lives in
/// [`crate::bwrap`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MountKind {
    /// Read-only bind from the host (translated to bwrap `--ro-bind`).
    MountRo {
        /// Host path being bound.
        host: PathBuf,
    },
    /// Read-write bind from the host (translated to bwrap `--bind`).
    MountRw {
        /// Host path being bound.
        host: PathBuf,
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

/// Provenance of a mount — extensible.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountSource {
    /// Hardcoded baseline mount from this module.
    Default,
    /// The project directory the user invoked us from (`$PWD`).
    Cwd,
    /// Added via a `-m`/`--mount-rw` CLI flag.
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
    /// `/dev` `/proc` `/tmp`, then `--tmpfs $HOME` followed by
    /// `--bind $PWD $PWD`.
    ///
    /// Order is load-bearing — the `$HOME` tmpfs must precede the
    /// `$PWD` bind so the bind punches through the tmpfs rather than
    /// the other way around.
    pub fn default_baseline(home: &Path, cwd: &Path) -> Self {
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
        list.mount_ro("/usr", "/usr", MountSource::Default);
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
        // by [`MountList::extend_from_cli`] are similarly later in the
        // list, so they too punch through.
        //
        // Known limitation: if $PWD == $HOME, the bind would re-
        // expose the real $HOME on top of the tmpfs and defeat the
        // hiding. v0 accepts this; harden later.
        //
        //   `specs/ARCHITECTURE.md` ("Filesystem layout inside the sandbox")
        list.tmpfs(home, MountSource::Default);
        list.mount_rw(cwd, cwd, MountSource::Cwd);

        list
    }

    /// Append a read-only bind mount.
    pub fn mount_ro(
        &mut self,
        sandbox: impl Into<PathBuf>,
        host: impl Into<PathBuf>,
        source: MountSource,
    ) -> &mut Self {
        self.0.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::MountRo { host: host.into() },
            source,
        });
        self
    }

    /// Append a read-write bind mount.
    pub fn mount_rw(
        &mut self,
        sandbox: impl Into<PathBuf>,
        host: impl Into<PathBuf>,
        source: MountSource,
    ) -> &mut Self {
        self.0.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::MountRw { host: host.into() },
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

/// A single CLI-supplied bind-mount specification: a host path and
/// the sandbox path it should appear at.
///
/// Parses from `HOST_PATH[:SANDBOX_PATH]` via [`FromStr`], which
/// clap picks up automatically.
#[derive(Debug, Clone)]
pub struct MountSpec {
    /// Absolute path on the host being bind-mounted in.
    pub host: PathBuf,

    /// Absolute path inside the sandbox where it should appear.
    pub sandbox: PathBuf,
}

impl FromStr for MountSpec {
    type Err = String;

    /// Parse a `HOST_PATH[:SANDBOX_PATH]` mount specification.
    ///
    /// If only one path is given, the sandbox path equals the host
    /// path (the common case for `-m ~/.gitconfig`). At most one
    /// `:` is permitted today — additional colons are reserved for
    /// future extensions (mount options, e.g. Docker's `:ro`).
    /// Both halves must be absolute paths starting with `/`;
    /// relative paths are nonsense for bind mounts and the early
    /// failure is more helpful than bwrap's later one.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        let (host, sandbox) = match parts.as_slice() {
            [single] => (*single, *single),
            [host, sandbox] => (*host, *sandbox),
            _ => {
                return Err(format!(
                    "mount spec {s:?} contains more than one `:`; \
                     multi-colon syntax is reserved for future use"
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
    /// Bind a host path read-only into the sandbox. Repeatable.
    /// Format: `HOST_PATH[:SANDBOX_PATH]`. If `:SANDBOX_PATH` is
    /// omitted, the sandbox path equals the host path.
    #[arg(
        short = 'm',
        long = "mount",
        value_name = "HOST_PATH[:SANDBOX_PATH]"
    )]
    pub mount: Vec<MountSpec>,

    /// Bind a host path read-write into the sandbox. Repeatable.
    /// Format: `HOST_PATH[:SANDBOX_PATH]`. **Use sparingly** — a
    /// writeable mount is a hole in the sandbox by design; the agent
    /// can modify anything inside it.
    #[arg(long = "mount-rw", value_name = "HOST_PATH[:SANDBOX_PATH]")]
    pub mount_rw: Vec<MountSpec>,
}

impl MountOpts {
    /// Stat every host path up-front and return a friendly error if
    /// any are missing. Without this, the user gets bwrap's terser
    /// `Can't find source path` failure deep inside sandbox setup.
    pub fn validate(&self) -> Result<()> {
        for spec in self.mount.iter().chain(self.mount_rw.iter()) {
            std::fs::metadata(&spec.host)
                .map_err(|e| Error::missing_mount_host(spec.host.clone(), e))?;
        }
        Ok(())
    }

    /// Append CLI mounts to a [`MountList`]. Read-only mounts first,
    /// then read-write — order between the two doesn't matter for
    /// non-overlapping paths, and the deterministic ordering keeps
    /// the JSONL output predictable.
    pub fn apply(&self, list: &mut MountList) {
        for spec in &self.mount {
            list.mount_ro(
                spec.sandbox.clone(),
                spec.host.clone(),
                MountSource::Cli,
            );
        }
        for spec in &self.mount_rw {
            list.mount_rw(
                spec.sandbox.clone(),
                spec.host.clone(),
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
        let mounts = MountList::default_baseline(home, cwd);

        let home_idx = mounts
            .iter()
            .position(|m| {
                m.sandbox == home && matches!(m.kind, MountKind::Tmpfs)
            })
            .expect("home tmpfs entry");
        let cwd_idx = mounts
            .iter()
            .position(|m| {
                m.sandbox == cwd && matches!(m.kind, MountKind::MountRw { .. })
            })
            .expect("cwd bind entry");
        assert!(
            home_idx < cwd_idx,
            "home tmpfs must precede cwd bind so the bind overlays the tmpfs",
        );
    }

    #[test]
    fn jsonl_serialization_uses_kebab_case_kinds() {
        let mounts = MountList::default_baseline(
            Path::new("/home/u"),
            Path::new("/home/u/proj"),
        );
        let lines: Vec<String> = mounts
            .iter()
            .map(|m| serde_json::to_string(m).expect("serializes"))
            .collect();
        // Spot-check a few representative shapes.
        assert!(lines.iter().any(|l| l.contains(r#""kind":"mount-ro""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"mount-rw""#)));
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
        let mut mounts = MountList::default_baseline(home, cwd);

        let opts = MountOpts {
            mount: vec![MountSpec {
                host: PathBuf::from("/home/u/.gitconfig"),
                sandbox: PathBuf::from("/home/u/.gitconfig"),
            }],
            mount_rw: vec![],
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

    fn parse(s: &str) -> std::result::Result<MountSpec, String> {
        s.parse()
    }

    #[test]
    fn mount_spec_accepts_single_path() {
        let spec = parse("/home/u/.gitconfig").expect("parses");
        assert_eq!(spec.host, PathBuf::from("/home/u/.gitconfig"));
        assert_eq!(spec.sandbox, PathBuf::from("/home/u/.gitconfig"));
    }

    #[test]
    fn mount_spec_accepts_host_colon_sandbox() {
        let spec = parse("/host/x:/sandbox/y").expect("parses");
        assert_eq!(spec.host, PathBuf::from("/host/x"));
        assert_eq!(spec.sandbox, PathBuf::from("/sandbox/y"));
    }

    #[test]
    fn mount_spec_rejects_multiple_colons() {
        // Reserved for future syntax (mount options, etc.).
        let err = parse("/host/x:/sandbox/y:ro")
            .expect_err("multi-colon should be rejected");
        assert!(err.contains("more than one `:`"), "{err}");
    }

    #[test]
    fn mount_spec_rejects_relative_paths() {
        assert!(parse("relative/path").is_err());
        assert!(parse("/abs:relative").is_err());
        assert!(parse("relative:/abs").is_err());
    }
}

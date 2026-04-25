//! The list of filesystem mounts that make up the sandbox.
//!
//! This is the security-critical inventory of every place inside
//! the sandbox where data is exposed to or from the host. Both
//! [`crate::sandbox::bwrap_argv`] and the `redoubtful mounts`
//! subcommand consume the *same* inventory, so a reviewer (or the
//! test suite) can audit it without reconstructing what the bwrap
//! argv means.
//!
//! Each [`Mount`] records *what* is exposed, *how* (`--ro-bind`,
//! `--bind`, `--tmpfs`, etc.), and *where it came from* (the
//! [`MountSource`]). The source field is intentionally extensible:
//! in v0 the only sources are [`MountSource::Default`] (the
//! hardcoded baseline) and [`MountSource::Cwd`] (the project dir
//! the user invoked us from); later, configs, CLI flags, and named
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

use serde::Serialize;

use crate::prelude::*;

/// A single filesystem mount inside the sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct Mount {
    /// Absolute path inside the sandbox where this mount appears.
    pub sandbox: PathBuf,

    /// Kind of mount (with any host path or symlink target it carries).
    /// Flattened so JSONL lines look like
    /// `{"sandbox": "...", "kind": "ro-bind", "host": "...", "source": "..."}`.
    #[serde(flatten)]
    pub kind: MountKind,

    /// Where this mount came from. Lets `redoubtful mounts --jsonl`
    /// distinguish the hardcoded baseline from user-provided config
    /// (once that exists).
    pub source: MountSource,
}

/// The subset of bwrap mount kinds we use.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MountKind {
    /// Read-only bind from the host (`--ro-bind`).
    RoBind {
        /// Host path being bound.
        host: PathBuf,
    },
    /// Read-write bind from the host (`--bind`).
    Bind {
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
    // Future: Config { path: PathBuf }, Cli, NamedProfile { name: String }, etc.
}

/// Build the v0 mount inventory.
///
/// Order is load-bearing: bwrap processes mounts in argv order, and
/// a later mount overlays an earlier one. In particular the
/// `--tmpfs $HOME` entry must come before the `--bind $PWD $PWD`
/// entry so the project bind punches through the tmpfs rather than
/// the other way around.
pub fn default_mount_list(home: &Path, cwd: &Path) -> Vec<Mount> {
    vec![
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
        ro_bind("/usr", "/usr"),
        symlink("/bin", "usr/bin"),
        symlink("/sbin", "usr/sbin"),
        symlink("/lib", "usr/lib"),
        symlink("/lib64", "usr/lib64"),
        // ----- /dev, /proc, /tmp -----
        //
        // --dev creates a minimal device set (null, zero, full,
        // random, urandom, tty, /dev/pts, /dev/shm) — *not* a host
        // bind. Block and character devices on the host stay
        // invisible.
        //
        // --proc mounts a fresh procfs that only sees our pid
        // namespace. Combined with --unshare-all (which includes
        // pidns) in sandbox.rs, this is what makes `ps aux` only
        // list sandboxed processes.
        //
        // --tmpfs /tmp gives an ephemeral scratch area isolated from
        // the host /tmp. On shared/multi-user systems the host /tmp
        // is a classic tmpfile-race vector; isolation closes that.
        //
        //   <https://man.archlinux.org/man/bwrap.1.en>
        dev("/dev"),
        proc_("/proc"),
        tmpfs_("/tmp"),
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
        // rather than the other way around.
        //
        // Known limitation: if $PWD == $HOME, the bind would re-
        // expose the real $HOME on top of the tmpfs and defeat the
        // hiding. v0 accepts this; harden later.
        //
        //   `specs/ARCHITECTURE.md` ("Filesystem layout inside the sandbox")
        Mount {
            sandbox: home.to_owned(),
            kind: MountKind::Tmpfs,
            source: MountSource::Default,
        },
        Mount {
            sandbox: cwd.to_owned(),
            kind: MountKind::Bind {
                host: cwd.to_owned(),
            },
            source: MountSource::Cwd,
        },
    ]
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

// --- internal helpers; keep call sites readable ---

fn ro_bind(sandbox: &str, host: &str) -> Mount {
    Mount {
        sandbox: PathBuf::from(sandbox),
        kind: MountKind::RoBind {
            host: PathBuf::from(host),
        },
        source: MountSource::Default,
    }
}

fn symlink(sandbox: &str, target: &str) -> Mount {
    Mount {
        sandbox: PathBuf::from(sandbox),
        kind: MountKind::Symlink {
            target: target.to_owned(),
        },
        source: MountSource::Default,
    }
}

fn dev(sandbox: &str) -> Mount {
    Mount {
        sandbox: PathBuf::from(sandbox),
        kind: MountKind::Dev,
        source: MountSource::Default,
    }
}

fn proc_(sandbox: &str) -> Mount {
    Mount {
        sandbox: PathBuf::from(sandbox),
        kind: MountKind::Proc,
        source: MountSource::Default,
    }
}

fn tmpfs_(sandbox: &str) -> Mount {
    Mount {
        sandbox: PathBuf::from(sandbox),
        kind: MountKind::Tmpfs,
        source: MountSource::Default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_list_orders_home_tmpfs_before_cwd_bind() {
        let home = Path::new("/home/u");
        let cwd = Path::new("/home/u/proj");
        let mounts = default_mount_list(home, cwd);

        let home_idx = mounts
            .iter()
            .position(|m| {
                m.sandbox == home && matches!(m.kind, MountKind::Tmpfs)
            })
            .expect("home tmpfs entry");
        let cwd_idx = mounts
            .iter()
            .position(|m| {
                m.sandbox == cwd && matches!(m.kind, MountKind::Bind { .. })
            })
            .expect("cwd bind entry");
        assert!(
            home_idx < cwd_idx,
            "home tmpfs must precede cwd bind so the bind overlays the tmpfs",
        );
    }

    #[test]
    fn jsonl_serialization_uses_kebab_case_kinds() {
        let mounts =
            default_mount_list(Path::new("/home/u"), Path::new("/home/u/proj"));
        let lines: Vec<String> = mounts
            .iter()
            .map(|m| serde_json::to_string(m).expect("serializes"))
            .collect();
        // Spot-check a few representative shapes.
        assert!(lines.iter().any(|l| l.contains(r#""kind":"ro-bind""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"symlink""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"tmpfs""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"dev""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"proc""#)));
        assert!(lines.iter().any(|l| l.contains(r#""kind":"bind""#)));
        assert!(lines.iter().any(|l| l.contains(r#""source":"cwd""#)));
        assert!(lines.iter().any(|l| l.contains(r#""source":"default""#)));
    }
}

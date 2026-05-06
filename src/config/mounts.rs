//! The list of filesystem mounts that make up the sandbox.
//!
//! This is the security-critical inventory of every place inside
//! the sandbox where data is exposed to or from the host. Both
//! [`crate::sandbox::bwrap::bwrap_argv`] and the `redoubtful show` subcommand
//! consume the *same* inventory, so a reviewer (or the test suite)
//! can audit it without reconstructing what the bwrap argv means.
//!
//! Pipeline: the user declares mounts via [`MountDecls`] (`-m`,
//! `--readonly` from the CLI; the `mounts = [...]` and `readonly`
//! keys in a `[profile.NAME]` block from TOML). [`Decl::resolve`]
//! turns one `MountDecls` into a [`Mounts`] (one [`Mount`] per
//! declared spec; the `readonly` toggle rides along as an extra
//! field). Multiple `Mounts` from layered profiles + CLI merge with
//! [`Finalize::merge_right_biased`] (left-then-right concatenation
//! — order is load-bearing). [`Finalize::base_config`] reads the
//! host env to bake the standard sandbox baseline (`/usr` ro-bind +
//! the `/bin` `/sbin` `/lib` `/lib64` symlinks, `/dev`, `/proc`,
//! `/tmp`, `$HOME` tmpfs, `$PWD` bind whose access mode comes from
//! the `readonly` extra). [`Finalize::clear_extra_fields`] zeroes
//! `readonly` so the final inventory is just the mount list.
//!
//! Order is load-bearing: bwrap processes mounts in argv order and a
//! later mount overlays an earlier one. The baseline places `--tmpfs
//! $HOME` before `--bind $PWD $PWD` so the project bind punches
//! through the tmpfs; user mounts are appended after the cwd bind so
//! they too punch through.
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

use std::{
    env::{current_dir, home_dir},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeSeq};

use super::mount::{Mount, MountAccess, MountDecl, MountKind};
use crate::{
    config::{
        Decl, Finalize, NormalizeConfigPaths, resolve_context::ResolveContext,
    },
    prelude::*,
};

/// Shared mount options.
///
/// Flattened with `#[command(flatten)]` into any subcommand that
/// builds a [`Mounts`] (`run`, `show`), and `#[serde(flatten)]`-ed
/// into [`crate::config::profile::ProfileDecl`] so the same struct
/// describes both CLI flags and `[profile.NAME]` blocks.
#[derive(Debug, Clone, Default, clap::Args, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MountDecls {
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
    pub mounts: Vec<MountDecl>,

    /// Mount the working directory read-only instead of read-write.
    /// Useful for exploratory agents that should be able to read the
    /// project but not modify it. Does not affect `-m` mounts —
    /// those carry their own access mode in the spec.
    ///
    /// `Option<bool>` (rather than plain `bool`) so the merge fold
    /// across profiles + CLI uses right-biased `Option::or`: an
    /// explicit `--readonly=false` overrides a profile that set
    /// `readonly = true`, and *neither* setting it leaves the cwd
    /// at its default (read-write). The `num_args = 0..=1,
    /// default_missing_value = "true"` clap pattern preserves the
    /// bare-flag CLI ergonomics: `--readonly` (no value) still
    /// means `Some(true)`, while `--readonly=false` is now also
    /// expressible.
    #[arg(
        long = "readonly",
        num_args = 0..=1,
        default_missing_value = "true",
        value_name = "true|false"
    )]
    pub readonly: Option<bool>,
}

impl NormalizeConfigPaths for MountDecls {
    /// Delegate to each [`MountDecl`]; `readonly` carries no path data.
    fn normalize_config_paths(&mut self, home: &Path) -> Result<()> {
        for spec in &mut self.mounts {
            spec.normalize_config_paths(home)?;
        }
        Ok(())
    }
}

impl Decl for MountDecls {
    type Resolved = Mounts;

    /// Stat every host path up-front and return a friendly error if
    /// any are missing. Without this, the user gets bwrap's terser
    /// `Can't find source path` failure deep inside sandbox setup.
    fn validate(&self) -> Result<()> {
        for spec in &self.mounts {
            spec.validate()?;
        }
        Ok(())
    }

    fn resolve(&self, ctx: &ResolveContext) -> Result<Self::Resolved> {
        let mounts = self
            .mounts
            .iter()
            .map(|d| d.resolve(ctx))
            .collect::<Result<Vec<_>>>()?;
        Ok(Mounts {
            mounts,
            readonly: self.readonly,
        })
    }
}

/// The ordered list of mounts that makes up the sandbox.
///
/// Two-field struct: `mounts` is the actual inventory the runtime
/// consumes (`bwrap.rs` reads it via [`Self::iter`]); `readonly` is
/// an *extra field* in [`Finalize`] terms — user declarations flow
/// through [`Decl::resolve`] into it, then [`Finalize::base_config`]
/// reads it to choose the cwd-bind access, and
/// [`Finalize::clear_extra_fields`] zeroes it so the final inventory
/// is just the mount list. Custom [`Serialize`] emits only `mounts`
/// as a JSON array (matching the `show --json` shape), so the extra
/// stays internal.
///
/// Owns two invariants that would otherwise live as comments at
/// every call site:
///
/// - **Order is load-bearing.** bwrap processes mounts in argv order
///   and a later mount overlays an earlier one. [`Finalize::base_config`]
///   places `--tmpfs $HOME` before `--bind $PWD $PWD` so the project
///   bind punches through the tmpfs.
/// - **User mounts append after the baseline.** [`merge_right_biased`]
///   is `Vec::extend` (left-then-right), so user mounts land *after*
///   the `$HOME` tmpfs and `$PWD` bind, punching through the same
///   way. Order between multiple user mounts matches declaration
///   order.
#[derive(Debug, Default, Clone)]
pub struct Mounts {
    /// The mount inventory, in argv order.
    mounts: Vec<Mount>,

    /// User-declared `--readonly` toggle — consumed by
    /// [`Finalize::base_config`] to choose the cwd-bind access mode,
    /// then cleared by [`Finalize::clear_extra_fields`].
    readonly: Option<bool>,
}

impl Serialize for Mounts {
    /// Emit `mounts` as a JSON array, ignoring the `readonly` extra.
    /// Matches what `show --json` consumers expect: a flat sequence
    /// of mount entries, one per `--bind`/`--tmpfs`/etc the sandbox
    /// will see.
    fn serialize<S: Serializer>(
        &self,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.mounts.len()))?;
        for m in &self.mounts {
            seq.serialize_element(m)?;
        }
        seq.end()
    }
}

impl Mounts {
    /// Iterate over the mounts in declaration order. Order matters
    /// — see the type-level docs.
    pub fn iter(&self) -> std::slice::Iter<'_, Mount> {
        self.mounts.iter()
    }

    /// Number of mounts in the list. Used for tracing fields.
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// Append a bind mount with the given [`MountAccess`].
    fn mount(
        &mut self,
        sandbox: impl Into<PathBuf>,
        host: impl Into<PathBuf>,
        access: MountAccess,
    ) -> &mut Self {
        self.mounts.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Mount {
                host: host.into(),
                access,
            },
        });
        self
    }

    /// Append a symlink (`sandbox` points at `target`).
    fn symlink(
        &mut self,
        sandbox: impl Into<PathBuf>,
        target: impl Into<String>,
    ) -> &mut Self {
        self.mounts.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Symlink {
                target: target.into(),
            },
        });
        self
    }

    /// Append a tmpfs mount.
    fn tmpfs(&mut self, sandbox: impl Into<PathBuf>) -> &mut Self {
        self.mounts.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Tmpfs,
        });
        self
    }

    /// Append a `--dev` minimal device set.
    fn dev(&mut self, sandbox: impl Into<PathBuf>) -> &mut Self {
        self.mounts.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Dev,
        });
        self
    }

    /// Append a fresh procfs.
    fn proc(&mut self, sandbox: impl Into<PathBuf>) -> &mut Self {
        self.mounts.push(Mount {
            sandbox: sandbox.into(),
            kind: MountKind::Proc,
        });
        self
    }
}

impl Finalize for Mounts {
    /// Concatenate left-then-right: baseline mounts (from `self`)
    /// come first, user mounts (from `other`) append after. `readonly`
    /// is right-biased `Option::or` so a later layer's explicit
    /// toggle wins, and absence at the right preserves an earlier
    /// setting (matches the `--readonly`/`--readonly=false`/(absent)
    /// CLI fold).
    fn merge_right_biased(&self, other: &Self) -> Self {
        let mut mounts = self.mounts.clone();
        mounts.extend(other.mounts.iter().cloned());
        let readonly = other.readonly.or(self.readonly);
        Self { mounts, readonly }
    }

    /// Build the standard sandbox baseline from host env reads + the
    /// `readonly` extra.
    ///
    /// Drops the `$HOME` tmpfs / `$PWD` bind silently if `home_dir()`
    /// / `current_dir()` errors here — production paths always
    /// provide both (sandbox setup elsewhere fails first via the
    /// same helpers); this is the testable-fallback.
    fn base_config(&self) -> Self {
        let mut base = Self::default();
        push_system_baseline(&mut base);

        // ----- $HOME blanked, $PWD bind-mounted back at its real path -----
        //
        // See `specs/ARCHITECTURE.md` for the threat model: a coding
        // agent running with
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
        // rather than the other way around. User mounts merged in
        // via `merge_right_biased` land later in the list, so they
        // too punch through.
        //
        // Known limitation: if $PWD == $HOME, the bind would re-
        // expose the real $HOME on top of the tmpfs and defeat the
        // hiding. v0 accepts this; harden later.
        match home_dir() {
            Some(home) => {
                base.tmpfs(home);
            }
            None => {
                trace!("$HOME not set; dropping $HOME tmpfs");
            }
        }
        match current_dir() {
            Ok(cwd) => {
                base.mount(
                    cwd.clone(),
                    cwd,
                    MountAccess::from_readonly(self.readonly),
                );
            }
            Err(e) => {
                trace!(error = %e, "current_dir unavailable; dropping $PWD bind");
            }
        }

        base
    }

    fn clear_extra_fields(&mut self) {
        // Used by `base_config` to choose the cwd-bind access; cleared
        // here so the final inventory is just the mount list.
        self.readonly = None;
    }
}

/// Push the system-level baseline mounts that
/// [`Finalize::base_config`] starts every sandbox from: `/usr`
/// ro-bind + the standard `/bin` `/sbin` `/lib` `/lib64` symlinks,
/// `/dev`, `/proc`, `/tmp`. The caller layers `$HOME` tmpfs + `$PWD`
/// bind on top.
fn push_system_baseline(list: &mut Mounts) {
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
    list.mount("/usr", "/usr", MountAccess::Ro);
    list.symlink("/bin", "usr/bin");
    list.symlink("/sbin", "usr/sbin");
    list.symlink("/lib", "usr/lib");
    list.symlink("/lib64", "usr/lib64");

    // ----- /etc read-only -----
    //
    // Whole-/etc ro-bind, matching `specs/ARCHITECTURE.md`. The
    // alternative (cherry-pick /etc/ssl/, /etc/passwd, /etc/group,
    // /etc/hosts, /etc/resolv.conf, /etc/nsswitch.conf, /etc/services,
    // /etc/protocols, …) is a death by a thousand "why doesn't tool
    // X work?" tickets; whole-/etc is one decision that buys
    // every standard client — curl/git/openssl reading the system CA
    // bundle, name-based ownership lookups (getpwuid/getgrgid), the
    // half-dozen small files glibc consults — at once.
    //
    // Why it's safe even though /etc/shadow appears in the listing:
    //
    // - The bind mount doesn't bypass DAC. The kernel still consults
    //   the file's owner/mode on every open. /etc/shadow is 0640
    //   root:shadow, and `--unshare-all` (which includes
    //   `--unshare-user`) puts the sandbox in a userns where uid 0
    //   maps to the *host* user emk. emk doesn't own shadow, isn't
    //   in the shadow group, and the others-bit is 0 → EACCES.
    // - Capabilities in a userns only apply to resources owned by
    //   uids/gids *mapped into* that userns. /etc/shadow is owned
    //   by host root (uid 0), which isn't mapped — so even
    //   CAP_DAC_READ_SEARCH inside the sandbox doesn't unlock it.
    //   Nested userns inherit the same boundary; the mapping
    //   chain always resolves back to emk's host uid.
    //
    // Consequence: `/etc/resolv.conf` is also visible. That's fine —
    // pasta gives the netns no route to the host's resolvers, so
    // tools that try to resolve directly fail fast (which is the
    // intended outcome; the lesson is "use HTTPS_PROXY"). Without
    // the file present, glibc's resolver hangs in some configurations
    // before giving up — visible-but-unreachable is the better failure
    // mode.
    //
    //   <https://man7.org/linux/man-pages/man7/user_namespaces.7.html>
    //   <https://man.archlinux.org/man/bwrap.1.en>
    //   `specs/ARCHITECTURE.md` filesystem table.
    list.mount("/etc", "/etc", MountAccess::Ro);

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
    list.dev("/dev");
    list.proc("/proc");
    list.tmpfs("/tmp");
}

#[cfg(test)]
mod tests {
    use toml::Spanned;

    use super::*;

    #[test]
    fn jsonl_serialization_emits_expected_shapes() {
        // Build the production baseline so every `MountKind` shape is
        // exercised at least once in the JSON output.
        let mounts = Mounts::default().finalize();
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
    }

    #[test]
    fn json_serialize_hides_readonly_extra() {
        // `readonly` is an extra field; show --json must emit only
        // the mount inventory as an array.
        let mut mounts = Mounts {
            readonly: Some(true),
            ..Mounts::default()
        };
        mounts.mount("/foo", "/foo", MountAccess::Ro);
        let json = serde_json::to_string(&mounts).expect("serializes");
        // Top-level shape: array, not object.
        assert!(json.starts_with('['), "expected array, got {json}");
        assert!(!json.contains("readonly"), "readonly leaked: {json}");
    }

    // ===== base_config (new Finalize pipeline) =====

    #[test]
    fn base_config_includes_system_mounts_in_order() {
        // base_config doesn't touch host env for the system pieces
        // (/usr, /etc, /dev, /proc, /tmp); only $HOME / $PWD differ.
        let base = Mounts::default().base_config();
        let kinds: Vec<&str> = base
            .iter()
            .map(|m| match &m.kind {
                MountKind::Mount { .. } => "mount",
                MountKind::Symlink { .. } => "symlink",
                MountKind::Tmpfs => "tmpfs",
                MountKind::Dev => "dev",
                MountKind::Proc => "proc",
            })
            .collect();
        // First: /usr ro-bind + the four symlinks + /etc ro-bind +
        // /dev + /proc + /tmp. After that: $HOME tmpfs (if HOME set)
        // + $PWD bind (if cwd available).
        assert_eq!(
            &kinds[..9],
            &[
                "mount", "symlink", "symlink", "symlink", "symlink", "mount",
                "dev", "proc", "tmpfs"
            ],
            "system baseline ordering (got: {kinds:?})",
        );
    }

    #[test]
    fn base_config_exposes_etc_read_only() {
        // Pinned: /etc must be present in the baseline, ro-bound at
        // its real path. This is what makes curl/git/openssl find the
        // system CA bundle, what lets glibc's name lookups work, and
        // what most "obviously expected" host config (resolv.conf,
        // hosts, nsswitch.conf, services, protocols) flows through.
        // If a future change drops it, the failure surface across
        // standard clients is huge and silent — guard explicitly.
        let base = Mounts::default().base_config();
        let etc = base
            .iter()
            .find(|m| m.sandbox == Path::new("/etc"))
            .expect("/etc baseline mount present");
        match &etc.kind {
            MountKind::Mount { host, access } => {
                assert_eq!(host, Path::new("/etc"), "/etc binds at host path");
                assert_eq!(*access, MountAccess::Ro, "/etc must be read-only");
            }
            other => panic!("/etc must be a Mount, got {other:?}"),
        }
    }

    #[test]
    fn base_config_honors_readonly_extra() {
        // With readonly=Some(true), the cwd bind comes out Ro. We
        // depend on `current_dir()` succeeding in the test runner —
        // it does for `cargo test`.
        let env = Mounts {
            readonly: Some(true),
            ..Mounts::default()
        };
        let base = env.base_config();
        let cwd =
            std::env::current_dir().expect("test runner has a working cwd");
        let cwd_entry = base
            .iter()
            .find(|m| m.sandbox == cwd)
            .expect("cwd bind present");
        assert!(
            matches!(
                cwd_entry.kind,
                MountKind::Mount {
                    access: MountAccess::Ro,
                    ..
                }
            ),
            "readonly=Some(true) must produce Ro cwd bind, got {:?}",
            cwd_entry.kind,
        );
    }

    #[test]
    fn base_config_defaults_cwd_to_rw_when_readonly_unset() {
        let base = Mounts::default().base_config();
        let cwd =
            std::env::current_dir().expect("test runner has a working cwd");
        let cwd_entry = base
            .iter()
            .find(|m| m.sandbox == cwd)
            .expect("cwd bind present");
        assert!(matches!(
            cwd_entry.kind,
            MountKind::Mount {
                access: MountAccess::Rw,
                ..
            }
        ));
    }

    #[test]
    fn base_config_emits_home_tmpfs_from_host_env() {
        // Read-only check against the test process's $HOME — no env
        // mutation, so concurrency-safe. If the test runner has $HOME
        // unset, the entry is dropped per the impl's contract; skip.
        let base = Mounts::default().base_config();
        match std::env::var_os("HOME") {
            Some(host_home) => {
                let home_path = PathBuf::from(host_home);
                assert!(
                    base.iter().any(|m| m.sandbox == home_path
                        && matches!(m.kind, MountKind::Tmpfs)),
                    "HOME tmpfs entry must use $HOME, got {:?}",
                    base.iter().map(|m| &m.sandbox).collect::<Vec<_>>(),
                );
            }
            None => {
                assert!(
                    base.iter().all(|m| !matches!(m.kind, MountKind::Tmpfs)
                        || m.sandbox == Path::new("/tmp")),
                    "no $HOME tmpfs when $HOME unset",
                );
            }
        }
    }

    // ===== merge_right_biased / clear_extra_fields / finalize =====

    #[test]
    fn merge_right_biased_appends_user_mounts_after_base() {
        // Order matters: user mounts must come *after* baseline so
        // they punch through the same way the cwd bind does.
        let mut left = Mounts::default();
        left.mount("/baseline", "/baseline", MountAccess::Ro);
        let mut right = Mounts::default();
        right.mount("/user", "/user", MountAccess::Rw);
        let merged = left.merge_right_biased(&right);
        let sandboxes: Vec<&Path> =
            merged.iter().map(|m| m.sandbox.as_path()).collect();
        assert_eq!(sandboxes, vec![Path::new("/baseline"), Path::new("/user")],);
    }

    #[test]
    fn merge_right_biased_readonly_is_right_or_left() {
        // Right's explicit toggle wins; absence on the right falls
        // back to the left.
        let left = Mounts {
            readonly: Some(true),
            ..Mounts::default()
        };
        let right_explicit = Mounts {
            readonly: Some(false),
            ..Mounts::default()
        };
        assert_eq!(
            left.merge_right_biased(&right_explicit).readonly,
            Some(false),
        );
        let right_absent = Mounts::default();
        assert_eq!(left.merge_right_biased(&right_absent).readonly, Some(true));
    }

    #[test]
    fn clear_extra_fields_zeros_readonly() {
        let mut m = Mounts {
            readonly: Some(true),
            ..Mounts::default()
        };
        m.clear_extra_fields();
        assert!(m.readonly.is_none());
    }

    #[test]
    fn finalize_clears_readonly_and_keeps_user_mounts_after_baseline() {
        // User declares one mount + readonly; finalize bakes the
        // baseline underneath, clears the extra, and the user's
        // mount sits at the end.
        let user = Mounts {
            readonly: Some(true),
            mounts: vec![Mount {
                sandbox: PathBuf::from("/user"),
                kind: MountKind::Mount {
                    host: PathBuf::from("/user"),
                    access: MountAccess::Rw,
                },
            }],
        };
        let finalized = user.finalize();
        assert!(finalized.readonly.is_none(), "readonly must be cleared");
        // The user's /user mount lands after every baseline entry.
        let user_idx = finalized
            .iter()
            .position(|m| m.sandbox == Path::new("/user"))
            .expect("user mount survives finalize");
        // /usr from the baseline is the first entry.
        assert!(user_idx > 0, "user mount must come after baseline");
    }

    // ===== NormalizeConfigPaths impl =====

    #[test]
    fn normalize_config_paths_iterates_each_decl() {
        let mut decls = MountDecls {
            mounts: vec![
                MountDecl {
                    host: Spanned::new(0..0, PathBuf::from("~/.gitconfig")),
                    sandbox: Some(Spanned::new(
                        0..0,
                        PathBuf::from("~/.gitconfig"),
                    )),
                    access: None,
                },
                MountDecl {
                    host: Spanned::new(0..0, PathBuf::from("/etc/gitconfig")),
                    sandbox: None,
                    access: None,
                },
            ],
            readonly: None,
        };
        decls
            .normalize_config_paths(Path::new("/home/test"))
            .expect("normalizes");
        assert_eq!(
            decls.mounts[0].host.get_ref(),
            &PathBuf::from("/home/test/.gitconfig"),
        );
        assert_eq!(
            decls.mounts[0].sandbox.as_ref().unwrap().get_ref(),
            &PathBuf::from("/home/test/.gitconfig"),
        );
        // Already-absolute paths pass through unchanged.
        assert_eq!(
            decls.mounts[1].host.get_ref(),
            &PathBuf::from("/etc/gitconfig"),
        );
    }

    // ===== Decl impl =====

    #[test]
    fn decl_resolve_propagates_readonly() {
        let decls = MountDecls {
            mounts: vec![],
            readonly: Some(true),
        };
        let ctx = ResolveContext::empty();
        let resolved = decls.resolve(&ctx).expect("resolves");
        assert_eq!(resolved.readonly, Some(true));
        assert_eq!(resolved.iter().count(), 0);
    }

    #[test]
    fn decl_resolve_yields_mount_per_decl() {
        let decls = MountDecls {
            mounts: vec![
                MountDecl {
                    host: Spanned::new(0..0, PathBuf::from("/a")),
                    sandbox: None,
                    access: None,
                },
                MountDecl {
                    host: Spanned::new(0..0, PathBuf::from("/b")),
                    sandbox: Some(Spanned::new(0..0, PathBuf::from("/c"))),
                    access: Some(MountAccess::Rw),
                },
            ],
            readonly: None,
        };
        let ctx = ResolveContext::empty();
        let resolved = decls.resolve(&ctx).expect("resolves");
        let entries: Vec<(PathBuf, MountAccess)> = resolved
            .iter()
            .filter_map(|m| match &m.kind {
                MountKind::Mount { access, .. } => {
                    Some((m.sandbox.clone(), *access))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            entries,
            vec![
                (PathBuf::from("/a"), MountAccess::Ro),
                (PathBuf::from("/c"), MountAccess::Rw),
            ],
        );
    }
}

//! Build the bwrap command line for `redoubtful run`.
//!
//! Translates the mount inventory (see [`crate::mounts`]) into the
//! corresponding bwrap argv, prepends our namespace + security
//! flags, and appends the user command. The mount inventory is the
//! security-critical inventory; this file is just glue plus the
//! namespace decisions.
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
//!   CVE-2017-5226 (TIOCSTI):
//!     <https://nvd.nist.gov/vuln/detail/CVE-2017-5226>
//!   Project architecture spec:
//!     `specs/ARCHITECTURE.md`
//!
//! This file favors "comment overkill", in order to preserve security
//! justifications and original reference information for our decisions.

use std::ffi::OsString;
use std::path::Path;

use crate::argv::ArgvBuilder;
use crate::env::EnvList;
use crate::mounts::{MountAccess, MountKind, MountList};
use crate::prelude::*;

/// Build the full argv for `bwrap` (not including `bwrap` itself),
/// ending with `-- <command> <args...>`.
#[instrument(level = "debug", skip_all,
    fields(command, n_mounts = mounts.len(), n_env = env.len()))]
pub fn bwrap_argv(
    mounts: &MountList,
    env: &EnvList,
    cwd: &Path,
    command: &str,
    args: &[String],
) -> Vec<OsString> {
    let mut a = ArgvBuilder::default();

    // ===== Process namespaces =====
    //
    // Idiom: `--unshare-all --share-net`. From the bwrap manpage,
    // --share-net "Retain the network namespace (can only combine
    // with --unshare-all)". So this pair means "unshare every
    // namespace bwrap supports *except* net" — the network
    // namespace is inherited from our parent.
    //
    // Today our parent is pasta (see `crate::pasta`), which created
    // a private netns; bwrap inherits that, isolated from the host's
    // network entirely apart from the explicit pasta forwards.
    //
    // Why follow the demo's idiom rather than enumerate
    // (--unshare-ipc --unshare-pid --unshare-user --unshare-uts
    // --unshare-cgroup)? Two reasons:
    //
    // 1. Forward-compat: any new namespace future bwrap adds (e.g.
    //    time) gets unshared automatically. Enumeration would
    //    silently leave it shared with the host until someone
    //    updates the list. Fail-closed beats fail-open for a
    //    security boundary.
    //
    // 2. The demo idiom is the well-known shape; reviewers familiar
    //    with bwrap recognize it instantly.
    //
    //   <https://github.com/containers/bubblewrap/blob/main/demos/bubblewrap-shell.sh>
    //   <https://man.archlinux.org/man/bwrap.1.en>
    //
    // sloonz, "Sandboxing Applications with Bubblewrap" (part 1)
    // covers the threat model these unshares address (PID
    // visibility, IPC reach, cgroup escape via /sys/fs/cgroup, etc.):
    //
    //   <https://sloonz.github.io/posts/sandboxing-1/>
    a.flag("--unshare-all");
    a.flag("--share-net");

    // ===== Lifecycle =====
    //
    // --die-with-parent: SIGKILL the sandboxed process if our
    // immediate parent (pasta) dies. Pasta in turn carries
    // PR_SET_PDEATHSIG from `redoubtful run`, so the chain unwinds:
    // redoubtful dies → pasta dies → bwrap dies → user command dies.
    //
    //   <https://man.archlinux.org/man/bwrap.1.en>
    a.flag("--die-with-parent");

    // ===== TTY hardening =====
    //
    // --new-session: place the sandboxed process in a fresh session
    // + controlling terminal. Mitigates CVE-2017-5226: a sandboxed
    // process could otherwise use the TIOCSTI ioctl on its inherited
    // tty to inject keystrokes that the *outer* shell would execute
    // after the sandbox exits. Mandated by spec
    // (`specs/ARCHITECTURE.md`, "The bwrap invocation").
    //
    //   <https://nvd.nist.gov/vuln/detail/CVE-2017-5226>
    //   <https://man.archlinux.org/man/bwrap.1.en>
    a.flag("--new-session");

    // ===== Environment =====
    //
    // --clearenv first, then an explicit --setenv NAME VALUE for
    // each entry the inventory wants. The host's environment never
    // reaches the sandbox by inheritance — every variable inside
    // came from the curated baseline or an explicit `-e`/`--path`
    // override. This is the credential-isolation boundary: no
    // ANTHROPIC_API_KEY, GITHUB_TOKEN, SSH_AUTH_SOCK, etc. survives
    // unless the user typed it on the command line.
    //
    // The `EnvList` is already resolved at this point — passthroughs
    // were materialized against `std::env::var` when the list was
    // built (see `crate::env`), so this layer is a straight
    // translation with no host-env reads of its own. That keeps the
    // mapping from inventory to argv mechanical and auditable, and
    // means `redoubtful show --json` produces exactly the same
    // entries the running sandbox sees.
    //
    //   bwrap(1) `--clearenv`, `--setenv`:
    //     <https://man.archlinux.org/man/bwrap.1.en>
    //   `specs/ARCHITECTURE.md`, "Environment variables set inside
    //   the sandbox" + "The bwrap invocation".
    a.flag("--clearenv");
    for entry in env.iter() {
        a.triple_str("--setenv", &entry.name, &entry.value);
    }

    // ===== Mount inventory =====
    //
    // Translated 1:1 from the inventory (see `crate::mounts`). All
    // semantic decisions live there with auditability comments.
    for m in mounts.iter() {
        match &m.kind {
            MountKind::Mount { host, access } => {
                let flag = match access {
                    MountAccess::Ro => "--ro-bind",
                    MountAccess::Rw => "--bind",
                };
                a.pair_path(flag, host, &m.sandbox);
            }
            MountKind::Symlink { target } => {
                a.pair_str_path("--symlink", target, &m.sandbox);
            }
            MountKind::Tmpfs => a.single_path("--tmpfs", &m.sandbox),
            MountKind::Dev => a.single_path("--dev", &m.sandbox),
            MountKind::Proc => a.single_path("--proc", &m.sandbox),
        }
    }

    // ===== Working directory and command =====
    a.single_path("--chdir", cwd);
    a.flag("--");
    a.flag(command);
    a.extend_args(args);
    let argv = a.into_vec();

    // Per spec: log the exact bwrap argv at DEBUG so users can
    // reproduce failures by hand. (`specs/ARCHITECTURE.md` final notes.)
    debug!(?argv, "bwrap argv");
    argv
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;
    use crate::mounts::MountAccess;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn find_pair(
        argv: &[OsString],
        flag: &str,
    ) -> Option<(OsString, OsString)> {
        let pos = argv
            .iter()
            .position(|a| a.as_os_str() == OsStr::new(flag))?;
        let one = pos.checked_add(1)?;
        let two = pos.checked_add(2)?;
        Some((argv.get(one)?.clone(), argv.get(two)?.clone()))
    }

    #[test]
    fn argv_starts_with_unshare_all_share_net() {
        let mounts = MountList::default_baseline(
            Path::new("/home/u"),
            Path::new("/home/u/proj"),
            MountAccess::Rw,
        );
        let env = EnvList::default_baseline(Path::new("/home/u"), None, &[]);
        let argv =
            bwrap_argv(&mounts, &env, Path::new("/home/u/proj"), "true", &[]);
        assert_eq!(argv.first(), Some(&os("--unshare-all")));
        assert_eq!(argv.get(1), Some(&os("--share-net")));
    }

    #[test]
    fn argv_includes_die_with_parent_and_new_session() {
        let mounts = MountList::default_baseline(
            Path::new("/home/u"),
            Path::new("/home/u/proj"),
            MountAccess::Rw,
        );
        let env = EnvList::default_baseline(Path::new("/home/u"), None, &[]);
        let argv =
            bwrap_argv(&mounts, &env, Path::new("/home/u/proj"), "true", &[]);
        assert!(argv.contains(&os("--die-with-parent")));
        assert!(argv.contains(&os("--new-session")));
    }

    #[test]
    fn argv_translates_default_mounts() {
        let mounts = MountList::default_baseline(
            Path::new("/home/u"),
            Path::new("/home/u/proj"),
            MountAccess::Rw,
        );
        let env = EnvList::default_baseline(Path::new("/home/u"), None, &[]);
        let argv =
            bwrap_argv(&mounts, &env, Path::new("/home/u/proj"), "true", &[]);
        assert_eq!(
            find_pair(&argv, "--ro-bind"),
            Some((os("/usr"), os("/usr"))),
        );
        assert_eq!(
            find_pair(&argv, "--symlink"),
            Some((os("usr/bin"), os("/bin"))),
        );
        assert_eq!(
            find_pair(&argv, "--bind"),
            Some((os("/home/u/proj"), os("/home/u/proj"))),
        );
    }

    #[test]
    fn argv_emits_clearenv_before_setenvs() {
        // Regression-guard the credential-isolation property: every
        // --setenv must come *after* --clearenv, otherwise the
        // bwrap manpage says the setenv is undone when clearenv
        // runs. (See `man bwrap`: "These options change in the
        // order they are given.")
        let mounts = MountList::default_baseline(
            Path::new("/home/u"),
            Path::new("/home/u/proj"),
            MountAccess::Rw,
        );
        let mut env = EnvList::new();
        env.set("FOO", "bar".to_owned(), crate::env::EnvSource::Default);
        let argv =
            bwrap_argv(&mounts, &env, Path::new("/home/u/proj"), "true", &[]);
        let clear_idx = argv
            .iter()
            .position(|a| a.as_os_str() == OsStr::new("--clearenv"))
            .expect("--clearenv emitted");
        let setenv_idx = argv
            .iter()
            .position(|a| a.as_os_str() == OsStr::new("--setenv"))
            .expect("--setenv emitted");
        assert!(
            clear_idx < setenv_idx,
            "--clearenv must precede --setenv (clear={clear_idx}, set={setenv_idx})",
        );
    }

    #[test]
    fn argv_emits_setenv_per_entry_in_order() {
        // The translation from EnvList to argv is a straight
        // 1:1 emit; verify that two entries produce two
        // --setenv NAME VALUE triples in order.
        let mounts = MountList::default_baseline(
            Path::new("/home/u"),
            Path::new("/home/u/proj"),
            MountAccess::Rw,
        );
        let mut env = EnvList::new();
        env.set("ALPHA", "1".to_owned(), crate::env::EnvSource::Default);
        env.set("BETA", "2".to_owned(), crate::env::EnvSource::Default);
        let argv =
            bwrap_argv(&mounts, &env, Path::new("/home/u/proj"), "true", &[]);
        // Find the first --setenv occurrence; the next two args
        // are name+value, then another --setenv with the next pair.
        let first = argv
            .iter()
            .position(|a| a.as_os_str() == OsStr::new("--setenv"))
            .expect("--setenv emitted");
        assert_eq!(argv.get(first + 1), Some(&os("ALPHA")));
        assert_eq!(argv.get(first + 2), Some(&os("1")));
        assert_eq!(argv.get(first + 3), Some(&os("--setenv")));
        assert_eq!(argv.get(first + 4), Some(&os("BETA")));
        assert_eq!(argv.get(first + 5), Some(&os("2")));
    }

    #[test]
    fn command_and_args_appear_after_double_dash() {
        let mounts = MountList::default_baseline(
            Path::new("/home/u"),
            Path::new("/home/u/proj"),
            MountAccess::Rw,
        );
        let env = EnvList::default_baseline(Path::new("/home/u"), None, &[]);
        let argv = bwrap_argv(
            &mounts,
            &env,
            Path::new("/home/u/proj"),
            "echo",
            &["hello".to_string(), "world".to_string()],
        );
        let dash = argv
            .iter()
            .position(|a| a.as_os_str() == OsStr::new("--"))
            .expect("-- separator present");
        assert_eq!(argv.get(dash + 1), Some(&os("echo")));
        assert_eq!(argv.get(dash + 2), Some(&os("hello")));
        assert_eq!(argv.get(dash + 3), Some(&os("world")));
    }
}

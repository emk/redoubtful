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

use crate::mounts::{Mount, MountKind};
use crate::prelude::*;

/// Build the full argv for `bwrap` (not including `bwrap` itself),
/// ending with `-- <command> <args...>`.
#[instrument(level = "debug", skip_all,
    fields(command, n_mounts = mounts.len()))]
pub fn bwrap_argv(
    mounts: &[Mount],
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
    // Today, our parent is the user's shell, so we inherit the host
    // netns (full Internet access — temporary, will be locked down
    // when we add pasta). Tomorrow, our parent will be pasta, and we
    // inherit pasta's restricted netns the same way.
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
    // launcher (this process) dies. Without this, `kill -9` of
    // redoubtful would orphan the sandboxed agent.
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

    // ===== Mount inventory =====
    //
    // Translated 1:1 from the inventory (see `crate::mounts`). All
    // semantic decisions live there with auditability comments.
    for m in mounts {
        match &m.kind {
            MountKind::RoBind { host } => {
                a.pair_path("--ro-bind", host, &m.sandbox)
            }
            MountKind::Bind { host } => a.pair_path("--bind", host, &m.sandbox),
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
    a.into_vec()
}

/// Internal helper that accumulates `OsString` argv tokens. Keeps
/// the call site readable (one logical step per line).
#[derive(Default)]
struct ArgvBuilder {
    argv: Vec<OsString>,
}

impl ArgvBuilder {
    fn flag(&mut self, s: &str) {
        self.argv.push(OsString::from(s));
    }

    fn single_path(&mut self, flag: &str, p: &Path) {
        self.argv.push(OsString::from(flag));
        self.argv.push(p.as_os_str().to_owned());
    }

    fn pair_path(&mut self, flag: &str, a: &Path, b: &Path) {
        self.argv.push(OsString::from(flag));
        self.argv.push(a.as_os_str().to_owned());
        self.argv.push(b.as_os_str().to_owned());
    }

    fn pair_str_path(&mut self, flag: &str, a: &str, b: &Path) {
        self.argv.push(OsString::from(flag));
        self.argv.push(OsString::from(a));
        self.argv.push(b.as_os_str().to_owned());
    }

    fn extend_args(&mut self, args: &[String]) {
        for a in args {
            self.argv.push(OsString::from(a));
        }
    }

    fn into_vec(self) -> Vec<OsString> {
        self.argv
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;
    use crate::mounts::default_mount_list;

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
        let mounts =
            default_mount_list(Path::new("/home/u"), Path::new("/home/u/proj"));
        let argv = bwrap_argv(&mounts, Path::new("/home/u/proj"), "true", &[]);
        assert_eq!(argv.first(), Some(&os("--unshare-all")));
        assert_eq!(argv.get(1), Some(&os("--share-net")));
    }

    #[test]
    fn argv_includes_die_with_parent_and_new_session() {
        let mounts =
            default_mount_list(Path::new("/home/u"), Path::new("/home/u/proj"));
        let argv = bwrap_argv(&mounts, Path::new("/home/u/proj"), "true", &[]);
        assert!(argv.contains(&os("--die-with-parent")));
        assert!(argv.contains(&os("--new-session")));
    }

    #[test]
    fn argv_translates_default_mounts() {
        let mounts =
            default_mount_list(Path::new("/home/u"), Path::new("/home/u/proj"));
        let argv = bwrap_argv(&mounts, Path::new("/home/u/proj"), "true", &[]);
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
    fn command_and_args_appear_after_double_dash() {
        let mounts =
            default_mount_list(Path::new("/home/u"), Path::new("/home/u/proj"));
        let argv = bwrap_argv(
            &mounts,
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

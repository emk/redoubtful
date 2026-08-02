//! Tests for sandbox filesystem behavior.

use std::{collections::HashSet, path::PathBuf};

use predicates::str::contains;

use crate::utils::{cmd, show_json::ShowJson};

#[test]
fn run_hides_unexpected_paths_in_home() {
    // (1) Ask the binary what it intends to expose.
    let show_out = cmd().args(["show", "--json"]).output().expect("show");
    assert!(
        show_out.status.success(),
        "show --json failed: {show_out:?}",
    );
    let stdout = std::str::from_utf8(&show_out.stdout).expect("utf-8");
    let parsed: ShowJson = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("bad show json {stdout:?}: {e}"));
    let mounts = parsed.mounts;
    assert!(!mounts.is_empty(), "no mounts emitted");

    // (2) Compute the allowlist: the first path component of any
    //     mount whose sandbox path sits at or below $HOME. Bwrap
    //     auto-creates these path components inside the tmpfs to
    //     host downstream bind/symlink mounts (e.g. for a project
    //     at $HOME/w/src/redoubtful, "w" is allowed).
    let home = PathBuf::from(std::env::var("HOME").expect("HOME"));
    let allowed: HashSet<String> = mounts
        .iter()
        .filter_map(|m| m.sandbox.strip_prefix(&home).ok())
        .filter_map(|rel| rel.components().next())
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();

    // (3) List $HOME inside the sandbox and assert every entry is
    //     in the allowlist.
    let ls = cmd()
        .args(["run", "ls", "-A", home.to_str().expect("utf-8 home")])
        .output()
        .expect("ls");
    assert!(ls.status.success(), "ls failed: {ls:?}");
    let actual: Vec<&str> = std::str::from_utf8(&ls.stdout)
        .expect("utf-8")
        .lines()
        .collect();

    for entry in &actual {
        assert!(
            allowed.contains(*entry),
            "unexpected entry in sandboxed $HOME: {entry:?}\n  \
             allowed (per `redoubtful show --json`): {allowed:?}\n  \
             actual  (per `redoubtful run -- ls -A $HOME`): {actual:?}",
        );
    }
}

#[test]
fn run_keeps_cwd_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("marker"), b"hello from cwd")
        .expect("write");

    cmd()
        .current_dir(dir.path())
        .args(["run", "cat", "marker"])
        .assert()
        .success()
        .stdout(contains("hello from cwd"));
}

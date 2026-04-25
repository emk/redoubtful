//! Integration tests for the `redoubtful` CLI.
//!
//! The load-bearing assertions for the v0 sandbox are
//! [`run_hides_unexpected_paths_in_home`] (no $HOME leaks) and
//! [`run_keeps_cwd_visible`] (project dir actually usable inside).
//! Everything else exercises plumbing.
//!
//! `run_hides_unexpected_paths_in_home` consumes the binary's own
//! `mounts --jsonl` output as the source of truth for what the
//! sandbox is supposed to expose. We list `$HOME` *inside* the
//! sandbox, then assert that every entry visible there corresponds
//! to a mount the binary said it intended to expose.
//!
//! Caveat (deliberate): this test implicitly assumes the user's
//! real `$HOME` is not magically empty. If it is, the assertion
//! passes trivially without verifying the tmpfs is doing anything.
//! In any realistic dev or CI environment, `$HOME` has dotfiles,
//! ~/.cargo, etc. — so the corner case is acknowledged but not
//! engineered around.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};

/// Our CLI command.
fn cmd() -> Command {
    Command::cargo_bin("redoubtful").expect("binary exists")
}

/// Minimal struct mirroring `mounts::Mount` for deserialization.
/// Defined here (not imported) because integration tests don't share
/// crate-internal types — and the test should fail loudly if the
/// JSONL shape changes unexpectedly.
#[derive(serde::Deserialize)]
struct MountJson {
    sandbox: PathBuf,
    // Other fields ignored — we only need `sandbox` for the
    // unexpected-paths assertion below.
}

#[test]
fn version_flag_prints_package_version() {
    cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_flag_prints_usage() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Usage:").and(contains("redoubtful")));
}

#[test]
fn run_executes_the_given_command() {
    cmd()
        .args(["run", "echo", "hello from redoubtful"])
        .assert()
        .success()
        .stdout(contains("hello from redoubtful"));
}

#[test]
fn run_propagates_child_exit_code() {
    cmd().args(["run", "sh", "-c", "exit 42"]).assert().code(42);
}

#[test]
fn run_reports_missing_command() {
    // bwrap prints `bwrap: execvp <name>: No such file or directory`
    // on stderr when the inner exec fails. The binary name still
    // appears, which is what the user cares about.
    cmd()
        .args(["run", "redoubtful-no-such-binary-xyz"])
        .assert()
        .failure()
        .stderr(contains("redoubtful-no-such-binary-xyz"));
}

#[test]
fn mounts_jsonl_is_parseable() {
    let out = cmd().args(["mounts", "--jsonl"]).output().expect("mounts");
    assert!(out.status.success(), "mounts --jsonl failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    assert!(!stdout.is_empty(), "no mounts emitted");
    for line in stdout.lines() {
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("bad jsonl line {line:?}: {e}"));
    }
}

#[test]
fn run_hides_unexpected_paths_in_home() {
    // (1) Ask the binary what it intends to expose.
    let mounts_out =
        cmd().args(["mounts", "--jsonl"]).output().expect("mounts");
    assert!(
        mounts_out.status.success(),
        "mounts --jsonl failed: {mounts_out:?}",
    );
    let stdout = std::str::from_utf8(&mounts_out.stdout).expect("utf-8");
    let mounts: Vec<MountJson> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid jsonl line"))
        .collect();
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
             allowed (per `redoubtful mounts --jsonl`): {allowed:?}\n  \
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

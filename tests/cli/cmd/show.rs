//! Tests for the `show` subcommand.

use std::collections::HashSet;

use crate::utils::{
    cmd, cmd_clean,
    show_json::{EnvJson, ShowJson},
};

#[test]
fn show_json_is_parseable() {
    let out = cmd().args(["show", "--json"]).output().expect("show");
    assert!(out.status.success(), "show --json failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    let parsed: ShowJson = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("bad show json {stdout:?}: {e}"));
    assert!(!parsed.mounts.is_empty(), "no mounts emitted");
    // Empty `forwards` is the expected baseline — no `-f` was passed.
    assert!(parsed.forwards.is_empty(), "unexpected forwards: {stdout}");
}

#[test]
fn show_json_includes_cli_mounts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host_file = dir.path().join("marker");
    std::fs::write(&host_file, b"x").expect("write marker");
    let spec =
        format!("{}:{}", host_file.to_str().expect("utf-8"), "/work/marker",);

    let out = cmd()
        .args(["show", "--json", "-m", &spec])
        .output()
        .expect("show");
    assert!(out.status.success(), "show --json failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    assert!(
        stdout.contains("/work/marker"),
        "expected the sandbox path /work/marker to appear; got:\n{stdout}",
    );
}

#[test]
fn show_json_includes_forwards() {
    let out = cmd()
        .args(["show", "--json", "-f", "8080", "-f", "5432:9999"])
        .output()
        .expect("show");
    assert!(out.status.success(), "show --json failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    let parsed: ShowJson = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("bad show json {stdout:?}: {e}"));
    assert_eq!(
        parsed.forwards.len(),
        2,
        "expected 2 forwards; got:\n{stdout}",
    );
    assert_eq!(parsed.forwards[0].host_port, 8080);
    assert_eq!(parsed.forwards[0].sandbox_port, 8080);
    assert_eq!(parsed.forwards[1].host_port, 5432);
    assert_eq!(parsed.forwards[1].sandbox_port, 9999);
}

#[test]
fn show_json_includes_env() {
    let out = cmd_clean()
        .env("TERM", "xterm-256color")
        .args(["show", "--json"])
        .output()
        .expect("show");
    assert!(out.status.success(), "show --json failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    let parsed: ShowJson = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("bad show json {stdout:?}: {e}"));

    let by_name = |name: &str| -> Option<&EnvJson> {
        parsed.env.iter().find(|e| e.name == name)
    };

    let path = by_name("PATH").expect("PATH entry present");
    assert_eq!(
        path.value,
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );

    let home = by_name("HOME").expect("HOME entry present");
    assert_eq!(
        home.value,
        std::env::var("HOME").expect("test process needs HOME"),
    );

    let term = by_name("TERM").expect("TERM entry present (passthrough)");
    assert_eq!(term.value, "xterm-256color");
}

#[test]
fn show_json_omits_unset_passthroughs() {
    // With cmd_clean(), only HOME and PATH are set on the test
    // process; everything else in the curated passthrough list is
    // unset. Those names should not appear in `show --json` output
    // — passthroughs are resolved eagerly at construction, so an
    // unset host var means no entry at all.
    let out = cmd_clean().args(["show", "--json"]).output().expect("show");
    assert!(out.status.success(), "show --json failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    let parsed: ShowJson = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("bad show json {stdout:?}: {e}"));
    let names: HashSet<&str> =
        parsed.env.iter().map(|e| e.name.as_str()).collect();

    // PATH and HOME are always present; everything below is a
    // passthrough that resolved to nothing under cmd_clean().
    assert!(names.contains("PATH"));
    assert!(names.contains("HOME"));
    for absent in &["EDITOR", "VISUAL", "PAGER", "LC_ALL", "TZ"] {
        assert!(
            !names.contains(*absent),
            "{absent:?} should be absent under a clean env; \
             got names: {names:?}",
        );
    }
}

//! Tests for the `check` subcommand.

use predicates::{prelude::PredicateBooleanExt, str::contains};

use crate::utils::{cmd, cmd_empty_path};

#[test]
fn check_on_healthy_host_passes() {
    // The check report goes to stderr in both `check` and `run` —
    // it's diagnostic output, not data, so stdout stays free for a
    // future `--json` mode.
    cmd()
        .env("NO_COLOR", "1")
        .arg("check")
        .assert()
        .success()
        .stderr(contains("✅ bwrap").and(contains("All checks passed.")));
}

#[test]
fn check_with_bwrap_missing_fails_and_skips_userns() {
    let out = cmd_empty_path()
        .arg("check")
        .output()
        .expect("check with empty PATH");
    assert!(!out.status.success(), "expected failure: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    // The bwrap fail header reads "❌ `bwrap` not found on $PATH" —
    // substring-match the bare binary name to avoid getting tangled
    // up in the backticks in the error message.
    assert!(stderr.contains("not found on $PATH"), "stderr: {stderr}");
    // userns must be Skip (not Fail) when bwrap is missing —
    // we shouldn't fake-fail a check whose prerequisite isn't met.
    assert!(stderr.contains("➖"), "skip glyph absent: {stderr}");
    assert!(
        stderr.contains("bwrap to check"),
        "userns skip absent: {stderr}"
    );
    assert!(stderr.contains("checks failed."), "stderr: {stderr}");
}

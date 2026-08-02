//! Basic `run` checks only.
//!
//! This does not include deeper tests of sandbox machinery, which
//! are handled elsewhere.

use predicates::str::contains;

use crate::utils::{cmd, cmd_empty_path};

#[test]
fn run_silent_on_preflight_success() {
    let out = cmd()
        .args(["run", "/bin/true"])
        .output()
        .expect("run /bin/true");
    assert!(out.status.success(), "run failed: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    // The preflight report contains this exact header. If preflight
    // passed we should not see it; pasta's own "No routable
    // interface for IPv6" lines on stderr are fine to ignore.
    assert!(
        !stderr.contains("Checking redoubtful prerequisites"),
        "preflight report should be silent on success; stderr: {stderr}",
    );
}

#[test]
fn run_emits_preflight_report_to_stderr_on_failure() {
    let out = cmd_empty_path()
        .args(["run", "/bin/true"])
        .output()
        .expect("run with empty PATH");
    assert!(!out.status.success(), "expected run to fail: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    // Preflight failure → the bwrap-missing header lands on stderr.
    // The "❌" emoji is unique to the report so its presence proves
    // preflight actually ran (vs. an empty stderr caused by some
    // unrelated early-bail).
    assert!(
        stderr.contains("❌") && stderr.contains("not found on $PATH"),
        "preflight report missing on stderr: stderr={stderr} stdout={stdout}",
    );
    // The user's command must not have run.
    assert_eq!(stdout, "", "stdout should be empty: {stdout}");
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
fn run_preserves_non_utf8_argv_bytes() {
    // Stray 0xff byte: invalid UTF-8 at any code unit boundary, so
    // any layer that called `to_string_lossy` on the argv would
    // replace it with U+FFFD (`\xef\xbf\xbd`) and the assertion
    // below would fail. The sandboxed `printf '%s' <arg>` echoes
    // the arg byte-for-byte to stdout, which `assert_cmd` exposes
    // as raw bytes — letting us verify the argv survived clap →
    // our types → bwrap argv → `execve` without a lossy hop.
    use std::os::unix::ffi::OsStringExt as _;
    let bytes: &[u8] = b"prefix-\xff-suffix";
    let arg = std::ffi::OsString::from_vec(bytes.to_vec());
    let out = cmd()
        .arg("run")
        .arg("/usr/bin/printf")
        .arg("%s")
        .arg(&arg)
        .output()
        .expect("run printf with non-UTF-8 arg");
    assert!(out.status.success(), "run failed: {out:?}");
    assert_eq!(
        out.stdout, bytes,
        "non-UTF-8 argv bytes did not survive into the sandbox",
    );
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

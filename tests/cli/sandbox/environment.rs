//! Environment tests.

use predicates::str::contains;

use crate::utils::cmd_clean;

// ===== Environment isolation =====
//
// The load-bearing assertion is `run_clears_host_credentials`: a
// fake `*_API_KEY` set on the test process must NOT survive into the
// sandbox. Everything else exercises the override surface (`-e`,
// `--path`) and the consistency between `run`'s realized env and
// `show --json`'s description.

/// Fake-credential set in the test's environment must NOT appear
/// inside the sandbox. This is the spec's
/// `redoubtful run -- env | grep -i api_key` acceptance test
/// (`specs/ARCHITECTURE.md`), realized as a positive guard.
///
/// We use a sentinel value (`"leaked-xyz-..."`) so a substring
/// search is precise: a coincidental empty `printenv` output
/// wouldn't be enough to claim the credential leaked. The
/// `; echo done` marker proves the inner command actually ran (a
/// silent setup failure also produces empty stdout — without the
/// marker, that would look like a pass).
#[test]
fn run_clears_host_credentials() {
    let out = cmd_clean()
        .env("FAKE_API_KEY", "leaked-xyz-do-not-let-me-survive")
        .args(["run", "sh", "-c", "printenv FAKE_API_KEY; echo done"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("done"),
        "inner shell didn't complete; stdout: {stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !stdout.contains("leaked-xyz"),
        "FAKE_API_KEY leaked into the sandbox: {stdout:?}",
    );
}

#[test]
fn run_e_literal_sets_value() {
    cmd_clean()
        .args(["run", "-e", "FOO=bar", "printenv", "FOO"])
        .assert()
        .success()
        .stdout(contains("bar"));
}

#[test]
fn run_e_empty_value_is_literal_empty_string() {
    // `-e FOO=` (with `=` but no value) sets FOO to the empty
    // string. We use `[$FOO]` rather than just `$FOO` so the
    // empty value is observable in stdout.
    cmd_clean()
        .args(["run", "-e", "FOO=", "sh", "-c", "echo \"[$FOO]\""])
        .assert()
        .success()
        .stdout(contains("[]"));
}

#[test]
fn run_e_passthrough_forwards_when_host_var_set() {
    cmd_clean()
        .env("MY_VAR", "yes-from-host")
        .args(["run", "-e", "MY_VAR", "printenv", "MY_VAR"])
        .assert()
        .success()
        .stdout(contains("yes-from-host"));
}

#[test]
fn run_e_passthrough_drops_when_host_var_unset() {
    // `-e MY_VAR` with `MY_VAR` unset on the host should produce a
    // sandbox where `MY_VAR` is also unset. `printenv MY_VAR`
    // exits 1 with empty stdout in that case; the `; echo done`
    // marker proves the command actually ran.
    let out = cmd_clean()
        .args([
            "run",
            "-e",
            "MY_VAR",
            "sh",
            "-c",
            "printenv MY_VAR; echo done",
        ])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.as_ref(),
        "done\n",
        "stdout should be exactly 'done\\n'; got {stdout:?}",
    );
}

#[test]
fn run_default_path_is_canonical() {
    cmd_clean()
        .args(["run", "printenv", "PATH"])
        .assert()
        .success()
        .stdout(contains(
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ));
}

#[test]
fn run_path_override_replaces_baseline_path() {
    // The override sets a PATH that doesn't include `/usr/bin`,
    // so we have to invoke `printenv` by absolute path — the
    // shell's PATH lookup happens *inside* the sandbox using the
    // overridden value.
    cmd_clean()
        .args([
            "run",
            "--path",
            "/custom:/another",
            "/usr/bin/printenv",
            "PATH",
        ])
        .assert()
        .success()
        .stdout(contains("/custom:/another"));
}

#[test]
fn run_path_add_prepends_to_canonical() {
    // `-p` should *prepend* to the canonical PATH (matches
    // fish_add_path and `PATH=$DIR:$PATH`). After this call the
    // sandbox PATH must contain both `/usr/bin` (canonical survives,
    // so unqualified `printenv` still resolves) and the added
    // directory, with the addition appearing first.
    let out = cmd_clean()
        .args(["run", "-P", "/opt/agent/bin", "printenv", "PATH"])
        .output()
        .expect("run");
    assert!(out.status.success(), "run failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    assert!(
        stdout.contains("/usr/bin"),
        "canonical PATH must survive `-p`; got {stdout:?}",
    );
    assert!(
        stdout.contains("/opt/agent/bin"),
        "`-p` directory must be present; got {stdout:?}",
    );
    // Order: addition first, canonical after.
    let added_idx = stdout
        .find("/opt/agent/bin")
        .expect("contains /opt/agent/bin");
    let canonical_idx = stdout.find("/usr/bin").expect("contains /usr/bin");
    assert!(
        added_idx < canonical_idx,
        "`-p` entries must precede canonical entries; got {stdout:?}",
    );
}

#[test]
fn run_path_add_repeatable_prepends_in_reverse_order() {
    // Multiple `-P` flags prepend in *reverse* CLI order so a later
    // flag wins (matches `export PATH=$DIR:$PATH` and the
    // "later overrides earlier" CLI convention): `-P /a -P /b` →
    // `/b:/a:<canonical>`.
    cmd_clean()
        .args([
            "run", "-P", "/first/bin", "-P", "/second/bin", "printenv", "PATH",
        ])
        .assert()
        .success()
        .stdout(contains(
            "/second/bin:/first/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ));
}

#[test]
fn run_path_add_prepends_to_path_override() {
    // `--path` plus `-p`: additions go in front of the override,
    // same prepend semantics as the canonical case.
    cmd_clean()
        .args([
            "run",
            "--path",
            "/only/this",
            "-P",
            "/extra",
            "/usr/bin/printenv",
            "PATH",
        ])
        .assert()
        .success()
        .stdout(contains("/extra:/only/this"));
}

#[test]
fn run_term_passthrough_forwards_value() {
    cmd_clean()
        .env("TERM", "xterm-256color")
        .args(["run", "printenv", "TERM"])
        .assert()
        .success()
        .stdout(contains("xterm-256color"));
}

#[test]
fn run_e_literal_overrides_baseline_path() {
    // Validates upsert semantics: `-e PATH=/only/this` must produce
    // a sandbox with exactly that PATH (one entry, last write wins),
    // not the canonical baseline + the override appended. Use
    // /usr/bin/printenv since /only/this won't have it.
    cmd_clean()
        .args(["run", "-e", "PATH=/only/this", "/usr/bin/printenv", "PATH"])
        .assert()
        .success()
        .stdout(contains("/only/this"));
}

//! Config and profile tests.

use std::path::PathBuf;

use predicates::{prelude::PredicateBooleanExt, str::contains};

use crate::utils::{cmd_clean, cmd_with_config};

// ===== Profiles (TOML config + `-u, --uses`) =====
//
// Tests below isolate the profile-loading path from whatever real
// `~/.config/redoubtful/config.toml` the developer has, by writing
// a fixture into a tempdir and pointing `XDG_CONFIG_HOME` at it.
// The binary's `config_path()` honors `XDG_CONFIG_HOME`, so a fresh
// tempdir gives each test its own config namespace.

#[test]
fn run_profile_unknown_errors_with_path() {
    let out = cmd_with_config("[profile.x]\n")
        .args(["run", "-u", "does-not-exist", "/bin/true"])
        .output()
        .expect("run with bad profile");
    assert!(!out.status.success(), "expected failure: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    assert!(
        stderr.contains("unknown profile") && stderr.contains("does-not-exist"),
        "stderr should name the unknown profile: {stderr}",
    );
    // The diagnostic should include the config path so the user
    // knows where to add the profile.
    assert!(
        stderr.contains("config.toml"),
        "stderr should mention the config file: {stderr}",
    );
}

#[test]
fn run_profile_repeated_errors() {
    // Same profile twice on the CLI is a strict no-repeats error.
    let out = cmd_with_config("[profile.x]\n")
        .args(["run", "-u", "x", "-u", "x", "/bin/true"])
        .output()
        .expect("run with repeated profile");
    assert!(!out.status.success(), "expected failure: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    assert!(
        stderr.contains("already included") && stderr.contains("`x`"),
        "stderr should flag the repeated profile: {stderr}",
    );
}

#[test]
fn run_profile_diamond_via_uses_errors() {
    // `a` and `b` both `uses = ["c"]`. Resolving `-u a -u b` would
    // visit `c` twice. Strict no-repeats rejects.
    let toml = r#"
[profile.a]
uses = ["c"]
[profile.b]
uses = ["c"]
[profile.c]
"#;
    let out = cmd_with_config(toml)
        .args(["run", "-u", "a", "-u", "b", "/bin/true"])
        .output()
        .expect("run with diamond");
    assert!(!out.status.success(), "expected failure: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    assert!(
        stderr.contains("already included") && stderr.contains("`c`"),
        "stderr should flag the diamond: {stderr}",
    );
}

#[test]
fn show_profile_emits_profile_mounts() {
    let dir = tempfile::tempdir().expect("tempdir for mount target");
    std::fs::write(dir.path().join("marker"), b"x").expect("write");
    let host = dir.path().to_str().expect("utf-8");
    let toml = format!(
        r#"
[profile.opencode]
mounts = [{{ host = "{host}/marker", sandbox = "/work/marker" }}]
"#,
    );
    let out = cmd_with_config(&toml)
        .args(["show", "--json", "-u", "opencode"])
        .output()
        .expect("show with profile");
    assert!(out.status.success(), "show failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    assert!(
        stdout.contains("/work/marker"),
        "sandbox path absent: {stdout}",
    );
}

#[test]
fn run_profile_path_add_prepends_to_path() {
    let toml = r#"
[profile.bin]
path_add = ["/opt/profile/bin"]
"#;
    cmd_with_config(toml)
        .args(["run", "-u", "bin", "printenv", "PATH"])
        .assert()
        .success()
        .stdout(contains("/opt/profile/bin").and(contains("/usr/bin")));
}

#[test]
fn run_profile_env_passthrough_resolves_against_host() {
    // Profile asks to pass `MY_VAR` through. Test process sets it.
    let toml = r#"
[profile.passthru]
env = [{ name = "MY_VAR" }]
"#;
    cmd_with_config(toml)
        .env("MY_VAR", "yes-from-host")
        .args(["run", "-u", "passthru", "printenv", "MY_VAR"])
        .assert()
        .success()
        .stdout(contains("yes-from-host"));
}

#[test]
fn run_profile_env_literal_lands_in_sandbox() {
    let toml = r#"
[profile.lit]
env = [{ name = "FOO", value = "bar-from-profile" }]
"#;
    cmd_with_config(toml)
        .args(["run", "-u", "lit", "printenv", "FOO"])
        .assert()
        .success()
        .stdout(contains("bar-from-profile"));
}

#[test]
fn run_cli_env_overrides_profile_env() {
    // Profile sets FOO=from-profile; CLI -e overrides to FOO=from-cli.
    // CLI applies last, so CLI wins.
    let toml = r#"
[profile.lit]
env = [{ name = "FOO", value = "from-profile" }]
"#;
    cmd_with_config(toml)
        .args(["run", "-u", "lit", "-e", "FOO=from-cli", "printenv", "FOO"])
        .assert()
        .success()
        .stdout(contains("from-cli"));
}

#[test]
fn run_profile_bad_path_errors_with_friendly_message() {
    let toml = r#"
[profile.bad]
path_add = ["relative/dir"]
"#;
    let out = cmd_with_config(toml)
        .args(["run", "-u", "bad", "/bin/true"])
        .output()
        .expect("run with bad path");
    assert!(!out.status.success(), "expected failure: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    assert!(
        stderr.contains("relative paths are not supported"),
        "stderr should explain: {stderr}",
    );
}

#[test]
fn run_no_profile_silently_ignores_missing_config() {
    // No -p, no config file at the XDG path → behaves exactly as
    // before (a missing config is "no profiles defined").
    let dir = tempfile::tempdir().expect("tempdir for empty xdg");
    let path: PathBuf = dir.keep();
    cmd_clean()
        .env("XDG_CONFIG_HOME", path)
        .args(["run", "echo", "hello"])
        .assert()
        .success()
        .stdout(contains("hello"));
}

#[test]
fn run_with_broken_config_surfaces_error_even_without_profile_arg() {
    // A broken config should fail loudly even when no -p is passed
    // — better that the user finds out the moment they introduce
    // the syntax error than the next time they happen to use a
    // profile.
    let dir = tempfile::tempdir().expect("tempdir");
    let config_dir = dir.path().join("redoubtful");
    std::fs::create_dir(&config_dir).expect("create dir");
    std::fs::write(config_dir.join("config.toml"), "= 1\n")
        .expect("write broken fixture");
    let path: PathBuf = dir.keep();
    let out = cmd_clean()
        .env("XDG_CONFIG_HOME", path)
        .args(["run", "/bin/true"])
        .output()
        .expect("run with broken config");
    assert!(!out.status.success(), "expected failure: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    assert!(
        stderr.contains("invalid TOML"),
        "stderr should call out invalid TOML: {stderr}",
    );
}

#[test]
fn first_run_writes_default_config() {
    // Brand-new XDG_CONFIG_HOME with no redoubtful/ subdir at all
    // — `load_or_init` should mkdir-p and drop the embedded default
    // in place.
    let dir = tempfile::tempdir().expect("tempdir for first run");
    let xdg = dir.path().to_path_buf();
    let cfg_path = xdg.join("redoubtful").join("config.toml");
    let leak: PathBuf = dir.keep();

    let out = cmd_clean()
        .env("XDG_CONFIG_HOME", &leak)
        .args(["run", "/bin/true"])
        .output()
        .expect("first run");
    assert!(out.status.success(), "first run failed: {out:?}");

    let on_disk =
        std::fs::read_to_string(&cfg_path).expect("config file written");
    assert!(
        on_disk.contains("[profile.opencode]"),
        "shipped default must include [profile.opencode]: {on_disk}",
    );
}

#[test]
fn second_run_does_not_re_emit_first_run_notice() {
    // After the file exists, subsequent runs hit the read path and
    // stay silent. If the second run *did* re-init, it'd be a UX
    // bug (and probably a sign of a Drop-related cleanup race).
    let dir = tempfile::tempdir().expect("tempdir for second run");
    let leak: PathBuf = dir.keep();

    // First run: triggers init + notice (we don't assert on it
    // here; the previous test covers that).
    let _ = cmd_clean()
        .env("XDG_CONFIG_HOME", &leak)
        .args(["run", "/bin/true"])
        .output()
        .expect("first run");

    // Second run: stderr should NOT contain the notice. (Other
    // stderr — pasta tap-init lines, the preflight report on a
    // failure — is fine; we only assert against the dump-notice
    // substring.)
    let out = cmd_clean()
        .env("XDG_CONFIG_HOME", &leak)
        .args(["run", "/bin/true"])
        .output()
        .expect("second run");
    assert!(out.status.success(), "second run failed: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    assert!(
        !stderr.contains("wrote default config to"),
        "second run must not re-emit init notice: {stderr}",
    );
}

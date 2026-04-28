//! Integration tests for the `redoubtful` CLI.
//!
//! The load-bearing assertions for the v0 sandbox are
//! [`run_hides_unexpected_paths_in_home`] (no $HOME leaks) and
//! [`run_keeps_cwd_visible`] (project dir actually usable inside).
//! Everything else exercises plumbing.
//!
//! `run_hides_unexpected_paths_in_home` consumes the binary's own
//! `show --json` output as the source of truth for what the sandbox
//! is supposed to expose. We list `$HOME` *inside* the sandbox, then
//! assert that every entry visible there corresponds to a mount the
//! binary said it intended to expose.
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
use std::time::Duration;

use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;

/// Our CLI command. Sandbox runs typically complete in well under
/// a second on a developer laptop; the 30s timeout is a CI-hang
/// circuit-breaker, not a steady-state expectation.
fn cmd() -> Command {
    let mut c = Command::cargo_bin("redoubtful").expect("binary exists");
    c.timeout(Duration::from_secs(30));
    c
}

/// `cmd()` with the test process's environment scrubbed. Used by env
/// tests so they don't accidentally inherit (and then assert against)
/// whatever the developer happens to have set in their shell —
/// notably real `*_API_KEY` values, which would defeat the leak
/// tests.
///
/// We re-set just the two host vars `redoubtful` itself needs:
/// `HOME` (consumed by `home_dir()` during sandbox setup) and `PATH`
/// (so the test process's `redoubtful` invocation can find `pasta`
/// and `bwrap`). Everything else stays empty until tests opt in via
/// `.env(...)`.
fn cmd_clean() -> Command {
    let mut c = cmd();
    c.env_clear();
    let home = std::env::var_os("HOME").expect("test process needs HOME");
    let path = std::env::var_os("PATH").expect("test process needs PATH");
    c.env("HOME", home);
    c.env("PATH", path);
    c
}

/// Sentinel string the host-side TCP stub writes to any client.
/// Picked to be obviously unique so a `contains` check is reliable.
const SENTINEL: &str = "redoubtful-sandbox-leak-sentinel-v1";

/// Spawn a single-shot TCP listener on `127.0.0.1:0` that accepts
/// one connection, writes [`SENTINEL`], and closes. Returns the
/// allocated port.
///
/// The runtime is kept alive on a dedicated background OS thread
/// (rather than `tokio::main` on the test, which would block the
/// `assert_cmd` invocation that needs to run on the same thread).
fn spawn_sentinel_listener() -> u16 {
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind 127.0.0.1:0");
            let port = listener.local_addr().expect("local_addr").port();
            port_tx.send(port).expect("send port");
            // Accept one client, write the sentinel, hang up.
            // Multiple clients per test would force ordering; one is
            // enough for both the positive control and the in-sandbox
            // probe (each test spawns its own listener).
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(SENTINEL.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
    });
    port_rx.recv().expect("listener never reported a port")
}

/// Read up to a few KB from a port (host-side) so the positive
/// control can assert the sentinel actually arrives end-to-end
/// before we trust the negative case.
fn read_sentinel_from_host(port: u16) -> String {
    use std::io::Read as _;
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .expect("host control connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read sentinel");
    buf
}

/// Minimal struct mirroring `mounts::Mount` for deserialization.
/// Defined here (not imported) because integration tests don't share
/// crate-internal types — and the test should fail loudly if the
/// per-mount JSON shape changes unexpectedly.
#[derive(serde::Deserialize)]
struct MountJson {
    sandbox: PathBuf,
    // Other fields ignored — we only need `sandbox` for the
    // unexpected-paths assertion below.
}

/// Top-level shape of `redoubtful show --json`. Fields are split out
/// per inventory so each test can grab just what it needs.
#[derive(serde::Deserialize)]
struct ShowJson {
    mounts: Vec<MountJson>,
    forwards: Vec<ForwardJson>,
    env: Vec<EnvJson>,
}

/// Minimal struct mirroring `forward::Forward` for deserialization.
#[derive(serde::Deserialize)]
struct ForwardJson {
    host_port: u16,
    sandbox_port: u16,
}

/// Minimal struct mirroring `env::EnvEntry` for deserialization. Each
/// entry is a fully-resolved `name=value` pair; `show --json`
/// describes exactly the env the sandbox would see at that instant
/// (passthroughs are already materialized, unset ones are absent).
#[derive(serde::Deserialize)]
struct EnvJson {
    name: String,
    value: String,
    source: String,
}

/// `cmd()` with a synthesized empty `$PATH` so bwrap and pasta
/// cannot be located. Used by preflight tests that want to assert
/// the failure-path report.
fn cmd_empty_path() -> Command {
    let dir = tempfile::tempdir().expect("tempdir for empty PATH");
    // Leak the tempdir so its path stays valid for the entire test —
    // the directory just needs to exist while assert_cmd runs the
    // child. Cleanup is best-effort via the OS-tempdir reaper.
    let path: PathBuf = dir.keep();
    let mut c = cmd();
    // NO_COLOR makes the report assertions stable regardless of
    // whether the test runner is attached to a TTY.
    c.env("PATH", path).env("NO_COLOR", "1");
    c
}

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

// ===== Network isolation =====

/// Without `-f`, the sandbox cannot reach a host loopback service.
/// This is the load-bearing assertion that pasta is doing its job.
///
/// Two-stage to guard against silent test breakage:
///
/// 1. **Positive control**: connect from the host first and assert
///    the sentinel arrives. If this fails, our listener is broken
///    and the negative case below would pass vacuously.
/// 2. **Negative case**: connect from inside the sandbox, assert
///    the sentinel does *not* appear and the inner command actually
///    ran (via the "---done---" marker). Without the "done" check,
///    a sandbox that fails to launch (e.g. `bash` not found) would
///    also produce empty stdout and look like a pass.
#[test]
fn host_loopback_is_unreachable_from_sandbox() {
    // Each sandbox probe needs its own one-shot listener.
    let probe_port = spawn_sentinel_listener();
    let received = read_sentinel_from_host(probe_port);
    assert!(
        received.contains(SENTINEL),
        "positive control failed: host couldn't read sentinel from \
         127.0.0.1:{probe_port}; got {received:?}",
    );

    let attack_port = spawn_sentinel_listener();
    let script = format!(
        "exec 3<>/dev/tcp/127.0.0.1/{attack_port} && cat <&3; echo '---done---'"
    );
    let out = cmd()
        .args(["run", "bash", "-c", &script])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("---done---"),
        "inner bash didn't run to completion; \
         pasta or bwrap setup may be broken.\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        !combined.contains(SENTINEL),
        "sentinel leaked into the sandbox — netns isolation is broken!\n\
         stdout: {stdout}\nstderr: {stderr}",
    );
}

/// With `-f $port`, a host loopback service *is* reachable inside
/// the sandbox. Mirrors the structure of the unreachable test above.
#[test]
fn forward_makes_host_port_reachable_from_sandbox() {
    let port = spawn_sentinel_listener();
    let received = read_sentinel_from_host(port);
    assert!(
        received.contains(SENTINEL),
        "positive control failed: host couldn't read sentinel from \
         127.0.0.1:{port}; got {received:?}",
    );

    let probe_port = spawn_sentinel_listener();
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{probe_port} && cat <&3");
    let out = cmd()
        .args(["run", "-f", &probe_port.to_string(), "bash", "-c", &script])
        .output()
        .expect("run with forward");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains(SENTINEL),
        "forwarded port did not deliver sentinel into sandbox.\n\
         stdout: {stdout}\nstderr: {stderr}",
    );
}

// ===== CLI mounts =====

#[test]
fn mount_exposes_host_path_readonly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host_file = dir.path().join("marker");
    std::fs::write(&host_file, b"hello from -m").expect("write marker");

    let spec = format!(
        "{}:{}",
        host_file.to_str().expect("utf-8 host"),
        "/work/marker",
    );

    // Read works.
    cmd()
        .args(["run", "-m", &spec, "cat", "/work/marker"])
        .assert()
        .success()
        .stdout(contains("hello from -m"));

    // Write fails (read-only mount). bwrap surfaces this as the
    // shell-level redirection error, not as a clean errno string,
    // so we just assert the run is not a success.
    let out = cmd()
        .args(["run", "-m", &spec, "bash", "-c", "echo evil > /work/marker"])
        .output()
        .expect("write attempt");
    assert!(
        !out.status.success(),
        "writing to a -m mount should fail; got {out:?}",
    );

    // And the host file is unchanged.
    let on_disk =
        std::fs::read_to_string(&host_file).expect("read marker after");
    assert_eq!(on_disk, "hello from -m");
}

#[test]
fn mount_rw_allows_writes_to_host_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host_file = dir.path().join("marker");
    std::fs::write(&host_file, b"original\n").expect("write marker");

    let spec = format!(
        "{}:{}:rw",
        host_file.to_str().expect("utf-8 host"),
        "/work/marker",
    );

    cmd()
        .args([
            "run",
            "-m",
            &spec,
            "bash",
            "-c",
            "echo from-sandbox > /work/marker",
        ])
        .assert()
        .success();

    let on_disk = std::fs::read_to_string(&host_file).expect("read marker");
    assert_eq!(on_disk.trim(), "from-sandbox");
}

#[test]
fn cwd_readonly_blocks_writes_with_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Run inside the tempdir so cwd == dir.path().
    let out = cmd()
        .current_dir(dir.path())
        .args(["run", "--readonly", "bash", "-c", "echo evil > ./marker"])
        .output()
        .expect("write attempt");
    assert!(
        !out.status.success(),
        "writing to cwd under --readonly should fail; got {out:?}",
    );
    assert!(
        !dir.path().join("marker").exists(),
        "no marker file should be created on the host under --readonly",
    );
}

#[test]
fn run_reports_missing_mount_host() {
    cmd()
        .args(["run", "-m", "/no/such/path/redoubtful-test", "true"])
        .assert()
        .failure()
        .stderr(contains("/no/such/path/redoubtful-test"));
}

// ===== `show` subcommand =====

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
        stdout.contains(r#""source": "cli""#),
        "expected a cli-source mount entry; got:\n{stdout}",
    );
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
        .args(["run", "-p", "/opt/agent/bin", "printenv", "PATH"])
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
fn run_path_add_repeatable_prepends_in_order() {
    // Multiple `-p` flags prepend in CLI order: `-p /a -p /b` →
    // `/a:/b:<canonical>`. Same convention as `fish_add_path /a /b`.
    cmd_clean()
        .args([
            "run", "-p", "/first/bin", "-p", "/second/bin", "printenv", "PATH",
        ])
        .assert()
        .success()
        .stdout(contains(
            "/first/bin:/second/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
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
            "-p",
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
    assert_eq!(path.source, "default");

    let home = by_name("HOME").expect("HOME entry present");
    assert_eq!(
        home.value,
        std::env::var("HOME").expect("test process needs HOME"),
    );
    assert_eq!(home.source, "default");

    let term = by_name("TERM").expect("TERM entry present (passthrough)");
    assert_eq!(term.value, "xterm-256color");
    assert_eq!(term.source, "default");
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

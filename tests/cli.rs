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
        "{}:{}",
        host_file.to_str().expect("utf-8 host"),
        "/work/marker",
    );

    cmd()
        .args([
            "run",
            "--mount-rw",
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
fn run_reports_missing_mount_host() {
    cmd()
        .args(["run", "-m", "/no/such/path/redoubtful-test", "true"])
        .assert()
        .failure()
        .stderr(contains("/no/such/path/redoubtful-test"));
}

// ===== Inventory subcommands =====

#[test]
fn mounts_jsonl_includes_cli_mounts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host_file = dir.path().join("marker");
    std::fs::write(&host_file, b"x").expect("write marker");
    let spec =
        format!("{}:{}", host_file.to_str().expect("utf-8"), "/work/marker",);

    let out = cmd()
        .args(["mounts", "--jsonl", "-m", &spec])
        .output()
        .expect("mounts");
    assert!(out.status.success(), "mounts --jsonl failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    assert!(
        stdout.contains(r#""source":"cli""#),
        "expected a cli-source mount line; got:\n{stdout}",
    );
    assert!(
        stdout.contains("/work/marker"),
        "expected the sandbox path /work/marker to appear; got:\n{stdout}",
    );
}

#[test]
fn forwards_jsonl_is_parseable() {
    let out = cmd()
        .args(["forwards", "--jsonl", "-f", "8080", "-f", "5432:9999"])
        .output()
        .expect("forwards");
    assert!(out.status.success(), "forwards --jsonl failed: {out:?}");
    let stdout = std::str::from_utf8(&out.stdout).expect("utf-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected 2 forward lines; got:\n{stdout}");
    for line in &lines {
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("bad jsonl line {line:?}: {e}"));
    }
    assert!(stdout.contains(r#""host_port":8080"#));
    assert!(stdout.contains(r#""sandbox_port":9999"#));
}

//! Sandbox networking tests.

use predicates::str::contains;

use crate::utils::{
    cmd, cmd_with_config,
    http::{
        UPSTREAM_SENTINEL, assert_https_upstream_reachable_on_host,
        assert_upstream_reachable_on_host, spawn_https_upstream,
        spawn_upstream,
    },
    tcp::{SENTINEL, read_sentinel_from_host, spawn_sentinel_listener},
};

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

/// The launcher's tunnel-only HTTPS proxy is up by default and the
/// sandbox sees `HTTPS_PROXY` pointing at it.
///
/// Stage 1 doesn't try to *use* the proxy from this test — that
/// would require an upstream host whose reachability we control,
/// which doesn't fit a hermetic suite. We only assert the wiring:
/// the env var is set, the form is `http://127.0.0.1:<u16>`, and
/// the port is non-zero. If those three things hold, sandboxed
/// HTTPS-proxy-aware clients (npm, curl, …) have everything they
/// need to start sending CONNECT to our listener.
#[test]
fn proxy_env_var_is_set_in_sandbox() {
    let out = cmd()
        .args(["run", "sh", "-c", "echo $HTTPS_PROXY"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let line = stdout.trim();
    let port_str =
        line.strip_prefix("http://127.0.0.1:").unwrap_or_else(|| {
            panic!(
                "HTTPS_PROXY not in expected form. \
             stdout: {stdout:?}\nstderr: {stderr:?}",
            )
        });
    let port: u16 = port_str
        .parse()
        .unwrap_or_else(|e| panic!("port {port_str:?} not a u16: {e}"));
    assert!(port > 0, "ephemeral port should be non-zero");
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

// ===== Proxy configuration (Stage 3: allow/deny routing) =====
//
// These tests verify that proxy CLI flags parse and accept values
// without error. The actual allow/deny routing is exercised by
// the unit tests in `sandbox::proxy` (which test `Proxies::should_allow`
// directly). Integration tests here only cover CLI wiring.

/// `--public-web=deny` is accepted by the CLI. Verifies the flag
/// parses and merges into the profile without crashing.
#[test]
fn proxy_public_web_deny_flag_is_accepted() {
    cmd()
        .args(["run", "--public-web=deny", "/bin/true"])
        .assert()
        .success();
}

/// `--proxy=HOST[:PORT][=ACTION]` is accepted by the CLI. Verifies
/// the compact proxy syntax parses without error.
#[test]
fn proxy_flag_accepts_compact_syntax() {
    // Full form: host:port=action
    cmd()
        .args(["run", "--proxy=example.net:80=deny", "/bin/true"])
        .assert()
        .success();
}

/// Invalid proxy syntax produces a clear error.
#[test]
fn proxy_flag_rejects_invalid_syntax() {
    let out = cmd()
        .args(["run", "--proxy=bad=host=action", "/bin/true"])
        .output()
        .expect("run");
    assert!(!out.status.success(), "expected failure: {out:?}");
    let stderr = std::str::from_utf8(&out.stderr).expect("utf-8");
    assert!(
        stderr.contains("invalid")
            || stderr.contains("multiple `=` separators"),
        "stderr should mention the syntax error: {stderr}",
    );
}

// ===== Proxy E2E: a real request through the handler =====
//
// These tests close the gap that let the Stage 3 allow/deny routing bug
// slip through. The `Proxies::should_allow` unit tests exercise the
// *predicate* in isolation, but that bug was in the *wiring*: the routing
// hook was wired into the wrong hudsucker callback, so every request —
// including explicitly-allowed hosts — came back 403. Nothing drove a
// real request through the handler to a controllable upstream, so the
// predicate tests passed no matter how the handler was wired.
//
// Each test here does exactly that: `redoubtful run` a `curl` to an
// upstream, which the sandboxed client sends to the proxy (because
// `HTTPS_PROXY`/`HTTP_PROXY` are set). The host-side proxy decides
// allow vs deny in `handle_request` and either forwards to the upstream
// or short-circuits with a 403. We assert which happened.
//
// There are four variants: plain HTTP (HTTP-forward) and HTTPS (CONNECT /
// raw-byte tunnel), each with an allow and a deny case. HTTPS exercises
// a path the HTTP-forward tests never touch — see
// `docs/SSL_DESIGN.md`.
//
// The upstream lives on `127.0.1.1`: inside the loopback block the
// host-side proxy can reach, but NOT in the client's `NO_PROXY`
// (`localhost,127.0.0.1`), so the sandboxed client is forced to send it
// through the proxy rather than bypassing it. No DNS, no LAN IP, no
// `/etc/hosts` — fully hermetic.

/// Default `public_web` is `allow`, so an unknown host (`127.0.1.1`) is
/// forwarded from the sandboxed client, through the proxy, to the
/// upstream. This is the test that would have caught the Stage 3 bug
/// (which 403'd every request regardless of allow/deny): under that bug,
/// the sandboxed `curl` would print the 403 deny body instead of the
/// sentinel, and this assertion would fail.
#[test]
fn http_through_proxy_reaches_upstream_when_allowed() {
    let (_server, target) = spawn_upstream();
    assert_upstream_reachable_on_host(&target);

    let out = cmd()
        .args(["run", "curl", "-s", "--max-time", "10", &target])
        .output()
        .expect("run curl through proxy");
    assert!(out.status.success(), "run failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains(UPSTREAM_SENTINEL),
        "sandboxed curl did not reach the upstream through the proxy; \
         expected the upstream sentinel in stdout.\nstdout: {stdout}\nstderr: {stderr}",
    );
}

// ===== Proxy E2E: credential injection (Stage 4) =====
//
// These tests verify that the proxy injects headers, query params, and
// auth credentials into requests sent to configured hosts. HTTP-forward
// injection (Phase 4.1) rewrites the request in `handle_request` before
// it reaches the upstream — no MITM, no CA trust needed.
//
/// Set `headers`, `params`, and `auth` on a proxy entry, then assert
/// the echo upstream reflects the injected values back.
///
/// This exercises the Phase 4.1 HTTP-forward injection path (no MITM,
/// no CA trust wiring — just rewriting in `handle_request`).
///
/// **Currently red**: injection is not yet implemented, so the echoed
/// response lacks the injected values and the assertions below fail.
/// Once `handle_request` rewrites headers / params / auth before
/// forwarding (Stage 4), the request reaches the upstream already
/// injected and the assertions pass.
#[test]
fn credential_injection_injects_headers_params_and_auth() {
    let (_server, target) = spawn_upstream();
    assert_upstream_reachable_on_host(&target);

    // Extract port from the target URL (http://127.0.1.1:PORT/).
    let port: u16 = url::Url::parse(&target)
        .expect("target is a URL")
        .port()
        .expect("target URL contains a port");

    // `[[profile.inject-test.proxies]]` (not bare `[[proxies]]`): the
    // proxy entries live *inside* the profile block, so the array-of
    // -tables must use the full dotted path — a bare `[[proxies]]` would
    // attach to the top level, which `ConfigFile` (profile-only) rejects.
    let toml = format!(
        r#"[profile.inject-test]
[[profile.inject-test.proxies]]
host = "127.0.1.1"
port = {port}
action = "allow"
headers = {{ "X-Test-Token" = "test-token-value" }}
params = {{ "api_key" = "injected-key" }}
auth = {{ token = "injected-bearer-token" }}
"#
    );

    let out = cmd_with_config(&toml)
        .args([
            "run",
            "-u",
            "inject-test",
            "curl",
            "-s",
            "--max-time",
            "10",
            &target,
        ])
        .output()
        .expect("run curl with injection config");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // The request should reach the upstream (default allow), and the
    // proxy should have injected the configured headers, params, and
    // auth. The echo upstream reflects them back, so we assert they
    // appear in the response.
    //
    // This is a red test until Stage 4 implements injection: with no
    // injection the echoed response lacks these values, so the
    // assertions below fail. Once `handle_request` rewrites headers /
    // params / auth before forwarding, they pass.
    assert!(
        stdout.contains(UPSTREAM_SENTINEL),
        "sandboxed curl did not reach the echo upstream; \
         expected the upstream sentinel.\nstdout: {stdout}\nstderr: {stderr}",
    );

    // URL query param injection.
    assert!(
        stdout.contains("QUERY: api_key=injected-key"),
        "expected the injected query param reflected back by the echo \
         upstream. This asserts that `params` injection is working.\n\
         stdout: {stdout}\nstderr: {stderr}",
    );

    // Bearer auth injection -> `Authorization` header.
    assert!(
        stdout.contains("AUTHORIZATION: Bearer injected-bearer-token"),
        "expected the injected bearer token reflected back by the echo \
         upstream. This asserts that `auth` (Bearer) injection is \
         working.\nstdout: {stdout}\nstderr: {stderr}",
    );

    // Custom header injection.
    assert!(
        stdout.contains("X-TEST-TOKEN: test-token-value"),
        "expected the injected custom header reflected back by the echo \
         upstream. This asserts that `headers` injection is working.\n\
         stdout: {stdout}\nstderr: {stderr}",
    );
}

/// `--public-web=deny` denies any host not explicitly allowed, so the
/// unknown `127.0.1.1` request is short-circuited by the proxy's 403
/// before it ever reaches the upstream. The host-side control proves the
/// upstream *is* reachable, so the 403 is a routing decision, not a
/// connection failure.
#[test]
fn http_through_proxy_is_403_when_denied() {
    let (_server, target) = spawn_upstream();
    assert_upstream_reachable_on_host(&target);

    let out = cmd()
        .args([
            "run",
            "--public-web=deny",
            "curl",
            "-s",
            "--max-time",
            "10",
            &target,
        ])
        .output()
        .expect("run curl with public-web denied");
    assert!(out.status.success(), "run failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains(UPSTREAM_SENTINEL),
        "denied request reached the upstream!\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        stdout.contains("denied by redoubtful proxy configuration"),
        "expected redoubtful's 403 deny body in stdout.\n\
         stdout: {stdout}\nstderr: {stderr}",
    );
}

/// HTTPS analog of
/// [`http_through_proxy_reaches_upstream_when_allowed`]: default
/// `public_web` is `allow`, so the unknown `127.0.1.1` request is tunneled
/// from the sandboxed client, through the proxy's CONNECT / raw-byte path,
/// to the TLS upstream. The host-side control verifies the upstream's
/// leaf against the CA1 test authority (no `-k`); the sandboxed client
/// still uses `-k` until it trusts the CA1+CA2 bundle (prerequisite 3).
#[test]
fn https_through_proxy_reaches_upstream_when_allowed() {
    let (_server, target) = spawn_https_upstream();
    assert_https_upstream_reachable_on_host(&target);

    // TODO: the `-k` goes away once the sandbox has proper certs (CA1 +
    // CA2 bundle) so curl can verify against a real CA-issued upstream.
    let out = cmd()
        .args(["run", "curl", "-sk", "--max-time", "10", &target])
        .output()
        .expect("run curl through proxy");
    assert!(out.status.success(), "run failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains(UPSTREAM_SENTINEL),
        "sandboxed curl did not reach the TLS upstream through the proxy; \
         expected the upstream sentinel in stdout.\nstdout: {stdout}\nstderr: {stderr}",
    );
}

/// HTTPS analog of [`http_through_proxy_is_403_when_denied`]:
/// `--public-web=deny` denies any unknown host, so the `127.0.1.1`
/// CONNECT is short-circuited by the proxy's 403 before it reaches the
/// TLS upstream.
///
/// Unlike the plain-HTTP case (where the 403 is the response to the
/// denied `GET`, so curl prints the body and exits 0), a denied
/// **CONNECT** surfaces to curl as a proxy tunnel failure: it treats a
/// non-2xx CONNECT as fatal, prints no body, and exits nonzero. So we
/// assert the run *fails*, the upstream sentinel never arrives, and (via
/// `curl -v`) stderr shows the proxy's 403 — proving it's our routing
/// decision rather than a dead listener (which the host-side control
/// already rules out).
///
/// TODO: the `-k` goes away once the sandbox has proper certs (CA1 +
/// CA2 bundle), at which point this denies before any TLS handshake so
/// it should still 403 regardless.
#[test]
fn https_through_proxy_is_403_when_denied() {
    let (_server, target) = spawn_https_upstream();
    assert_https_upstream_reachable_on_host(&target);

    let out = cmd()
        .args([
            "run",
            "--public-web=deny",
            "curl",
            "-skv",
            "--max-time",
            "10",
            &target,
        ])
        .output()
        .expect("run curl with public-web denied");
    assert!(!out.status.success(), "denied HTTPS should fail: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains(UPSTREAM_SENTINEL),
        "denied request reached the TLS upstream!\n\
         stdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        stderr.contains("403"),
        "expected the proxy's 403 on the denied CONNECT in stderr \
         (curl -v); got:\nstderr: {stderr}",
    );
}

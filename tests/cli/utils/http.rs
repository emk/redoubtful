//! HTTP test server infrastructure.

use std::{net::SocketAddr, path::PathBuf, sync::OnceLock};

use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};

// All upstreams are axum servers (with an optional rustls acceptor) on
// their own background tokio runtime. Mocking HTTP and HTTPS with one
// framework is deliberate: the same [`echo_handler`] serves every
// request, returning the sentinel followed by the reflected query /
// `Authorization` / `X-Test-Token` when present — so plain reachability
// tests and MITM credential-injection tests share one upstream.

/// Body the upstream echo serves for any request.
pub const UPSTREAM_SENTINEL: &str = "redoubtful-proxy-e2e-sentinel-v1";

/// Handle to a [`spawn_axum_upstream`] test upstream.
///
/// Owns the background thread (and its tokio runtime) running the axum
/// server. Dropping it signals shutdown and joins the thread, aborting
/// the server task and closing its listener — the usual "kept alive
/// until the returned value is dropped" contract for a test upstream.
pub struct Upstream {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        // Signal the background thread to stop; it finishes the select
        // and drops its runtime (aborting the listener). Best-effort: if
        // the thread already exited, the send is a no-op.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Drive a server's `serve` future until `shutdown` fires, then return
/// (letting the caller's runtime drop abort the listener).
///
/// Shared between the HTTP and TLS upstreams so their teardown stays
/// identical.
fn run_until_shutdown(
    rt: &tokio::runtime::Runtime,
    serve: impl std::future::Future<Output = std::io::Result<()>>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    rt.block_on(async {
        tokio::select! {
            r = serve => {
                r.expect("test upstream serve failed");
            }
            _ = shutdown => {}
        }
    });
}

/// The CA1 test authority — the hermetic "outside" CA that signs the
/// test HTTPS upstream's leaf (see `docs/SSL_DESIGN.md`).
///
/// One is shared across the whole test process, generated on the fly
/// (never committed to the tree, so no secret scanner is upset). It is
/// the trust anchor the host-side controls verify the TLS upstream
/// against, and is the CA1 the sandbox bundle will start from once MITM
/// lands (prerequisite 4).
struct Ca1 {
    /// Issuer that signs the test upstream's leaf certs.
    issuer: Issuer<'static, KeyPair>,
    /// Path to the PEM-encoded CA1 certificate, so host-side `curl
    /// --cacert` (and future `SSL_CERT_FILE` wiring) has a stable file.
    cert_path: PathBuf,
}

/// Build or fetch the process-wide CA1 test authority.
///
/// `get_or_init` runs once per test process, lazily on the first TLS
/// upstream or host control. The tempdir is leaked so the cert file
/// stays valid for the process lifetime (same pattern as
/// `shared_xdg_config_home`).
fn ca1() -> &'static Ca1 {
    static CA1: OnceLock<Ca1> = OnceLock::new();
    CA1.get_or_init(|| {
        let key_pair = KeyPair::generate().expect("generates CA1 keypair");

        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "redoubtful test CA1");
        params.distinguished_name = dn;

        let ca_cert_pem = params
            .self_signed(&key_pair)
            .expect("CA1 self-signed cert")
            .pem();

        // Persist the CA cert PEM so host-side controls have a stable
        // path to hand `curl --cacert`.
        let dir = tempfile::tempdir().expect("tempdir for CA1 cert");
        let dir_path = dir.keep();
        let cert_path = dir_path.join("ca1.pem");
        std::fs::write(&cert_path, ca_cert_pem).expect("write CA1 cert");

        let issuer = Issuer::new(params, key_pair);
        Ca1 { issuer, cert_path }
    })
}

/// Path to the PEM-encoded CA1 test certificate.
///
/// The SSL-foundation E2E tests set `SSL_CERT_FILE` on the `redoubtful`
/// child to this path, so `find_system_ca_bundle` reads CA1 as the
/// "system" bundle and the merged sandbox bundle contains CA1 (which is
/// what lets sandboxed curl verify the CA1-issued test upstream without
/// `-k`).
pub fn ca1_cert_path() -> &'static std::path::Path {
    ca1().cert_path.as_path()
}

/// Sign a fresh leaf cert (with its key) for the `127.0.1.1` upstream
/// using the shared CA1 test authority.
fn sign_tls_leaf() -> (Vec<u8>, Vec<u8>) {
    let leaf_key =
        KeyPair::generate().expect("generates upstream leaf keypair");
    let params = CertificateParams::new(vec!["127.0.1.1".to_string()])
        .expect("leaf SANs for the 127.0.1.1 target");
    let leaf = params
        .signed_by(&leaf_key, &ca1().issuer)
        .expect("CA1 signs the upstream leaf");
    (
        leaf.pem().into_bytes(),
        leaf_key.serialize_pem().into_bytes(),
    )
}

/// Echo handler for the downstream side: reflects back what the request
/// carried, so credential-injection E2E tests can assert what the proxy
/// added.
///
/// The response always starts with [`UPSTREAM_SENTINEL`] so existing
/// sentinel-checking helpers ([`assert_upstream_reachable_on_host`] and
/// the `contains(UPSTREAM_SENTINEL)` assertions) keep working. Then, for
/// each of the three cred shapes we test, it appends a `FIELD: value`
/// line only when that field is present:
///
/// - `QUERY: ...` — the request's query string.
/// - `AUTHORIZATION: ...` — the `Authorization` header (auth injection).
/// - `X-TEST-TOKEN: ...` — the `X-Test-Token` header (custom headers).
///
/// A request with none of these gets the sentinel alone, byte-for-byte
/// the old response — so unifying the sentinel and echo servers is free.
/// Uses `axum::http` re-exports (not the `http` crate directly) so we
/// don't need `http` as a test-binary dependency.
async fn echo_handler(
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> String {
    let mut body = String::from(UPSTREAM_SENTINEL);
    body.push('\n');

    if let Some(query) = uri.query() {
        body.push_str("QUERY: ");
        body.push_str(query);
        body.push('\n');
    }

    if let Some(v) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        body.push_str("AUTHORIZATION: ");
        body.push_str(v);
        body.push('\n');
    }

    if let Some(v) = headers.get("x-test-token").and_then(|h| h.to_str().ok()) {
        body.push_str("X-TEST-TOKEN: ");
        body.push_str(v);
        body.push('\n');
    }

    body
}

/// Spawn an axum test upstream on `127.0.1.1:0` that answers every
/// request with the echo handler — [`UPSTREAM_SENTINEL`] first, then the
/// query / `Authorization` / `X-Test-Token` reflected back when present
/// (see [`echo_handler`]) — and a `200 OK`, either plain HTTP
/// (`use_tls = false`) or TLS (`use_tls = true`).
///
/// Returns the server handle plus the target URL. The handle is kept
/// alive for as long as the returned value is in scope; on drop the
/// background runtime shuts down and the listener closes.
///
/// We use axum-server as our "simple existing HTTPS server framework"
/// (see `docs/SSL_DESIGN.md`) so HTTP and HTTPS mocking share one
/// harness; the rustls acceptor is the whole difference.
fn spawn_axum_upstream(use_tls: bool) -> (Upstream, String) {
    use axum::{Router, routing::get};

    // rustls can't auto-pick a crypto provider here: `aws-lc-rs` is
    // enabled transitively (via hudsucker's hyper-rustls) alongside our
    // pure-Rust `ring`, so the two feature flags are ambiguous. Pin the
    // project's preferred pure-Rust `ring` backend explicitly; ignore the
    // "already installed" error from a parallel test.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // TLS upstreams serve a fresh leaf signed by the shared CA1 test
    // authority (see [`ca1`]); the IP SAN keeps it semantically right for
    // the 127.0.1.1 target. The sandboxed client still uses `curl -k`
    // until it trusts the CA1+CA2 bundle (prerequisite 3), while the
    // host-side control verifies the leaf against CA1 with `--cacert`.
    let cert = if use_tls { Some(sign_tls_leaf()) } else { None };

    // Bind inside the background runtime thread (NOT with a
    // `std::net::TcpListener` handed across threads — tokio rejects
    // registering a blocking socket cross-thread, issue #7172), and send
    // the chosen ephemeral port back so we can build the target URL.
    let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();

    // Answer every request with the echo handler (sentinel + reflected
    // credentials when present).
    let app = Router::new().route("/", get(echo_handler));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let thread = std::thread::spawn(move || {
        // Each test server runs on its own background tokio runtime.
        let rt = tokio::runtime::Runtime::new()
            .expect("tokio runtime for test upstream");

        // Bind on the runtime so the socket is runtime-owned; report the
        // port to the caller before serving.
        let listener = rt
            .block_on(tokio::net::TcpListener::bind(SocketAddr::from((
                [127u8, 0, 1, 1],
                0,
            ))))
            .expect("upstream binds on 127.0.1.1");
        let _ = port_tx.send(
            listener
                .local_addr()
                .expect("bound upstream has an address")
                .port(),
        );

        match cert {
            Some((cert_pem, key_pem)) => {
                // `from_pem` is async (it parses the key/cert on the
                // blocking pool), so build the rustls config inside the
                // runtime.
                let config = rt
                    .block_on(axum_server::tls_rustls::RustlsConfig::from_pem(
                        cert_pem, key_pem,
                    ))
                    .expect("rustls config from test cert");
                let server =
                    axum_server::Server::<std::net::SocketAddr>::from_listener(
                        listener,
                    )
                    .acceptor(
                        axum_server::tls_rustls::RustlsAcceptor::new(config),
                    );
                run_until_shutdown(
                    &rt,
                    server.serve(app.into_make_service()),
                    shutdown_rx,
                );
            }
            None => {
                let server =
                    axum_server::Server::<std::net::SocketAddr>::from_listener(
                        listener,
                    );
                run_until_shutdown(
                    &rt,
                    server.serve(app.into_make_service()),
                    shutdown_rx,
                );
            }
        }
    });

    // Wait for the background thread to report its bound port.
    let port = port_rx.recv().expect("upstream reported its port");
    let scheme = if use_tls { "https" } else { "http" };
    let target = format!("{scheme}://127.0.1.1:{port}/");

    (
        Upstream {
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        },
        target,
    )
}

/// Spawn a plain-HTTP upstream on `127.0.1.1:0` answering any request
/// with [`UPSTREAM_SENTINEL`] and a `200 OK`.
pub fn spawn_upstream() -> (Upstream, String) {
    spawn_axum_upstream(false)
}

/// Spawn a TLS upstream on `127.0.1.1:0` answering any request with
/// [`UPSTREAM_SENTINEL`] and a `200 OK`.
///
/// Unlike plain HTTP, an HTTPS request goes through the **CONNECT /
/// raw-byte tunnel**: the sandboxed client sends the proxy a
/// `CONNECT 127.0.1.1:<port>` and the proxy pipes raw bytes to this TLS
/// server (no MITM, no CA wiring — see `docs/SSL_DESIGN.md`). The cert
/// is a fresh leaf signed by the shared CA1 test authority (see [`ca1`]);
/// the sandboxed client still uses `curl -k` until it trusts the CA1+CA2
/// bundle (prerequisite 3), while the host-side control verifies the
/// leaf against CA1 via [`assert_https_upstream_reachable_on_host`].
pub fn spawn_https_upstream() -> (Upstream, String) {
    spawn_axum_upstream(true)
}

/// Host-side positive control: fetch `target` directly (bypassing any
/// host-level proxy) and assert the upstream sentinel arrives.
///
/// Guards the sandbox assertions below against a silently-broken upstream
/// being misread as a routing pass or fail — the same two-stage pattern
/// as the loopback-reachability tests.
///
/// For the plain-HTTP upstream ([`spawn_upstream`]); `-k` is a harmless
/// no-op here (no TLS). The TLS upstream ([`spawn_https_upstream`]) is
/// verified against CA1 by [`assert_https_upstream_reachable_on_host`]
/// instead.
pub fn assert_upstream_reachable_on_host(target: &str) {
    let out = std::process::Command::new("curl")
        .args(["-s", "-k", "--max-time", "10", "--noproxy", "*", target])
        .output()
        .expect("host control curl failed to run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(UPSTREAM_SENTINEL),
        "positive control failed: host curl to {target} did not return the \
         upstream sentinel; got {stdout:?}\n\
         stderr: {:?}",
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Host-side positive control for the TLS upstream: fetch `target`
/// directly (bypassing any host-level proxy) and assert the sentinel
/// arrives, **verifying the upstream's leaf against the CA1 test
/// authority** (no `-k`).
///
/// This is the positive control for the TLS upstream: it asserts the
/// upstream really serves a CA1-issued leaf and that the CA1 certificate
/// is a valid trust anchor. The host curl verifies against CA1 with
/// `--cacert` because the host itself doesn't trust the test CA1 (only
/// the sandbox does, via the merged CA bundle).
pub fn assert_https_upstream_reachable_on_host(target: &str) {
    let ca1_path = ca1().cert_path.to_str().expect("CA1 cert path is UTF-8");
    let out = std::process::Command::new("curl")
        .args([
            "-s",
            "--cacert",
            ca1_path,
            "--max-time",
            "10",
            "--noproxy",
            "*",
            target,
        ])
        .output()
        .expect("host control curl failed to run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(UPSTREAM_SENTINEL),
        "positive control failed: host curl to {target} did not return the \
         upstream sentinel; got {stdout:?}\n\
         stderr: {:?}",
        String::from_utf8_lossy(&out.stderr),
    );
}

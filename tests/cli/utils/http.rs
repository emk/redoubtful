//! HTTP test server infrastructure.

use std::net::SocketAddr;

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

    // TLS upstreams need a throwaway self-signed leaf. `curl -k` skips
    // verification, so nothing has to trust it; the IP SAN keeps it
    // semantically right for the 127.0.1.1 target.
    let cert = if use_tls {
        let c =
            rcgen::generate_simple_self_signed(vec!["127.0.1.1".to_string()])
                .expect("rcgen creates a self-signed test cert");
        Some((
            c.cert.pem().into_bytes(),
            c.signing_key.serialize_pem().into_bytes(),
        ))
    } else {
        None
    };

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
/// is a throwaway rcgen self-signed leaf, so both the sandboxed client
/// and the host-side control use `curl -k`.
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
/// Uses `-k` so the same helper works for both the plain-HTTP upstream
/// ([`spawn_upstream`], where it is a harmless no-op) and the TLS
/// upstream ([`spawn_https_upstream`], whose throwaway self-signed
/// cert must not be verified).
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

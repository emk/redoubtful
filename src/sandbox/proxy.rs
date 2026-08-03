//! A proxy server with allow/deny configuration on host loopback.
//!
//! The sandbox cannot resolve DNS or reach external network on its
//! own (`docs/ARCHITECTURE.md`, "No DNS resolution to arbitrary
//! hosts"); proxying through the host is the only path out. This
//! module owns the host-side proxy: it binds an ephemeral port on
//! `127.0.0.1`, accepts the `CONNECT host:port` requests sandboxed
//! clients send when they see `HTTPS_PROXY`, resolves the upstream
//! host *on the host*, and pipes raw bytes between the client and
//! that upstream. TLS terminates end-to-end between the client and
//! the real server — the proxy never sees plaintext.
//!
//! **Allow/deny routing.** hudsucker calls
//! [`PassthroughHandler::handle_request`] as the gateway for *every*
//! request (HTTP and CONNECT alike, before any upstream is touched), so
//! that is where routing lives. It consults the [`Proxies`] config:
//!
//! - Allowed hosts: the request is returned unchanged → plain HTTP is
//!   forwarded upstream; CONNECT streams are tunneled raw (no MITM).
//! - Denied hosts: an HTTP 403 `Response` is returned, short-circuiting
//!   the request before it reaches any upstream.
//!
//! Credential injection (headers, params, auth) is deferred to
//! Stage 4 — allowed hosts always tunnel in this stage.
//!
//! **Certificate authority.** Hudsucker's builder requires `with_ca`
//! to leave the `WantsCa` state. We generate a fresh per-session CA
//! with `rcgen`, pass the [`Issuer`] to hudsucker for leaf cert
//! signing, and persist the CA's self-signed certificate to a
//! [`NamedTempFile`] owned by [`ProxyHandle`]. The launcher reads the
//! path via [`ProxyHandle::ca_cert_path`] to bind-mount the cert into
//! the sandbox, and sets CA-bundle env vars so sandboxed tools trust
//! it.
//!
//! **Upstream TLS trust.** The proxy's outbound HTTPS connector — the
//! one it will use when MITM-forwarding to a real upstream (Phase 4.2)
//! — trusts the *system* CA bundle discovered by `openssl-probe`
//! (honoring `SSL_CERT_FILE` / `SSL_CERT_DIR`), the same roots the
//! sandbox sees, rather than hudsucker's compiled-in Mozilla roots.
//! See [`build_upstream_connector`] and `docs/SSL_DESIGN.md`.

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
};

use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy,
    certificate_authority::RcgenAuthority,
    hyper::{Method, Request, Response, StatusCode},
};
use hyper_util::client::legacy::connect::HttpConnector;
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};
use rustls::crypto::CryptoProvider;
use tempfile::NamedTempFile;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

use crate::{
    config::{
        env_vars::EnvVars, forwards::Forwards, mounts::Mounts,
        profile::Profile, proxies::Proxies,
    },
    hostname::Hostname,
    prelude::*,
};

/// Handle to the running proxy task.
///
/// Held by `cmd_run` for the lifetime of the sandbox; on shutdown
/// the caller invokes [`Self::shutdown`] to signal the proxy to
/// stop accepting and to drain in-flight tunnels.
///
/// Owns the per-session CA certificate as a [`NamedTempFile`] so it
/// is cleaned up when the handle is dropped.
pub struct ProxyHandle {
    /// Host-loopback port the proxy is listening on. Pasta forwards
    /// this into the sandbox's netns; bwrap sets `HTTPS_PROXY` to
    /// `http://127.0.0.1:<port>`.
    pub port: u16,
    /// Per-session CA certificate. Lives on disk so the launcher can
    /// bind-mount it into the sandbox. Auto-deleted on drop.
    ca_cert: NamedTempFile,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ProxyHandle {
    /// Path to the CA certificate PEM file.
    ///
    /// The launcher bind-mounts this into the sandbox (e.g.
    /// `/etc/ssl/certs/sandbox-ca.pem`) and sets CA-bundle env vars
    /// (`SSL_CERT_FILE`, `GIT_SSL_CAINFO`, etc.) so sandboxed tools
    /// trust it.
    #[expect(dead_code, reason = "consumed by launcher once MITM is wired")]
    pub fn ca_cert_path(&self) -> &Path {
        self.ca_cert.path()
    }

    /// Signal the proxy to stop and wait for its task to finish.
    ///
    /// Best-effort: if the task already exited (e.g. the listener
    /// hit a fatal error and logged itself to death), the await is a
    /// no-op. Errors awaiting the task are swallowed — sandbox
    /// teardown shouldn't fail the user's command on something this
    /// peripheral.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            // Receiver lives inside the proxy task; if it's already
            // dropped the proxy must have exited, which is fine.
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

/// Bind a host-loopback port, spawn the proxy on it,
/// and return a handle the launcher can use to query the port and
/// shut the proxy down on exit.
///
/// Listens on `127.0.0.1:0` so the kernel picks an unused ephemeral
/// port. Pasta's `-T` flag forwards that port into the sandbox's
/// netns (see `crate::pasta`), so a sandboxed client doing
/// `connect("127.0.0.1", port)` lands on this listener.
#[instrument(level = "debug", skip_all)]
pub async fn start_proxy(proxies: &Proxies) -> Result<ProxyHandle> {
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| Error::other("could not bind proxy listener", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::other("could not read proxy local_addr", e))?
        .port();
    debug!(port, "proxy listener bound");

    // Clone and wrap in Arc so the handler can share the config
    // across connections without contention.
    let proxies = Arc::new(proxies.clone());

    // Log what routing config actually reached the proxy: `public_web`
    // and `(host, port, action)` per entry. Deliberately no headers,
    // params, or auth (those may hold secrets).
    let (public_web, entries) = proxies.routing_summary();
    debug!(?public_web, entries = ?entries, "proxy routing config");

    // Per-session CA: issuer goes to hudsucker for leaf cert signing,
    // PEM cert goes to a temp file so the launcher can bind-mount it
    // into the sandbox.
    let (issuer, ca_cert_pem) = build_throwaway_ca()?;
    let ca_cert = NamedTempFile::new()
        .map_err(|e| Error::other("could not create CA cert temp file", e))?;
    std::fs::write(ca_cert.path(), &ca_cert_pem)
        .map_err(|e| Error::other("could not write CA cert to temp file", e))?;
    debug!(ca_cert = ?ca_cert.path(), "CA cert persisted");

    // Pure-Rust crypto for hudsucker's TLS layers. In tunnel-only
    // mode the provider isn't actually exercised on the proxy's
    // hot path (no MITM = no leaf cert signing, no inbound TLS
    // accept), but the builder needs one to wire up its outbound
    // hyper-rustls client.
    let provider = rustls::crypto::ring::default_provider();
    let ca = RcgenAuthority::new(issuer, 1024, provider.clone());

    // Upstream-client trust: the same roots the sandbox sees (system
    // bundle via openssl-probe), not hudsucker's compiled-in Mozilla
    // roots. See `build_upstream_connector` and `docs/SSL_DESIGN.md`.
    let upstream_connector = build_upstream_connector(&provider)?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_http_connector(upstream_connector)
        .with_http_handler(PassthroughHandler {
            proxies: proxies.clone(),
        })
        .with_graceful_shutdown(async move {
            // A `Sender::send` we never receive (because the launcher
            // exited without calling `shutdown`) cancels via the
            // dropped-sender path; either way the future resolves
            // and hudsucker stops.
            let _ = shutdown_rx.await;
        })
        .build()
        .map_err(|e| {
            Error::other(
                "could not build proxy",
                std::io::Error::other(e.to_string()),
            )
        })?;

    let task = tokio::spawn(async move {
        if let Err(err) = proxy.start().await {
            warn!(error = %err, "proxy task exited with error");
        }
    });

    Ok(ProxyHandle {
        port,
        ca_cert,
        shutdown_tx: Some(shutdown_tx),
        task,
    })
}

/// Generate the per-session CA for the proxy.
///
/// Returns the [`Issuer`] (for hudsucker's leaf cert signing) and
/// the PEM-encoded self-signed CA certificate (for the launcher to
/// bind-mount into the sandbox).
///
/// `is_ca = Unconstrained` so the cert is a valid CA for signing
/// leaf certificates. The CA cert is written to a [`NamedTempFile`
/// (`tempfile::NamedTempFile`)] in [`start_proxy`] and auto-cleaned
/// when [`ProxyHandle`] is dropped.
fn build_throwaway_ca() -> Result<(Issuer<'static, KeyPair>, String)> {
    let key_pair = KeyPair::generate().map_err(|e| {
        Error::other(
            "could not generate proxy CA keypair",
            std::io::Error::other(e.to_string()),
        )
    })?;

    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "redoubtful sandbox proxy CA");
    params.distinguished_name = dn;

    // Generate the self-signed CA cert before consuming `params`
    // into the `Issuer`. `Issuer::new` takes ownership of params
    // and extracts only the DN and key usages — it doesn't store
    // the certificate.
    let ca_cert_pem = params
        .self_signed(&key_pair)
        .map_err(|e| {
            Error::other(
                "could not generate proxy CA self-signed cert",
                std::io::Error::other(e.to_string()),
            )
        })?
        .pem();

    // Rebuild params for the Issuer. We only set is_ca, dn, and
    // the rest are defaults, so this is cheap and explicit.
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "redoubtful sandbox proxy CA");
    params.distinguished_name = dn;
    let issuer = Issuer::new(params, key_pair);

    Ok((issuer, ca_cert_pem))
}

/// Build the proxy's outbound HTTPS connector.
///
/// This is the *single source of CA truth* for the upstream-client leg
/// (see `docs/SSL_DESIGN.md`). It trusts the system CA bundle discovered
/// by `openssl-probe` via [`rustls_native_certs::load_native_certs`]
/// (honoring the user's `SSL_CERT_FILE` / `SSL_CERT_DIR`), instead of
/// hudsucker's default compiled-in Mozilla roots. If no bundle is found
/// at all we fail loudly, rather than silently trusting only our own CA.
///
/// `https_or_http()` is required so plain-HTTP forwarding keeps working:
/// hudsucker builds its single upstream `Client` from this connector,
/// and HTTP-forward requests (the current Phase 4.1 path) use `http://`
/// URIs through it — not just the future HTTPS MITM path.
fn build_upstream_connector(
    provider: &CryptoProvider,
) -> Result<hyper_rustls::HttpsConnector<HttpConnector>> {
    // Discover the system CA bundle. `rustls-native-certs` on Linux
    // reads `openssl_probe::probe()`, which honors `SSL_CERT_FILE` /
    // `SSL_CERT_DIR`.
    let native = rustls_native_certs::load_native_certs();
    for err in &native.errors {
        warn!(error = %err, "skipping a malformed system CA certificate");
    }
    let roots = roots_from_certs(native.certs)?;

    let client_config =
        rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::other("could not configure proxy TLS", e))?
            .with_root_certificates(roots)
            .with_no_client_auth();

    Ok(hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(client_config)
        .https_or_http()
        .enable_http1()
        .build())
}

/// Build a [`rustls::RootCertStore`] from a set of system CA
/// certificates.
///
/// Fails loudly if there are none at all, rather than silently trusting
/// only our own CA (see `docs/SSL_DESIGN.md`). Kept as a pure function
/// so the empty-store guard is unit-testable without touching the real
/// system store or `SSL_CERT_FILE`.
fn roots_from_certs(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
) -> Result<rustls::RootCertStore> {
    if certs.is_empty() {
        return Err(Error::no_root_certificates());
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|e| {
            Error::other("could not add a system CA certificate", e)
        })?;
    }
    Ok(roots)
}

/// Proxy handler that enforces allow/deny rules and injects credentials
/// from the [`Proxies`] config.
///
/// hudsucker calls [`PassthroughHandler::handle_request`] as the
/// gateway for every request (HTTP and CONNECT alike), so that's where
/// routing and injection live:
///
/// - Allowed HTTP requests: credentials (headers/params/auth) are
///   injected for hosts that carry them, then the request is forwarded.
/// - Allowed CONNECT: passed through untouched (MITM is a `should_intercept`
///   decision, Phase 4.2).
/// - Denied hosts: an HTTP 403 `Response` is returned, short-circuiting
///   the request before it reaches any upstream.
///
/// `should_intercept` is never consulted for routing — it only gates
/// MITM on CONNECT, which Phase 4.1 does not do. `Clone` because
/// hudsucker clones the handler per connection; cloning `Arc` is cheap.
#[derive(Clone)]
struct PassthroughHandler {
    proxies: Arc<Proxies>,
}

impl HttpHandler for PassthroughHandler {
    /// Decide whether to MITM a CONNECT stream.
    ///
    /// Stage 3 is tunnel-only: allowed CONNECT hosts are piped raw
    /// bytes end-to-end and never intercepted, so this returns `false`
    /// unconditionally. Stage 4 (credential injection) will flip this
    /// per-host to enable MITM.
    async fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        _req: &Request<Body>,
    ) -> bool {
        false
    }

    /// Gateway for every request (HTTP and CONNECT). Routes based on
    /// the [`Proxies`] config:
    ///
    /// - Allowed host → return `Request` so hudsucker tunnels/forwards.
    /// - Denied host → return the 403 `Response`, short-circuiting it.
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> hudsucker::RequestOrResponse {
        // Owned copy (not a borrow of `req`): we move `req` into the
        // injection path below, so any `&str` derived from its URI would
        // outlive the move.
        let host = req.uri().host().unwrap_or("unknown").to_owned();
        let hostname =
            match req.uri().host().and_then(|h| h.parse::<Hostname>().ok()) {
                Some(h) => h,
                None => {
                    // No host or parse failure → deny. Log so we can spot
                    // extraction problems (e.g. a port or trailing dot
                    // leaking into the hostname).
                    trace!(host, "unparseable host; denying");
                    return hudsucker::RequestOrResponse::Response(
                        deny_response(&host),
                    );
                }
            };
        if !self.proxies.should_allow(&hostname) {
            trace!(host, "denied request");
            return hudsucker::RequestOrResponse::Response(deny_response(
                &host,
            ));
        }
        trace!(host = %host, "routing: forwarding allowed host");

        if req.method() == Method::CONNECT {
            // HTTPS CONNECT: pass through untouched. The MITM decision is
            // `should_intercept` (Phase 4.2) — injection there happens on
            // the decrypted inner request, not here.
            return hudsucker::RequestOrResponse::Request(req);
        }

        // Plain HTTP (the HTTP-forward path): inject configured credential
        // headers / query params / auth before forwarding.
        let mut req = req;
        if let Some(rewrite) = self
            .proxies
            .get(&hostname)
            .and_then(crate::sandbox::rewrite::Rewrite::from_proxy)
        {
            debug!(host = %host, "injecting credentials into request");
            rewrite.apply(&mut req);
        }
        hudsucker::RequestOrResponse::Request(req)
    }
}

/// Build the HTTP 403 deny response for a host.
fn deny_response(host: &str) -> Response<Body> {
    // This should always build successfully.
    #[allow(clippy::expect_used)]
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Via", "1.1 redoubtful-proxy")
        .body(Body::from(format!(
            "Access to {host} is denied by redoubtful proxy configuration.\n"
        )))
        .expect("403 response builds")
}

/// Construct the proxy env-var inventory.
///
/// Lives here (not in `cmd::run`) so the list of names stays beside
/// the proxy itself: any future change to what the proxy accepts —
/// adding `WSS_PROXY` if we ever speak WebSocket directly, dropping
/// `ALL_PROXY` if it causes trouble — is one edit in one file.
///
/// `NO_PROXY` is set explicitly even though `--clearenv` already
/// drops the host's value. Whatever we ultimately set here (empty,
/// localhost, etc.) should be a matter of policy.
pub fn proxy_env_vars(port: u16) -> EnvVars {
    let url = format!("http://127.0.0.1:{port}");
    let mut env = EnvVars::default();
    env.set("HTTPS_PROXY", &url);
    env.set("https_proxy", &url);
    env.set("HTTP_PROXY", &url);
    env.set("http_proxy", &url);
    env.set("ALL_PROXY", &url);
    env.set("all_proxy", &url);
    env.set("NO_PROXY", "localhost,127.0.0.1");
    env.set("no_proxy", "localhost,127.0.0.1");
    env
}

/// Build a resolved [`Profile`] representing the proxy's contribution.
///
/// This is a *resolved* (not declared) `Profile`: it contributes one
/// same-port forward and 8 env vars, with no declarations to validate.
/// Merged into the user's finalized profile via
/// [`Finalize::merge_right_biased`] so proxy env vars win on any
/// key collision.
///
/// See [`crate::config::Finalize`] for the `Finalize` trait.
pub fn proxy_profile(port: u16) -> Profile {
    let mut forwards = Forwards::default();
    forwards.forward(port, port);
    Profile {
        mounts: Mounts::default(),
        forwards,
        env: proxy_env_vars(port),
        proxies: Proxies::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_env_vars_populates_all_eight_names_with_matching_url() {
        use std::ffi::OsStr;

        let env = proxy_env_vars(12345);
        let names: Vec<&str> = env.iter().map(|e| e.name.as_str()).collect();
        // BTreeMap gives ASCII-sorted order (uppercase before lowercase;
        // "HTTPS" < "HTTP_" because 'S' (0x53) < '_' (0x5F)).
        assert_eq!(
            names,
            vec![
                "ALL_PROXY",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "NO_PROXY",
                "all_proxy",
                "http_proxy",
                "https_proxy",
                "no_proxy",
            ],
        );

        // The six proxy URLs all match and point at the bound port.
        let expected = OsStr::new("http://127.0.0.1:12345");
        for name in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            let entry = env
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(&entry.value, expected, "{name} value");
        }

        // NO_PROXY exempts loopback so proxy-bypassing traffic (e.g. a
        // local model server) never enters the proxy (see `proxy_env_vars`
        // doc).
        for name in ["NO_PROXY", "no_proxy"] {
            let entry = env
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(
                &entry.value,
                OsStr::new("localhost,127.0.0.1"),
                "{name} value"
            );
        }
    }

    #[tokio::test]
    async fn start_proxy_binds_a_port_and_shuts_down_cleanly() {
        // Smoke test: we can bind, get a port, and shut down without
        // hanging. Doesn't exercise an actual CONNECT (that would
        // require an upstream and is a bwrap+pasta integration
        // concern, not a unit-level one).
        let proxies = Proxies::default();
        let handle = start_proxy(&proxies).await.expect("proxy starts");
        assert!(handle.port > 0, "ephemeral port assigned");
        handle.shutdown().await;
    }

    // ===== upstream root store tests =====

    #[test]
    fn roots_from_certs_empty_fails_loudly() {
        // The "single source of CA truth" guard: if the system store
        // yields no certificates at all, we must fail rather than
        // silently trust only our own CA.
        let err = roots_from_certs(Vec::new()).expect_err("empty store errors");
        assert!(matches!(err, Error::NoRootCertificates));
    }

    #[test]
    fn roots_from_certs_loads_valid_certificates() {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate().expect("generates keypair");
        let cert = CertificateParams::default()
            .self_signed(&key_pair)
            .expect("self-signs");

        let roots = roots_from_certs(vec![cert.der().clone()])
            .expect("one valid cert loads");
        assert_eq!(roots.len(), 1, "one root in the store");
    }

    // ===== should_allow routing tests =====
    //
    // These test `Proxies::should_allow` directly — the pure routing
    // logic extracted from the handler. This avoids needing to
    // construct hudsucker's non-exhaustive `HttpContext`.

    fn mk_proxy(
        host: &str,
        action: crate::config::proxy::ProxyAction,
    ) -> crate::config::proxy::Proxy {
        crate::config::proxy::Proxy {
            host: host.parse().expect("valid hostname"),
            port: 443,
            action,
            headers: std::collections::BTreeMap::new(),
            params: std::collections::BTreeMap::new(),
            auth: None,
        }
    }

    fn host(s: &str) -> Hostname {
        s.parse().expect("valid hostname")
    }

    #[test]
    fn should_allow_explicit_allow() {
        // public_web=Deny, explicit Allow for example.net
        let proxies = Proxies::with_entries(
            Some(crate::config::proxy::ProxyAction::Deny),
            [mk_proxy(
                "example.net",
                crate::config::proxy::ProxyAction::Allow,
            )],
        );
        assert!(proxies.should_allow(&host("example.net")));
    }

    #[test]
    fn should_deny_explicit_deny() {
        // public_web=Allow, explicit Deny for example.net
        let proxies = Proxies::with_entries(
            Some(crate::config::proxy::ProxyAction::Allow),
            [mk_proxy(
                "example.net",
                crate::config::proxy::ProxyAction::Deny,
            )],
        );
        assert!(!proxies.should_allow(&host("example.net")));
    }

    #[test]
    fn should_allow_unknown_when_public_allow() {
        // public_web=Allow, host not in map
        let proxies = Proxies::with_entries(
            Some(crate::config::proxy::ProxyAction::Allow),
            [],
        );
        assert!(proxies.should_allow(&host("unknown.net")));
    }

    #[test]
    fn should_deny_unknown_when_public_deny() {
        // public_web=Deny, host not in map
        let proxies = Proxies::with_entries(
            Some(crate::config::proxy::ProxyAction::Deny),
            [],
        );
        assert!(!proxies.should_allow(&host("unknown.net")));
    }

    #[test]
    fn should_deny_when_public_web_none() {
        // Unknown state → deny (safety default)
        let proxies = Proxies::with_entries(None, []);
        assert!(!proxies.should_allow(&host("anything.net")));
    }
}

//! Stage 1: a tunnel-only HTTPS proxy on host loopback.
//!
//! The sandbox cannot resolve DNS or reach external network on its
//! own (`specs/ARCHITECTURE.md`, "No DNS resolution to arbitrary
//! hosts"); proxying through the host is the only path out. This
//! module owns the host-side proxy: it binds an ephemeral port on
//! `127.0.0.1`, accepts the `CONNECT host:port` requests sandboxed
//! clients send when they see `HTTPS_PROXY`, resolves the upstream
//! host *on the host*, and pipes raw bytes between the client and
//! that upstream. TLS terminates end-to-end between the client and
//! the real server — the proxy never sees plaintext.
//!
//! Stage 1 deliberately does **not** intercept (no MITM, no
//! credential injection, no allow/deny). The architecture spec's
//! "MITM mode" lands later; for now the only goal is "make
//! HTTPS-proxy-aware clients in the sandbox able to reach the
//! internet at all" so things like `pi`'s `npm install` no longer
//! die on `getaddrinfo EAI_AGAIN`.
//!
//! Why a CA shows up below despite no MITM. Hudsucker's typed
//! builder requires `with_ca` to leave the `WantsCa` state — the
//! API doesn't model "tunnel-only, no CA" as a valid configuration
//! even though it is a valid runtime mode (`HttpHandler::should_intercept`
//! returning `false` short-circuits CONNECT before the CA is touched).
//! We therefore generate a throwaway in-memory CA at startup, hand
//! it to the builder, and never let it sign anything: no cert is
//! written to disk, no env var points at one, nothing is bind-mounted
//! into the sandbox. This is the cheapest way to satisfy the
//! type-state without lying about our policy.

use std::net::{Ipv4Addr, SocketAddr};

use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy,
    certificate_authority::RcgenAuthority, hyper::Request,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

use crate::{
    config::{
        env_vars::EnvVars, forwards::Forwards, mounts::Mounts, profile::Profile,
    },
    prelude::*,
};

/// Handle to the running proxy task.
///
/// Held by `cmd_run` for the lifetime of the sandbox; on shutdown
/// the caller invokes [`Self::shutdown`] to signal the proxy to
/// stop accepting and to drain in-flight tunnels.
pub struct ProxyHandle {
    /// Host-loopback port the proxy is listening on. Pasta forwards
    /// this into the sandbox's netns; bwrap sets `HTTPS_PROXY` to
    /// `http://127.0.0.1:<port>`.
    pub port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ProxyHandle {
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

/// Bind a host-loopback port, spawn the tunnel-only proxy on it,
/// and return a handle the launcher can use to query the port and
/// shut the proxy down on exit.
///
/// Listens on `127.0.0.1:0` so the kernel picks an unused ephemeral
/// port. Pasta's `-T` flag forwards that port into the sandbox's
/// netns (see `crate::pasta`), so a sandboxed client doing
/// `connect("127.0.0.1", port)` lands on this listener.
#[instrument(level = "debug", skip_all)]
pub async fn start_proxy() -> Result<ProxyHandle> {
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| Error::could_not_run("bind proxy listener", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::could_not_run("read proxy local_addr", e))?
        .port();
    debug!(port, "proxy listener bound");

    // Throwaway CA — see module doc for why it exists. Generated
    // fresh per process; the keypair never leaves this address space.
    let issuer = build_throwaway_ca()?;

    // Pure-Rust crypto for hudsucker's TLS layers. In tunnel-only
    // mode the provider isn't actually exercised on the proxy's
    // hot path (no MITM = no leaf cert signing, no inbound TLS
    // accept), but the builder needs one to wire up its outbound
    // hyper-rustls client.
    let provider = rustls::crypto::ring::default_provider();
    let ca = RcgenAuthority::new(issuer, 1024, provider.clone());

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_rustls_connector(provider)
        .with_http_handler(TunnelOnlyHandler)
        .with_graceful_shutdown(async move {
            // A `Sender::send` we never receive (because the launcher
            // exited without calling `shutdown`) cancels via the
            // dropped-sender path; either way the future resolves
            // and hudsucker stops.
            let _ = shutdown_rx.await;
        })
        .build()
        .map_err(|e| {
            Error::could_not_run(
                "build proxy",
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
        shutdown_tx: Some(shutdown_tx),
        task,
    })
}

/// Generate the throwaway CA hudsucker's builder demands. See the
/// module doc for why this exists; the short version is that the
/// builder's type-state requires `with_ca` to compile, and we want
/// to satisfy it without lying — this CA is real, just unused.
///
/// `is_ca = Unconstrained` so the cert is *technically* a valid CA
/// in case a future change flips a single host to MITM mode and
/// hudsucker's leaf-signing path actually fires; it costs nothing
/// to set correctly today and it matches what we'd need then.
fn build_throwaway_ca() -> Result<Issuer<'static, KeyPair>> {
    let key_pair = KeyPair::generate().map_err(|e| {
        Error::could_not_run(
            "generate proxy CA keypair",
            std::io::Error::other(e.to_string()),
        )
    })?;

    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        "redoubtful sandbox proxy (unused — tunnel-only)",
    );
    params.distinguished_name = dn;

    Ok(Issuer::new(params, key_pair))
}

/// Hudsucker handler that vetoes interception for every CONNECT,
/// turning the proxy into a pure CONNECT-tunnel: client TLS goes
/// end-to-end to the real upstream, the proxy just pipes bytes.
///
/// `Clone` because hudsucker clones the handler per connection.
/// Stateless, so cloning is free.
#[derive(Clone)]
struct TunnelOnlyHandler;

impl HttpHandler for TunnelOnlyHandler {
    /// Returning `false` short-circuits hudsucker's MITM path: the
    /// CONNECT response is `200 Connection established` and the rest
    /// of the connection is `tokio::io::copy_bidirectional` between
    /// the client socket and a fresh outbound TCP to the upstream.
    /// `handle_request` / `handle_response` are never called in this
    /// mode, so we keep their default impls.
    async fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        _req: &Request<Body>,
    ) -> bool {
        false
    }
}

/// Construct the proxy env-var inventory.
///
/// Lives here (not in `cmd::run`) so the list of names stays beside
/// the proxy itself: any future change to what the proxy accepts —
/// adding `WSS_PROXY` if we ever speak WebSocket directly, dropping
/// `ALL_PROXY` if it causes trouble — is one edit in one file.
///
/// `NO_PROXY=""` is set explicitly even though `--clearenv` already
/// drops the host's value: it nails the policy down at the bwrap
/// layer rather than relying on absence-as-policy, and a future
/// reader sees the rule rather than having to infer it.
pub fn proxy_env_vars(port: u16) -> EnvVars {
    let url = format!("http://127.0.0.1:{port}");
    let mut env = EnvVars::default();
    env.set("HTTPS_PROXY", &url);
    env.set("https_proxy", &url);
    env.set("HTTP_PROXY", &url);
    env.set("http_proxy", &url);
    env.set("ALL_PROXY", &url);
    env.set("all_proxy", &url);
    env.set("NO_PROXY", "");
    env.set("no_proxy", "");
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

        // NO_PROXY family is empty — explicit-empty policy at the
        // bwrap layer (see `proxy_env_vars` doc).
        for name in ["NO_PROXY", "no_proxy"] {
            let entry = env
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(&entry.value, OsStr::new(""), "{name} value");
        }
    }

    #[tokio::test]
    async fn start_proxy_binds_a_port_and_shuts_down_cleanly() {
        // Smoke test: we can bind, get a port, and shut down without
        // hanging. Doesn't exercise an actual CONNECT (that would
        // require an upstream and is a bwrap+pasta integration
        // concern, not a unit-level one).
        let handle = start_proxy().await.expect("proxy starts");
        assert!(handle.port > 0, "ephemeral port assigned");
        handle.shutdown().await;
    }
}

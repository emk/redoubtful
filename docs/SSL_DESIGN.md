# SSL Design

> **Status:** Reference design notes. Describes how the different parts of
> redoubtful's stack decide which TLS certificates to trust, and why they
> agree on a single source of truth. Canonical for the related discussions
> in `plans/PROXY_CONFIG.md` and `docs/proxy-testing-challenges.md` — those
> refer here instead of repeating the details. The design is fully
> implemented; this doc describes how it works now, not how it got here.

This document is about how different parts of redoubtful's stack decide
which TLS certificates to trust, and why we want them to agree.

## CA1 and CA2

Two independent certificate authorities appear in redoubtful's trust model
(see `plans/PROXY_CONFIG.md`, "SSL foundation phasing" for the original
reasoning):

- **CA1** — the *outside* CA. In production, the public web of trust; in
  tests, a hermetic `rcgen` test CA that signs the test upstream's leaf.
- **CA2** — redoubtful's *inside* per-session MITM CA that signs the
  proxy's leaf certs.

## The four SSL trust contexts

Trust lives in different places depending on who is doing the verifying.
It helps to name all of them before reasoning about them:

| Context | Who is verifying | What it trusts |
|---|---|---|
| **Real world ("outside")** | Public clients / servers | **CA1** = the public CA web of trust. The baseline everyone starts from. |
| **Integration testing** | Our test tools | **CA1** = a hermetic throwaway CA (`rcgen` test CA) that signs our test upstream's leaf cert. Fully ours to control. |
| **hudsucker's upstream connections** | redoubtful's own TLS *client* | **CA1** (the upstream's CA) — what the proxy trusts when it MITM-connects to a real upstream. Does **not** need CA2. |
| **Code inside the sandbox** | sandboxed tools (`curl`, git, MCP clients, …) | **CA1 + CA2** (the upstream's CA *and* redoubtful's MITM CA) — the merged CA bundle the proxy mounts into the sandbox. |

The two we care about most here are the last two. Everything below is
about them.

## The "single source of SSL truth" goal

The two trust legs above should not diverge. A cert approved by one leg
must not be rejected by the other, and a system administrator should be
able to make both honor their customization with one knob. **We want one
canonical source of trust, and different *contexts* merely append what
they specifically need to it.**

### The canonical source

The **system CA bundle as discovered by `openssl-probe`** (which honors a
user's `SSL_CERT_FILE` / `SSL_CERT_DIR`). Concretely, `rustls-native-certs`
loads it into a `rustls::RootCertStore`. Everything else derives from it:

- **hudsucker's upstream client** → `RootCertStore` from
  `rustls-native-certs` (+ any extras the caller needs).
- **Sandbox-side** → the *same* system bundle, plus redoubtful's
  per-session MITM CA appended (so sandboxed tools trust redoubtful's
  leaf certs).

So both legs share **CA1** as the base. Each leg adds only what it is for:

- **sandbox leg** appends **CA2** (redoubtful's internal MITM CA) → trusts
  **CA1 + CA2**, so sandboxed curl can verify the CA1-issued upstream in
  passthrough AND the proxy's CA2 leaf in MITM;
- **upstream-client leg** uses **CA1 only** — the proxy never MITM-verifies
  its own leaf, so it does not need CA2.

In test mode, `SSL_CERT_FILE` points at the test CA1, so `openssl-probe`
reads CA1 as the "system" store. The merged sandbox bundle is then CA1 +
CA2, and the upstream-client leg trusts CA1 — the same roots, in two
places.

### How the upstream client gets the store

`with_rustls_connector(provider)` is a dead end — it accepts only a crypto
`CryptoProvider` and always calls `with_webpki_roots()`. The general
escape hatch is hudsucker's **`with_http_connector(connector)`**, which
accepts any `hyper::Client` connector. When no `client` is supplied,
hudsucker builds its upstream-forwarding `Client` straight from that
connector (`proxy/mod.rs`, `Client::builder(..).build(http_connector)`);
that `.client` is exactly what `handle_request`'s forwarding uses. So:

```text
openssl-probe / SSL_CERT_FILE / SSL_CERT_DIR
   └─> rustls-native-certs::load_native_certs()
         └─> RootCertStore
               └─> ClientConfig::builder_with_provider(provider)
                    .with_root_certificates(root_store).with_no_client_auth()
                    └─> hyper_rustls::HttpsConnector ──> with_http_connector(...)
```

This single change makes redoubtful's upstream client honor
`SSL_CERT_FILE`/`SSL_CERT_DIR` — which is exactly the seam the MITM tests
need (point it at a bundle containing the test CA).

**Tradeoff:** production upstream trust changes from bundled Mozilla
webpki roots to the host's system bundle. That is the deliberate point of
"one source of truth". If `openssl-probe` finds no bundle at all, we fail
loudly rather than silently trusting only our CA.

## Constraints

**Hard no: OpenSSL (`openssl-native` / `openssl-sys`).** This is a hard
exclusion for *any* design choice here — already enforced in
`deny.toml`. Rationale: too many past integration problems, it is a large
C library with a serious security-fix history, and it has caused minor
API breakage over time. Any framework or dependency that would pull
OpenSSL in (including its C bindings) is disqualified, and if a candidate
offers an OpenSSL or rustls path we must take the rustls path. (This is
why the test server uses `axum-server`'s rustls path
(`tls-rustls-no-provider`) and never an openssl one.)

### Streaming and WebSockets

Two important behaviors sit on the edge of this design and must not be
lightly broken:

1. **OpenAI-style LLM incremental output** (e.g. llama-server's
   OpenAI-compatible endpoint) uses **Server-Sent Events over plain HTTP**
   (`text/event-stream`, `stream=true`) — *not* WebSockets.
2. **MCP clients** use exactly two official transports — **`stdio`** and
   **Streamable HTTP** (HTTP POST/GET with optional SSE; the older form
   was HTTP+SSE). WebSocket is only a *proposal* (SEP-1288), not a
   standard MCP transport.

Both therefore flow through the **normal HTTP connector / MITM-forward**
path — the very connector we customize — and are unaffected by decisions
about WebSockets. This is verified against the ecosystem, not assumed.

**WebSockets are carried raw.** None of the streaming cases above use them,
so we do not MITM `Upgrade: websocket` requests — they forward/tunnel
untouched (see "Other details" for the mechanics). The only WebSocket-based
LLM streaming is the *official* OpenAI Responses-API WebSocket mode, a
managed API feature, not something a self-hosted sandbox endpoint speaks.

## Current implementation

How the design is wired today:

- **Routing stays in `handle_request`.** Allowed hosts forward (plain HTTP
  upstream, CONNECT tunneled raw unless MITM'd); denied hosts get a 403 at
  `handle_request` time.
- **Upstream-client leg.** `build_upstream_connector` in
  `src/sandbox/proxy.rs` builds the proxy's outbound HTTPS connector from a
  `rustls-native-certs` / `openssl-probe` root store via
  `with_http_connector(...)`, honoring `SSL_CERT_FILE` / `SSL_CERT_DIR`. It
  trusts **CA1**.
- **Sandbox leg.** `src/sandbox/ca_bundle.rs` builds the merged **CA1+CA2**
  bundle (`find_system_ca_bundle` via `openssl-probe` +
  `build_sandbox_ca_bundle`). `start_proxy` persists it as a host-side
  `NamedTempFile` owned by `ProxyHandle`; `proxy_profile` bind-mounts it ro
  into the sandbox at `/tmp/redoubtful-ca-bundle.crt` and sets the `*_CA_*`
  env vars (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
  `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`). It trusts **CA1 + CA2**.
- **MITM.** `Proxies::should_mitm` gates `should_intercept_connect` per-host
  (`allowed && has_injection_config`, where `has_injection` means the host
  carries headers/params/auth). When true, hudsucker terminates TLS with a
  **CA2**-signed leaf and feeds the decrypted inner request back through
  `handle_request`, which injects the configured credentials via
  `Rewrite` and forwards over the upstream connector.
- **Our own CA authority (`SandboxCa`).** The MITM leaves are signed by our
  own `CertificateAuthority` (`SandboxCa` in `src/sandbox/proxy.rs`), not
  hudsucker's built-in `RcgenAuthority`. This works around a genuine
  hudsucker bug: `RcgenAuthority` always emits a `DnsName` SAN even for
  IP-literal hosts, which curl/browsers reject (they require an
  `IpAddress` SAN for an IP peer). `SandboxCa` emits `IpAddress` for IP
  hosts, `DnsName` otherwise, and keeps a tiny LRU cache of generated
  configs.

## Testing

The E2E HTTPS tests exercise the **CONNECT / raw-byte tunnel** and **MITM**
paths, which the HTTP-forward tests never touch, so they add real coverage.

The chosen test server is **`axum-server` + `axum`** (the same framework we
mock plain HTTP with, so HTTP and HTTPS share one harness):

```rust
let app = Router::new().route("/", get(|| async { HTTPS_SENTINEL }));
let server =
    axum_server::Server::<std::net::SocketAddr>::from_listener(listener)
        .acceptor(axum_server::tls_rustls::RustlsAcceptor::new(config));
server.serve(app.into_make_service())
```

Why axum-server and not an HTTP mock:

- `httptest` (our original HTTP mock) has **no TLS support** (raw
  `TcpListener` + hyper, no TLS feature).
- `wiremock`-rs also has **no TLS support** (the "Serving HTTPS" pages are
  the Java WireMock, easy to get fooled by).
- `httpmock` supports HTTPS but couples it to bundled-reserved-hostname
  CAs, which fights the hermetic `127.0.1.1` IP-literal trick.

So there is no off-the-shelf HTTP-mock TLS server that fits; we use a
simple existing Rust HTTPS-capable server framework with a one- or
two-line handler: bind `127.0.1.1:0`, terminate TLS, and answer every
request `200 OK` + sentinel. The tests run on the host (bwrap + pasta +
curl).

### Test-server decisions

Key decisions, all verified against the dependency sources:

- **Feature:** `axum-server`'s `tls-rustls-no-provider` feature (NOT
  `tls-rustls`, which would additionally enable `rustls/aws-lc-rs`).
  The rustls `tls_rustls` API is gated on `tls-rustls-no-provider`, so we
  get `bind_rustls` / `RustlsConfig` / `RustlsAcceptor` without importing
  the aws-lc C backend.
- **Crypto provider:** `aws-lc-rs` is already enabled transitively by
  hudsucker's `hyper-rustls` alongside our pure-Rust `ring`, so rustls
  cannot auto-pick one. We call
  `rustls::crypto::ring::default_provider().install_default()` once in the
  test helper, honoring the project's pure-Rust preference. (`rustls` is
  a dev-dep so the integration tests can reach it.)
- **Port:** bound on a background tokio runtime via a
  `tokio::net::TcpListener` (NOT a `std::net::TcpListener` handed across
  threads — tokio rejects registering a blocking socket cross-thread,
  issue #7172). The ephemeral port is reported back through a channel so
  we can build the hermetic `127.0.1.1:<port>` target. `axum-server`'s
  own `bind_rustls` can't hand back a `:0` bind's port (no public
  `local_addr`), so we pre-bind a tokio listener and use
  `Server::<SocketAddr>::from_listener(...)`.
- **Teardown:** each upstream runs on its own background tokio `Runtime`
  on a detached thread; the handle sends a oneshot shutdown and joins.
  An `Upstream` guard drops it at test end.
- `rcgen` (already a dependency for the proxy CA) generates the
  throwaway leaf; the IP SAN keeps it semantically right for the
  `127.0.1.1` target.
- The upstream is async but the test driver is sync: we deliberately do
  **not** convert the tests to async. The axum server lives on its own
  background `Runtime`; the test (bwrap + pasta + curl) stays blocking.

Rationale vs `tiny_http`: `tiny_http`'s `ssl-rustls` pulls in an
**old rustls 0.20 + ring 0.16** (a second, older TLS implementation in
 the tree). axum-server reuses the already-present rustls 0.23 / hyper /
 tokio-rustls stack and moves in sync with it. The async-vs-sync hosting
cost is absorbed by the shared background-`Runtime` upstream.

### The CA1 test authority

The test upstream serves a leaf signed by a dedicated on-the-fly `rcgen`
test CA (never committed, so no secret scanner is upset), in
`tests/cli/utils/http.rs` (`ca1()` + `ca1_cert_path()`). The host-side
control verifies the leaf against CA1 with `curl --cacert`.

The three HTTPS test behaviors:

- **Passthrough routing** (`https_through_proxy_*`): the sandboxed curl
  verifies the CA1-issued upstream directly against CA1 in the merged
  bundle (no `-k`).
- **Denied routing**: the proxy 403s the CONNECT before any TLS handshake,
  so no CA verification is involved.
- **MITM injection** (`https_credential_injection_mitms_and_injects`):
  exercises both legs at once — the sandboxed curl trusts the proxy's
  CA2-signed leaf via the merged bundle, and the proxy's upstream client
  trusts CA1 via `SSL_CERT_FILE`, so it can reconnect to the test upstream.

## Other details worth remembering

- **The `127.0.1.1` hermetic shortcut** (inside loopback, outside the
  client's `NO_PROXY=localhost,127.0.0.1`) is the key that makes the E2E
  tests DNS-free. See `docs/proxy-testing-challenges.md`.
- **WebSocket mechanics in hudsucker:** `ws://` upgrade requests route
  through `upgrade_websocket`/`handle_websocket`, which uses the
  `websocket_connector`; `with_http_connector` leaves it `None`, so WS
  upgrades fall back to tokio-tungstenite's default connector. `wss://`
  goes through the CONNECT raw tunnel regardless, so it never touches any
  connector at all.
- **hudsucker builder state order:** `with_addr`/`with_listener` →
  `with_ca` → `with_rustls_connector` *or* `with_http_connector` →
  `with_http_handler` → `with_websocket_connector` / `with_client` →
  `build`.
- **Dependencies for the unified connector:** `rustls-native-certs` (new,
  tiny) plus `hyper-rustls` and `hyper-util` (already transitively present;
  declared directly to build the connector), and `openssl-probe` for the
  sandbox bundle.
- **Test-server deps:** `axum` + `axum-server` (dev-deps, feature
  `tls-rustls-no-provider`), `rustls` (dev-dep, to pin the `ring`
  provider), plus `rcgen` in dev-deps (already a main dep) for the
  throwaway cert/key.

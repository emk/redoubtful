# SSL Design

> **Status:** Reference design notes. Captures the TLS trust model for
> redoubtful's proxy, the decision to unify on a *single source of SSL
> truth*, and the consequences for testing HTTPS. Canonical for the
> related discussions in `plans/PROXY_CONFIG.md` and
> `docs/proxy-testing-challenges.md` — those refer here instead of
> repeating the details.
>
> **Status — prerequisite 1 (single source of CA truth) is IMPLEMENTED.**
> `src/sandbox/proxy.rs` now builds the upstream-client connector with
> `with_http_connector(...)` from a `rustls-native-certs` / `openssl-probe`
> root store (off the compiled-in Mozilla roots); see
> [`build_upstream_connector`](../src/sandbox/proxy.rs). Still *not*
> implemented: the sandbox-leg CA bundle (CA2 appended to the merged
> bundle), the CA1 test upstream, and dropping `-k` in passthrough tests.
> Per the revised phasing in `plans/PROXY_CONFIG.md` ("SSL foundation
> phasing"), this was the first prerequisite to build, before any HTTPS/MITM
> work or dropping `-k` in passthrough tests. This doc uses **CA1** (the
> outside test/server CA) and **CA2** (redoubtful's internal MITM CA)
> terminology — see the phasing doc for the who-verifies-which table.

This document is about how different parts of redoubtful's stack decide
which TLS certificates to trust, and why we want them to agree.

## The four SSL trust contexts

Trust lives in different places depending on who is doing the verifying.
It helps to name all of them before reasoning about them:

In CA1+CA2 terms (see `plans/PROXY_CONFIG.md`, "SSL foundation phasing"):
**CA1** is the *outside* CA — in production, the public web of trust; in
tests, our `rcgen` test CA that signs the test upstream's leaf. **CA2** is
redoubtful's *inside* per-session MITM CA that signs the proxy's leaf
certs.

| Context | Who is verifying | What it trusts |
|---|---|---|
| **Real world ("outside")** | Public clients / servers | **CA1** = the public CA web of trust. The baseline everyone starts from. |
| **Integration testing** | Our test tools | **CA1** = a hermetic throwaway CA (`rcgen` test CA) that signs our test upstream's leaf cert. Fully ours to control. |
| **hudsucker's upstream connections** | redoubtful's own TLS *client* | **CA1** (the upstream's CA) — what the proxy trusts when it MITM-connects to a real upstream. Does **not** need CA2. |
| **Code inside the sandbox** | sandboxed tools (`curl`, git, MCP clients, …) | **CA1 + CA2** (the upstream's CA *and* redoubtful's MITM CA) — this is what the plan's CA-bundle machinery targets. |

The two we care about most here are the last two. Everything below is
about them.

## The "single source of SSL truth" goal

Today the last two contexts trust *different* stores:

- **hudsucker's upstream client** is built by `with_rustls_connector`,
  which hardcodes `ClientConfig::...with_webpki_roots()...` — a
  compiled-in Mozilla root set with no public way to extend it. It
  ignores the system store and `SSL_CERT_FILE`/`SSL_CERT_DIR`.
- **Sandbox-side trust** is the planned `openssl-probe` merged bundle
  (system CA bundle + redoubtful's per-session MITM CA appended), mounted
  into the sandbox and advertised via `SSL_CERT_FILE`/`GIT_SSL_CAINFO` etc.

Two independent sources of truth are a security smell: a cert approved by
one may be rejected by the other, and a system administrator cannot make
both honor their customization with one knob. **We want one canonical
source of trust, and different *contexts* merely append what they
specifically need to it.**

### The chosen canonical source

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
- **upstream-client leg** uses **CA1 only** (and, in tests, needs the test
  CA to MITM-connect to our CA1-issued HTTPS endpoint) — it does **not**
  need CA2, since the proxy never MITM-verifies its own leaf.

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
`SSL_CERT_FILE`/`SSL_CERT_DIR` — which is exactly the seam MITM tests need
(point it at a bundle containing the test CA).

**Tradeoff:** production upstream trust changes from bundled Mozilla
webpki roots to the host's system bundle. That is the deliberate point of
"one source of truth", and it matches the existing `openssl-probe`
philosophy. If `probe()` finds no bundle at all, we fail loudly rather
than silently trusting only our CA (the position already taken in the
`ca_bundle.rs` plan).

## Constraints

**Hard no: OpenSSL (`openssl-native` / `openssl-sys`).** This is a hard
exclusion for *any* design choice here — already enforced in
`deny.toml`. Rationale: too many past integration problems, it is a large
C library with a serious security-fix history, and it has caused minor
API breakage over time. Any framework or dependency that would pull
OpenSSL in (including its C bindings) is disqualified, and if a candidate
offers an OpenSSL or rustls path we must take the rustls path. (This is
why, below, the test server uses `axum-server`'s rustls path
(`tls-rustls-no-provider`) and never an openssl one.)

### Streaming and WebSockets

We must not lightly break two important behaviors that sit on the edge of
this design:

1. **OpenAI-style LLM incremental output** (e.g. llama-server's
   OpenAI-compatible endpoint) uses **Server-Sent Events over plain HTTP**
   (`text/event-stream`, `stream=true`) — *not* WebSockets.
2. **MCP clients** use exactly two official transports — **`stdio`** and
   **Streamable HTTP** (HTTP POST/GET with optional SSE; the older form
   was HTTP+SSE). WebSocket is only a *proposal* (SEP-1288), not a
   standard MCP transport.

Both therefore flow through the **normal HTTP connector / MITM-forward**
path — the very connector we are customizing — and are unaffected by
decisions about WebSockets. This is verified against the ecosystem, not
assumed.

**WebSockets are less important.** None of the streaming cases above use
them. The only WebSocket-based LLM streaming is the *official* OpenAI
Responses-API WebSocket mode, which is a managed API feature, not something
a self-hosted sandbox endpoint speaks.

## The plan

1. **Routing stays in `handle_request`.** Stage 3 is tunnel-only; allowed
   CONNECT streams are piped raw bytes, denied hosts get a 403 at
   `handle_request` time. Unchanged.
2. **Unify hudsucker's upstream client on the system store** (choice 1
   above): swap `with_rustls_connector(provider)` for
   `with_http_connector(custom_https_connector)` built from a
   `rustls-native-certs` root store. **DONE** — see
   `build_upstream_connector` in `src/sandbox/proxy.rs`.
3. **WebSockets — two acceptable options:**
   - *Carry them along on the same ClientConfig* via
     `with_websocket_connector(Connector::Rustls(Arc::new(client_config)))`,
     reusing the exact same root store (still one source of truth); **or**
   - *Declare "no MITM / no credential injection for WebSockets"* — just
     don't intercept `Upgrade: websocket` requests; they tunnel/forward
     raw. This is safe precisely because the injection-relevant streams
     (SSE) are HTTP, not WebSocket.
   The cheap insurance is the first; the simpler policy is the second.
4. **No CA trust wiring for passthrough routing tests.** In tunnel mode
   the proxy never terminates TLS, so neither the upstream-client store
   nor the sandbox bundle is engaged. Passthrough tests need `curl -k`
   and zero CA machinery; the upstream-client seam is only exercised once
   MITM comes (Stage 4).

## Testing implications

Two E2E HTTPS tests mirror the existing HTTP routing pair
(`http_through_proxy_*`) by exercising the **CONNECT / raw-byte tunnel**
path — which the HTTP tests (HTTP-forward only) never touch, so they add
real coverage.

- `httptest` (our original HTTP mock) has **no TLS support** (raw
  `TcpListener` + hyper, no TLS feature).
- `wiremock`-rs also has **no TLS support** (the "Serving HTTPS" pages are
  the Java WireMock, easy to get fooled by).
- `httpmock` supports HTTPS but couples it to bundled-reserved-hostname
  CAs, which fights the hermetic `127.0.1.1` IP-literal trick.

So there is no off-the-shelf HTTP-mock TLS server that fits. The plan is
**not to hand-roll TLS/HTTP**, but to use a *simple existing Rust
HTTPS-capable server framework* with a one- or two-line handler: bind
`127.0.1.1:0`, terminate TLS, and answer every request `200 OK` + sentinel.
Both routing tests run on this host (bwrap + pasta + curl), like the HTTP
pair.

### The test server: axum + axum-server (rustls)

The chosen test server is **`axum-server` + `axum`** (the same
framework we mock plain HTTP with, so HTTP and HTTPS share one harness):

```rust
let app = Router::new().route("/", get(|| async { HTTPS_SENTINEL }));
let server =
    axum_server::Server::<std::net::SocketAddr>::from_listener(listener)
        .acceptor(axum_server::tls_rustls::RustlsAcceptor::new(config));
server.serve(app.into_make_service())
```

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
  An `Upstream` (formerly `HttpsUpstream`) guard drops it at test end —
  the `httptest::Server` "dropped at end of scope" contract.
- `rcgen` (already a dependency for the proxy CA) generates the
  throwaway self-signed leaf; the IP SAN keeps it semantically right for
  the `127.0.1.1` target even though `curl -k` ignores it.
- The upstream is async but the test driver is sync: we deliberately do
  **not** convert the tests to async. The axum server lives on its own
  background `Runtime`; the test (bwrap + pasta + curl) stays blocking.

Rationale vs `tiny_http`: `tiny_http`'s `ssl-rustls` pulls in an
**old rustls 0.20 + ring 0.16** (a second, older TLS implementation in
 the tree). axum-server reuses the already-present rustls 0.23 / hyper /
 tokio-rustls stack and moves in sync with it. The async-vs-sync hosting
cost is absorbed by the shared background-`Runtime` upstream.

**For clean MITM upgrade (this is CA1):** the test upstream should be
**CA1-issued** by a dedicated `rcgen` test CA (not a bare self-signed
leaf; today `spawn_https_upstream` still uses
`rcgen::generate_simple_self_signed`, so a CA1 does **not** exist yet),
and the CA1 PEM kept as a test artifact. In test mode, point
`SSL_CERT_FILE` / `openssl-probe` at CA1 so it masquerades as "the
system store"; then:

- **sandbox leg** trusts the merged **CA1 + CA2** bundle (CA2 = the
  proxy's per-session MITM CA, appended on top), so curl can verify the
  CA1-issued upstream in passthrough **and** the proxy's CA2 leaf in MITM;
- **upstream-client leg** trusts **CA1** so redoubtful's own client can
  MITM-connect to the test upstream (it does not need CA2).

Passthrough tests can still use `curl -k` until the sandbox bundle
(CA1 + CA2) is wired — the tunnel tests carry a `// TODO` waiting on it.

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
- **The plan's Stage 4 `openssl-probe` work covers the sandbox leg only.**
  The upstream-client leg (this doc's whole point) was the discovered gap;
  `with_http_connector` closes it without forking hudsucker.
- **hudsucker builder state order:** `with_addr`/`with_listener` →
  `with_ca` → `with_rustls_connector` *or* `with_http_connector` →
  `with_http_handler` → `with_websocket_connector` / `with_client` →
  `build`.
- **New deps for the unify step:** `rustls-native-certs` (new, tiny) plus
  `hyper-rustls` and `hyper-util` (already transitively present; declare
  them directly to build the connector).
- **Test-server deps:** `axum` + `axum-server` (dev-deps, feature
  `tls-rustls-no-provider`), `rustls` (dev-dep, to pin the `ring`
  provider), plus `rcgen` in dev-deps (already a main dep) for the
  throwaway cert/key.

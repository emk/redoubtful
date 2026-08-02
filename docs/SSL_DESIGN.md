# SSL Design

> **Status:** Reference design notes. Captures the TLS trust model for
> redoubtful's proxy, the decision to unify on a *single source of SSL
> truth*, and the consequences for testing HTTPS. Canonical for the
> related discussions in `plans/PROXY_CONFIG.md` and
> `docs/proxy-testing-challenges.md` — those refer here instead of
> repeating the details.

This document is about how different parts of redoubtful's stack decide
which TLS certificates to trust, and why we want them to agree.

## The four SSL trust contexts

Trust lives in different places depending on who is doing the verifying.
It helps to name all of them before reasoning about them:

| Context | Who is verifying | What it trusts |
|---|---|---|
| **Real world ("outside")** | Public clients / servers | The public CA web of trust. We don't control this; it is the baseline everyone starts from. |
| **Integration testing** | Our test tools | Hermetic throwaway CAs (e.g. an `rcgen` test CA that signs our test upstream's leaf cert). Fully ours to control. |
| **hudsucker's upstream connections** | redoubtful's own TLS *client* | What the proxy trusts when it connects (MITM) to a real upstream server. |
| **Code inside the sandbox** | sandboxed tools (`curl`, git, MCP clients, …) | What a sandboxed process trusts. This is what the plan's CA-bundle machinery targets. |

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

So both legs share one base. Each leg adds only what it is for:

- sandbox leg appends **redoubtful's internal MITM CA**;
- (in tests) the upstream-client leg appends **the test CA** so redoubtful
  can MITM-connect to our test HTTPS endpoint.

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
why, below, the test server uses `tiny_http`'s `ssl-rustls` feature and
rejects `ssl-openssl`.)

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
   `rustls-native-certs` root store.
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

Two E2E HTTPS tests will mirror the existing HTTP routing pair
(`http_through_proxy_*`) by exercising the **CONNECT / raw-byte tunnel**
path — which the HTTP tests (HTTP-forward only) never touch, so they add
real coverage.

- `httptest` (current HTTP mock) has **no TLS support** (raw `TcpListener`
  + hyper, no TLS feature).
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

### The HTTPS test server

The leading candidate is **`tiny_http`** (synchronous, dead-simple):

```rust
let server = tiny_http::Server::https(addr, SslConfig {
    certificate: cert_pem,   // from rcgen
    private_key: key_pem,    // from rcgen
})?;
for request in server.incoming_requests() {
    request.respond(Response::from_string(HTTPS_SENTINEL))?;
}
```

- `tiny_http` needs its **`ssl-rustls`** feature. `tiny_http` also offers
  `ssl-openssl`, but OpenSSL is a hard no here (see Constraints above), so
  we enable the rustls feature and never the openssl one.
- `rcgen` (already a dependency for the proxy CA) generates the
  throwaway self-signed cert/key for `SslConfig`.
- Runs on a background thread, dropped at test teardown.

(If `tiny_http` proves unsuitable for any reason, the fallback is the
same *simple existing handler framework* shape with a rustls-based server
such as `axum-server`'s `bind_rustls` — the point is a simple existing
framework, not a self-built HTTP stack.)

**For clean MITM upgrade:** the test upstream should be CA-*issued* by a
dedicated `rcgen` test CA (not a bare self-signed leaf), and the CA PEM
kept as a test artifact. Passthrough tests can still use `curl -k`
(no CA machinery needed now), but the CA is there for MITM: point
redoubtful's upstream client at it (via `SSL_CERT_FILE` / the custom root
store) and the sandbox at it (via the existing sandbox-bundle machinery).

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
- **Test-server deps:** `tiny_http` (dev-dep, feature `ssl-rustls`) plus
  `rcgen` in dev-deps (already a main dep) for the throwaway cert/key.

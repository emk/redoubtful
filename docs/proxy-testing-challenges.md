# Proxy Testing Challenges

Notes on how to test the host-side proxy (allow/deny routing, and eventually
credential injection) hermetically, and the networking model that makes it
tricky.

> **Status:** Reference notes. Captures a bug we hit in Stage 3 and the
> testing gap that let it through, plus the now-implemented harness for
> Stage 5's HTTP routing E2E (`tests/cli.rs`). The same harness will be
> extended (in the future / Stage 4) to validate credential injection with
> a richer upstream that echoes what it received.

## The bug that motivated this

In Stage 3, allow/deny routing was wired into `should_intercept`, and every
request came back **403** — including explicitly-allowed hosts.

Root cause (verified against hudsucker 0.24.0 `src/proxy/internal.rs`):

- hudsucker calls `handle_request` as the **first hook for every request**
  (HTTP and CONNECT alike), *before* touching upstream.
  Returning `Response` short-circuits the request; returning `Request` lets
  it continue (HTTP forward / CONNECT tunnel / websocket).
- `should_intercept` is only consulted later, inside `process_connect`, and
  it decides **MITM vs tunnel** for CONNECT — not allow/deny.

So the routing belongs in **`handle_request`** (return `Request` to
forward/tunnel when allowed, `Response` 403 when denied), and
`should_intercept` is purely the future MITM gate for credential injection.
This was the "HTTP vs HTTPS — TBD" uncertainty flagged in Stage 3:
"may require distinguishing CONNECT targets from Host-header-based routing
in `handle_request`."

The fix moved routing into `handle_request` and made `should_intercept`
return `false` (Stage 3 is tunnel-only).

## Why the test suite missed it

The proxy-related integration tests were hermetic by design and never sent a
real request through the handler:

- `proxy_env_var_is_set_in_sandbox` only asserts the `HTTPS_PROXY` env var is
  set/formatted correctly — its doc comment explicitly says it doesn't
  *use* the proxy (would need a controllable upstream).
- The `-f` forward test hits a local sentinel directly (bypasses the proxy,
  and is `NO_PROXY`-exempt anyway).
- The CLI tests only check that `--public-web` / `--proxy` flags parse and
  merge.

Meanwhile the routing **unit** tests exercise `Proxies::should_allow` — the
*predicate* — in isolation. They pass no matter how the handler is wired,
because the bug was in the **wiring** (wrong hook), not the predicate.

Lesson: unit tests validate *what to decide*; nothing validated *that the
decision is reached* through the actual handler path. We need an E2E test
that drives a request through the handler to a controllable upstream and
checks the result.

## The networking model

Inside the sandbox there is no DNS resolver and no direct route out. A
sandboxed client just hands a `host:port` string to the proxy:

- HTTP forward → absolute-form URI (`http://host:port/...`)
- CONNECT → authority (`CONNECT host:port`)

The **proxy process runs host-side** and is the one that resolves/connects
to upstream. So the DNS that matters is the *proxy's*, on the host — not the
sandbox's. (This is exactly how `prometheus.lan` reaches a model: the sandbox
never resolves it; the proxy does, host-side.)

## The two real constraints for a controllable upstream

1. **Client-side `NO_PROXY`.** The target must not be `localhost,127.0.0.1`
   (the running `NO_PROXY` value), or the sandbox client will bypass the
   proxy and connect directly — and we won't be testing the proxy at all.
2. **Host-side reachability.** The proxy must be able to connect the target
   `host:port` to our upstream listener.

## The shortcut: an IP literal

To avoid DNS entirely, bound the upstream to the **host's own routable
interface** and target that IP from inside the sandbox, e.g.
`http://<host LAN IP>:<port>/`:

- Client (sandbox): non-`NO_PROXY` IP → sends it through the proxy. ✓
- Proxy (host): connects to an address it literally owns. ✓
- No name resolution anywhere.

**Resolved target (as implemented): `127.0.1.1`.** Even better than a LAN
IP — it is inside the `127.0.0.0/8` loopback block (so the host-side proxy
can connect to it), but is **not** `127.0.0.1` and therefore falls outside
the client's `NO_PROXY` (`localhost,127.0.0.1`), forcing the sandboxed
client to route it through the proxy. No LAN IP, no DNS, no `/etc/hosts`
entry, and no dependence on which physical interface the host happens to
have — fully hermetic. Verified empirically: with `NO_PROXY =
localhost,127.0.0.1`, `curl` to `http://127.0.1.1:<t>/` sends
`GET http://127.0.1.1:<t>/ HTTP/1.1` (absolute-form) to the proxy, and the
host-side proxy connects back to a listener bound on `127.0.1.1:<t>`.

DNS only enters if we want real hostnames — then the name must resolve
host-side to the listener (lean on `/etc/hosts` or a local DNS entry for
hermeticity).

## Harness (as implemented)

The sketch below is now real code in `tests/cli.rs` (`// ===== Proxy E2E:
a real request through the handler =====`). The tiny HTTP upstream is
`httptest` (`ServerBuilder::bind_addr(127.0.1.1:0)`), which removes the
need to hand-roll HTTP parsing/response in the test; its `times(1..)`
expectation keeps the drop-time assertion from flaking on the host-side
control request. The `curl` client is the host's own (visible to the
sandbox via bwrap's shared rootfs).

```
spawn_upstream() → (httptest::Server, target URL)
    // httptest server bound to 127.0.1.1:0, answering any request with
    //   HTTP/1.1 200 OK
    //   <SENTINEL_BODY>

assert_upstream_reachable_on_host(&target)
    // host curl --noproxy "*" to the target → positive control that
    // the upstream is reachable (so a deny isn't misread as a dead
    // listener).

test: http_through_proxy_reaches_upstream_when_allowed
    redoubtful run  curl -s <target>
    assert sandbox stdout contains SENTINEL_BODY
    // old buggy code: got the 403 body → assertion fails ✓

test: http_through_proxy_is_403_when_denied
    redoubtful run --public-web=deny curl -s <target>
    assert sandbox stdout contains "denied by redoubtful proxy configuration"
    assert sandbox stdout does NOT contain SENTINEL_BODY
```

Caveat: these are host-side integration tests (they spawn bwrap + pasta),
so they do not run under `just check-sandbox` (which runs only unit tests
— see the `justfile`); the full `just check` runs them on a real host.

## Future work (Stage 4 / credential injection)

The same harness applies, but with a richer upstream that **echoes what it
received** (headers, query params, auth), so we can assert injected
credentials actually reached it:

- inject a header → upstream echoes it back → assert in the sandbox output
- inject a URL param → same
- Basic/Bearer auth → same

HTTPS tests will additionally require the CA trust wiring (bind-mount of the
per-session CA + `SSL_CERT_FILE`/`GIT_SSL_CAINFO`), which isn't wired yet.
HTTP is the fast path and covers the routing + injection logic without TLS.

## Open details for implementation

- **Pinning the exact target host — resolved for HTTP:** `127.0.1.1`
  (`127.0.0.0/8` loopback, outside the client's `NO_PROXY`) satisfies both
  constraints, as described in the shortcut section above. The routing E2E
  tests in `tests/cli.rs` use it now.
- **Still open for Stage 4 (injection):** the deny-side negative guard and
  the assertion of *what was injected* will need an upstream that echoes its
  received headers/params/auth (see "Future work" below), plus — for HTTPS
  injection — the per-session CA trust wiring (`SSL_CERT_FILE` etc.), which
  is not yet wired.

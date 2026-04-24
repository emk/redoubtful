# redoubtful — v1 Architecture

> **Status:** Original design. The core feature set is fairly settled; CLI details and code layout may still change quite a bit.

A single-binary Linux tool that runs coding agents (Claude Code, OpenCode, etc.) inside a tight sandbox with just enough host access to be useful.

The name is a small pun. `redoubt` is a small fortified enclosure; `redoubtful` reads simultaneously as "full of redoubts," as the archaic word meaning "apprehensive, dreading," and as "re-doubtful" — doubting again, the appropriate stance toward an agent whose outputs you already half-trust enough to run. The tool is all three things.

## Purpose

The guiding principle is that **harder sandboxing is a better UX**: the more restricted the sandbox is, the more freely the agent can run without permission prompts. The tool aims to make `--dangerously-skip-permissions`–style autonomy safe by construction.

The v1 goal is a working base case. Extensions (Docker bridge attachment, socket forwarding for non-TCP services, Podman support) are deferred.

## What the sandbox provides

- **Phantom home directory.** `$HOME` appears nearly empty inside the sandbox. Project directory is bind-mounted at its real path (so git worktrees work). A small, configurable list of dotfiles and dotdirs is re-exposed read-only.
- **No external network.** The sandbox cannot reach the Internet directly, cannot reach RFC 1918 ranges, cannot reach host loopback services by default.
- **Private loopback.** The sandbox has a working `lo` interface in its own netns. Unit tests that bind ephemeral ports on `127.0.0.1` work, and port collisions with host services cannot happen.
- **Credential-injecting HTTPS proxy.** All outbound HTTPS goes through a proxy running on the host. The proxy injects credentials for configured endpoints (Anthropic API, GitHub, etc.) and tunnels unmodified traffic to an allowlist of other hosts (package registries, etc.). Everything else is denied.
- **Scoped host-port forwarding.** Specific TCP ports on host loopback can be exposed into the sandbox via an explicit allowlist. Used for the credential proxy endpoint itself and for host-side services like local LLM inference servers.

## What the sandbox does not provide (by design, in v1)

- No Docker network attachment. Users who want to reach Docker services either publish container ports to host loopback and add them to the forwarded-port list, or wait for v2.
- No SOCKS proxy for raw TCP to external hosts. Outbound is HTTPS-only.
- No IPv6 outbound. Loopback IPv6 works in-sandbox; outbound v6 via the proxy is not in scope for v1.
- No macOS support. Linux only.
- No HTTP/3 support in the proxy. All configured endpoints must negotiate down to HTTP/1.1 or HTTP/2.
- No session persistence across invocations beyond what the project directory's writeability gives you naturally.

## Dependencies

- **`bwrap`** (the `bubblewrap` package). Provides mount/user/pid/ipc/uts/cgroup namespaces, filesystem layout, capability dropping.
- **`pasta`** (the `passt` package). Provides rootless network namespace connectivity and explicit host-loopback port forwarding.
- **Rust toolchain** (build-time only, for the tool itself).

The tool is distributed as a single static musl-linked binary. End users install `bubblewrap` and `passt` via their package manager, drop the binary somewhere on `$PATH`, and write a TOML config.

## Component overview

```
┌────────────────────────────────────────────────────────────────┐
│ Host                                                           │
│                                                                │
│  ┌──────────────┐    ┌────────────────────────────────────┐    │
│  │ Tool binary  │───▶│ Credential proxy (in-process,      │    │
│  │ (launcher +  │    │ listens on 127.0.0.1:$PORT)        │    │
│  │ proxy + ...) │    └────────────────────────────────────┘    │
│  │              │                                              │
│  │  spawns ▼    │                                              │
│  │              │                                              │
│  │  ┌────────────────────────────────────────────────────┐    │
│  │  │ pasta (creates netns, forwards allowlisted ports) │    │
│  │  │                                                    │    │
│  │  │  execs ▼                                           │    │
│  │  │                                                    │    │
│  │  │  ┌──────────────────────────────────────────────┐ │    │
│  │  │  │ bwrap (mount/pid/user/ipc/uts/cgroup nses)  │ │    │
│  │  │  │                                              │ │    │
│  │  │  │  execs ▼                                     │ │    │
│  │  │  │                                              │ │    │
│  │  │  │  ┌────────────────────────────────────────┐ │ │    │
│  │  │  │  │ User command (e.g. `claude`)           │ │ │    │
│  │  │  │  │                                        │ │ │    │
│  │  │  │  │  HTTPS_PROXY → 127.0.0.1:$PORT        │ │ │    │
│  │  │  │  │  (reaches proxy via pasta forward)     │ │ │    │
│  │  │  │  └────────────────────────────────────────┘ │ │    │
│  │  │  └──────────────────────────────────────────────┘ │    │
│  │  └────────────────────────────────────────────────────┘    │
│  └──────────────┘                                              │
└────────────────────────────────────────────────────────────────┘
```

The Rust binary is simultaneously the launcher (coordinates bwrap + pasta + user command startup and teardown) and the credential proxy (runs as a Tokio task inside the same process).

## Process nesting

```
tool-binary
  └─ pasta (owns network namespace)
      └─ bwrap (owns mount, pid, user, ipc, uts, cgroup namespaces; inherits netns)
          └─ user command
```

Critical: bwrap must **not** include `--unshare-net` or `--unshare-all`. It enumerates its unshares explicitly so pasta's netns is inherited. The relevant bwrap flags are `--unshare-ipc --unshare-pid --unshare-user --unshare-uts --unshare-cgroup`.

## Filesystem layout inside the sandbox

Built up by bwrap in argument order. Roughly:

| Path           | Mount                                          | Purpose                                |
|----------------|------------------------------------------------|----------------------------------------|
| `/usr`         | `--ro-bind` from host                          | System binaries and libraries          |
| `/bin`         | `--symlink usr/bin`                            | Standard layout                        |
| `/lib`, `/lib64` | `--symlink usr/lib`, `--symlink usr/lib64`  | Standard layout                        |
| `/etc`         | `--ro-bind` from host                          | System config (resolv.conf, etc.)      |
| `/dev`         | `--dev`                                        | Minimal device nodes                   |
| `/proc`        | `--proc`                                       | Process filesystem for this PID ns     |
| `/tmp`         | `--tmpfs`                                      | Ephemeral scratch                      |
| `$HOME`        | `--tmpfs`                                      | Phantom home (blanks everything)       |
| `$HOME/.gitconfig` etc. | `--ro-bind` from host (configurable list) | Re-exposed dotfiles             |
| `$PWD`         | `--bind` from host at real path                | Project directory, writeable           |
| `/etc/ssl/certs/sandbox-ca.pem` | `--ro-bind` from ephemeral CA file | Proxy CA for TLS trust    |

The order matters: `--tmpfs $HOME` blanks the home first, then `--ro-bind` entries poke holes at specific dotfile paths. Then `--bind $PWD $PWD` re-exposes the project at its real absolute path.

## Environment variables set inside the sandbox

| Variable                  | Value                                           | Purpose                                |
|---------------------------|-------------------------------------------------|----------------------------------------|
| `HTTPS_PROXY`             | `http://127.0.0.1:$PROXY_PORT`                  | Outbound HTTPS routing                 |
| `https_proxy`             | same                                            | Lowercase variant (some tools)         |
| `HTTP_PROXY`, `http_proxy` | same                                           | Plain HTTP routing                     |
| `ALL_PROXY`, `all_proxy`  | same                                            | Some tools honor this                  |
| `NO_PROXY`, `no_proxy`    | `""` (explicitly empty)                         | Prevent inherited host `NO_PROXY` leak |
| `SSL_CERT_FILE`           | `/etc/ssl/certs/sandbox-ca.pem`                 | Generic CA bundle override             |
| `REQUESTS_CA_BUNDLE`      | same                                            | Python `requests`                      |
| `CURL_CA_BUNDLE`          | same                                            | curl                                   |
| `GIT_SSL_CAINFO`          | same                                            | Git HTTPS transport                    |
| `NODE_EXTRA_CA_CERTS`     | same                                            | Node.js                                |
| `CARGO_HTTP_CAINFO`       | same                                            | Cargo (rustls builds)                  |

Additional variables propagated from the host via `--setenv`: `HOME`, `USER`, `TERM`, `LANG`, `PATH`, `SHELL`. Everything else is cleared by bwrap's namespace setup.

## The credential proxy

Runs as a Tokio task inside the tool binary, listening on `127.0.0.1:$PROXY_PORT`. Pasta forwards that port into the sandbox's netns.

### Per-request flow

1. Client in sandbox issues `CONNECT api.anthropic.com:443 HTTP/1.1` to the proxy.
2. Proxy looks up `api.anthropic.com` in its route table.
3. Two possible modes:
   - **MITM mode** (for credential injection): proxy responds `200 Connection established`, generates a leaf cert for `api.anthropic.com` signed by the per-sandbox CA, completes TLS handshake with the client. Reads decrypted HTTP request. Injects configured auth headers from the host keychain / secrets store. Opens separate outbound TLS to the real `api.anthropic.com`. Forwards request, pipes response back.
   - **Tunnel mode** (for allowlisted endpoints that don't need injection): proxy responds `200 Connection established` and just bidirectionally pipes bytes. Client does real TLS to the real destination. No interception, no CA trust needed for that hostname.
4. **Default deny** for anything not in the route table. Proxy responds with `502` or `403` and logs the attempt.

### Certificate authority

- Generated fresh per sandbox session using `rcgen`.
- Lives in a tempdir; destroyed on teardown.
- Trusted only inside the sandbox (via the env vars above); never installed on the host.
- Leaf certs are generated on-the-fly per hostname encountered, cached for the lifetime of the session.

### Secrets

- Read from a TOML secrets file on the host (start simple; OS keychain integration is a v1.1 concern).
- File lives at `$XDG_CONFIG_HOME/redoubtful/secrets.toml` (or similar; pick a name), permissions enforced 0600.
- Loaded into the proxy's memory at startup. Never written to the sandbox in any form.

## Configuration (TOML)

Lives at `$XDG_CONFIG_HOME/redoubtful/config.toml` by default, overridable with `--config`.

```toml
# ====================================================================
# Filesystem policy
# ====================================================================

[filesystem]
# Dotfiles and dotdirs to re-expose read-only inside the sandbox.
# Paths are relative to $HOME.
expose_readonly = [
  ".gitconfig",
  ".config/git",
  ".config/gh",
  ".cargo/config.toml",
  ".config/nvim",
  ".vimrc",
]

# Dotdirs to re-expose read-write (use sparingly — these are escape hatches).
expose_readwrite = []

# ====================================================================
# Network policy
# ====================================================================

[network]
# TCP ports on host loopback to forward into the sandbox.
# The proxy port is added automatically — don't list it here.
forward_ports = [
  # { port = 8080, comment = "llama-server" },
  # { port = 5432, comment = "dev postgres (if host-published)" },
]

# Credential proxy listen port on host loopback. Chosen deterministically
# or randomly per session — set this only if you need it stable.
# proxy_port = 18080  # optional

# ====================================================================
# HTTPS proxy routes
# ====================================================================

# Endpoints where the proxy MITMs, injects credentials, and forwards.
[[route]]
match_host = "api.anthropic.com"
mode = "mitm"
inject = [
  { header = "x-api-key", secret = "anthropic_api_key" },
]

[[route]]
match_host = "api.openai.com"
mode = "mitm"
inject = [
  { header = "Authorization", value = "Bearer {{openai_api_key}}" },
]

[[route]]
match_host = "api.github.com"
mode = "mitm"
inject = [
  { header = "Authorization", value = "Bearer {{github_token}}" },
]

# Git smart-HTTP endpoint for GitHub. Injects HTTP Basic auth.
[[route]]
match_host = "github.com"
mode = "mitm"
inject_basic_auth = { username = "x-access-token", secret = "github_token" }

# Package registries and similar: pass through unmodified.
[[route]]
match_host = "crates.io"
mode = "tunnel"

[[route]]
match_host = "static.crates.io"
mode = "tunnel"

[[route]]
match_host = "index.crates.io"
mode = "tunnel"

[[route]]
match_host = "registry.npmjs.org"
mode = "tunnel"

[[route]]
match_host = "pypi.org"
mode = "tunnel"

[[route]]
match_host = "files.pythonhosted.org"
mode = "tunnel"

[[route]]
match_host = "huggingface.co"
mode = "tunnel"

[[route]]
match_host = "cdn-lfs.huggingface.co"
mode = "tunnel"

# Wildcards are supported.
[[route]]
match_host = "*.githubusercontent.com"
mode = "tunnel"

# Anything not matched is denied.
```

Secrets live in a separate file (`secrets.toml`) with 0600 perms:

```toml
anthropic_api_key = "sk-ant-..."
openai_api_key = "sk-..."
github_token = "ghp_..."
```

## CLI

```
redoubtful run -- <command> [args...]       Run a command in a sandbox
redoubtful run --config PATH -- <command>   Specify config
redoubtful run --network NAME -- <command>  Select a named network profile (v1.1+)
redoubtful check                            Validate config and check dependencies
redoubtful version
```

Focus v1 on `redoubtful run` and `redoubtful check`. Everything else later.

## Implementation notes

### Crate choices

- `clap` with `derive` for CLI parsing.
- `tokio` runtime.
- `hyper` 1.x for HTTP, or `hudsucker` as a higher-level MITM-proxy framework if its current API suits. (Hudsucker handles a lot of the CONNECT/MITM plumbing; evaluate whether its opinions fit.)
- `rustls` for TLS (client side, outbound).
- `rcgen` for CA and leaf cert generation.
- `serde` + `toml` for config.
- `nix` for any direct namespace or filesystem syscalls we need (probably just reading `/proc/$PID/ns/net` paths).
- `tracing` + `tracing-subscriber` for logging.

Avoid heavy async-ecosystem crates you won't use. The tool is small; keep the dep tree small.

### Startup sequence

1. Parse CLI and config.
2. Validate: bwrap and pasta are on `$PATH`; config is well-formed; secrets file exists and is 0600; project dir is writeable.
3. Create tempdir for this session (CA cert, any other runtime state).
4. Generate per-session CA keypair, write cert to tempdir.
5. Start credential proxy Tokio task, listening on `127.0.0.1:$PROXY_PORT`. Wait for it to be accepting connections.
6. Build pasta command line with `-T` flags for configured forward ports plus the proxy port.
7. Build bwrap command line with filesystem, env, and namespace args.
8. `pasta -- bwrap -- <user command>`. Wait for the child to exit.
9. On exit or signal: kill proxy task, remove tempdir, exit with the user command's exit code.

Use `--die-with-parent` on bwrap. Install signal handlers in the launcher that forward `SIGINT`/`SIGTERM` to the child process group and then clean up.

### The pasta invocation

```
pasta \
  --config-net \
  --no-map-gw \
  --no-dhcp --no-dhcpv6 --no-ra \
  -T <port>,<port>,<port> \
  -- <bwrap and everything after>
```

`--no-map-gw` prevents the sandbox from treating pasta's host-side address as a reachable gateway. The `--no-dhcp*` flags skip the dynamic configuration pasta doesn't need since we're using `--config-net`. Forward ports are comma-separated or repeated `-T` flags; comma-separated is cleaner.

### The bwrap invocation

Key flags:

- `--unshare-ipc --unshare-pid --unshare-user --unshare-uts --unshare-cgroup` — not `--unshare-all`, not `--unshare-net`.
- `--die-with-parent`
- `--new-session` (needed to protect against TIOCSTI out-of-sandbox command injection, per CVE-2017-5226)
- `--clearenv` followed by explicit `--setenv` for every variable we want. Don't inherit the host environment.
- `--chdir $PWD`
- All the `--ro-bind`, `--bind`, `--tmpfs`, `--symlink` mounts described above in argument order.

### The proxy internals

Structure roughly:

```rust
enum RouteMode {
    Mitm { injections: Vec<HeaderInjection> },
    Tunnel,
    Deny,
}

struct Route {
    host_pattern: HostPattern, // exact or glob
    mode: RouteMode,
}

enum HeaderInjection {
    Literal { name: String, value: String },
    FromSecret { header: String, secret_key: String },
    BasicAuth { username: String, password_secret_key: String },
}

async fn handle_connect(req: ConnectRequest, routes: Arc<Routes>, secrets: Arc<Secrets>, ca: Arc<Ca>) {
    let route = routes.find(&req.host);
    match route.mode {
        RouteMode::Mitm { .. } => mitm(req, route, secrets, ca).await,
        RouteMode::Tunnel => tunnel(req).await,
        RouteMode::Deny => deny_response(),
    }
}
```

MITM flow generates the leaf cert for the target host, does a `TlsAcceptor::accept` on the client stream, reads the HTTP request, applies injections to headers, opens a `rustls` outbound connection to the real host with the real CA chain, forwards request, streams response back. Cache leaf certs by hostname for the session.

Tunnel flow is just `tokio::io::copy_bidirectional` between the client stream and a TCP connection to the target.

HTTP/2 support is desirable; HTTP/1.1 is required. QUIC/HTTP/3 is explicitly not in scope.

### Logging

Structured logs via `tracing`. At least three levels the user cares about:

- `INFO`: sandbox lifecycle (starting, stopping), routes matched, credential injection events (host only, no secret values ever).
- `WARN`: blocked requests (host attempted, routes considered, nothing matched).
- `DEBUG`: per-request details, filesystem mount arguments, pasta invocation.

Log to stderr by default. Provide `--log-file` to redirect.

## Security properties v1 must preserve

1. **No host credentials appear inside the sandbox.** Not as env vars, not as files, not on disk. The only way the sandbox authenticates to anything is by making requests through the proxy.
2. **No host-side files outside the project directory and the configured read-only list are readable.** This is enforced by the mount layout, not by any policy layer the sandbox could subvert.
3. **No TCP destinations are reachable except forwarded host-loopback ports.** Enforced by pasta's port forwarding list plus the absence of any other route.
4. **No DNS resolution to arbitrary hosts.** The sandbox has no default route and no resolver pointing at anything public. Name resolution happens at the proxy, on the host side, only for hostnames the proxy is configured to handle.
5. **No ambient authority via shared host namespaces.** Fresh user, pid, ipc, uts, cgroup, mount namespaces. The sandbox sees itself as pid 1, has its own hostname if set, cannot see host processes.
6. **Cannot write to `.bashrc`, `.gitconfig`, or other shell/config files even in writable paths.** Bwrap's allowlist excludes these, following srt's pattern of hardcoded deny paths for defense in depth.

## Testing strategy

A suite of integration tests that run `redoubtful run` against known-dangerous commands and verify the expected outcome:

- `redoubtful run -- cat ~/.ssh/id_rsa` fails with "no such file."
- `redoubtful run -- curl http://10.0.0.1` fails with connection refused or similar.
- `redoubtful run -- curl http://127.0.0.1:22` fails (host's SSH is not reachable).
- `redoubtful run -- env | grep -i api_key` produces no output.
- `redoubtful run -- curl https://api.anthropic.com/v1/messages` with a minimal payload succeeds (proxy injected key).
- `redoubtful run -- git clone https://github.com/some/private-repo` succeeds without any visible token.
- `redoubtful run -- bash -c 'python -c "import socket; s=socket.socket(); s.bind((\"127.0.0.1\", 0)); print(s.getsockname())"'` succeeds with an ephemeral port.
- `redoubtful run -- bash -c 'echo evil >> ~/.bashrc'` fails.
- `redoubtful run -- cargo build` in a sample project succeeds (tunneled to crates.io).

These are the load-bearing guarantees. Each should be a test case.

## Out of scope for v1, to revisit

- Docker bridge attachment (the `--network name` feature).
- OS keychain integration for secrets (GNOME Keyring / KWallet / Secret Service).
- SOCKS5 for raw TCP to arbitrary hosts.
- macOS / Seatbelt support.
- A TUI or interactive config editor.
- Per-session state persistence beyond the project directory.
- A `redoubtful exec` mode that attaches to a running sandbox.
- Any form of multi-sandbox coordination.

## One-time user setup

```
sudo apt install bubblewrap passt    # or equivalent
cargo install redoubtful                    # or curl | sh from a release
mkdir -p ~/.config/redoubtful
cp /usr/share/redoubtful/config.toml.example ~/.config/redoubtful/config.toml
$EDITOR ~/.config/redoubtful/secrets.toml   # create with 0600 perms
```

Then:

```
cd ~/my-project
redoubtful run -- claude
```

## File layout of the source tree

```
redoubtful/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs              # entry point, CLI
│   ├── config.rs            # TOML parsing, validation
│   ├── secrets.rs           # secrets file loading
│   ├── launcher.rs          # bwrap + pasta orchestration
│   ├── proxy/
│   │   ├── mod.rs           # proxy task setup
│   │   ├── ca.rs            # CA and leaf cert generation
│   │   ├── routes.rs        # route matching
│   │   ├── mitm.rs          # MITM flow
│   │   └── tunnel.rs        # tunnel flow
│   ├── sandbox/
│   │   ├── mod.rs           # bwrap arg construction
│   │   ├── filesystem.rs    # mount arg generation
│   │   └── env.rs           # env var list
│   └── error.rs             # error types
├── examples/
│   └── config.toml          # shipped example config
└── tests/
    └── integration.rs       # end-to-end tests
```

## Build and distribution

- `cargo build --release --target x86_64-unknown-linux-musl` produces the static binary.
- Also target `aarch64-unknown-linux-musl` for ARM64 machines.
- CI builds both, publishes GitHub releases, includes SHA256 sums.
- No `cargo install` required for end users; download the binary from releases.

## Final notes for the implementer

- Keep the proxy code paths small and auditable. This is the piece handling credentials; it's worth being legible at the cost of some expressiveness.
- Resist the urge to add configuration knobs for things that aren't actually load-bearing. The config surface is already a lot; every optional flag is another thing to document, test, and maintain.
- The bwrap and pasta invocations are where bugs will live. Log the exact command lines at DEBUG level so users can reproduce them manually when something goes wrong.
- Ubuntu 24.04+ requires `kernel.apparmor_restrict_unprivileged_userns=0` or the bwrap-userns-restrict AppArmor profile. `redoubtful check` should detect this and tell the user what to do.
- Write the integration tests first-ish. The guarantees listed in the security properties section are what the tool *is*; everything else is implementation detail.
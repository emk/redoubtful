# Proxy Configuration Sketch

> **Status:** Human-written spec with Qwen3-written detailed plans. Supercedes `docs/ARCHITECTURE.md` and `docs/SECURITY_PHILOSOPHY.md`. Stage 1 complete; Stage 2 complete; Stage 3 complete. Stage 4 (credential injection) **partially implemented** — Phase 4.1 (HTTP-forward injection, no MITM) is done and green; Phase 4.2 (HTTPS MITM + CA trust) is planned. Stage 5 (E2E testing): the HTTP routing harness is implemented (pulled ahead of Stage 4, per `docs/proxy-testing-challenges.md`); HTTP-forward injection E2E is green; HTTPS injection E2E is still planned.
>
> **Revised phasing after review.** Work on the SSL/CA foundation *before* further HTTPS-side work. See "SSL foundation phasing" below for the updated order and the CA1+CA2 model.

## CLI Configuration

This allows limited control over the proxy configuration from the CLI.
Unlike other confioguration options, proxy configuration is  too complex
to fully expose via the CLI.

```
--public-web[=allow]            # On by default
--public-web=deny               # Optional
--proxy=example.net[=allow]     # HTTPS
--proxy=example.net=deny
--proxy=example.net:80[=allow]  # Non-standard port 
```

We may extend this later with more options.

## TOML Configuration

```toml
public-web = "allow"

[[proxies]]
host = "example.net"
port = 80
action = "allow"
```

### Credential injection

Place secrets into `~/.config/redoubtful/secrets.toml`, which is free-form TOML, but which is conventionally organized by site.

```toml
[example]
api-key = "fake"
username = "jdoe"
password = "password"
```

Just like we auto-create a sample `config.toml`, we will want to auto-create a sample `secrets.toml`.

Secrets can be inserted into the security-related configuration fields using Handlebars templating, where they will be mapped as `secrets`.

Custom headers:

```toml
headers = {
    "X-Api-Key" = "{{secrets.example.api-key}}"
}
```

URL parameters:

```toml
params = {
    "api_key" = "{{secrets.example.api-key}}"
}
```

As a shorter form, we have basic authorization:

```toml
auth = {
    username = "{{secrets.example.username}}"
    password = "{{secrets.example.password}}"
}
```

And bearer token authorization:

```toml
auth = {
    token = "{{secrets.example.token}}"
}
```

## Rust type

The Rust types should look like this (with any necessary corrections to make it work):

```rust
#[derive(Clone, Debug, Deserialize, clap::Args)]
pub struct ProxyDecls {
    #[serde(default)]
    pub public_web: Option<ProxyAction>,

    #[serde(default)]
    #[clap(long = "proxy", short = "p")]
    pub proxies: Vec<ProxyDecl>,
}

// We will probably need to create a ResolveContext type
// that gets passed to all Decl::resolve calls, to hold
// a Handlebars context.
// 
// impl Decl for ProxyDecls
// 
// base_config is just `public_web = Some(ProxyAction::Allow)`.
// 
// There are no "extra fields" needed here, actually, to get
// sensible merge_right_biased.

// `Proxies` looks like `ProxyDecls`, except `ProxyDecl` is replaced by `Proxy`.

impl Proxies {
    // Global check: do we need a proxy server process at all?
    pub fn is_proxy_server_needed(&self) -> bool {
        todo!()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProxyDecl {
    pub host: String,
    #[serde(default="https_port")]
    pub port: u16,
    #[serde(default)]
    pub action: ProxyAction,
    #[serde(default)]
    pub headers: BTreeMap<String, Template>,
    #[serde(default)]
    pub params: BTreeMap<String, Template>,
    #[serde(default)]
    pub auth: Option<ProxyAuth>,
    // No need for `mode`, etc. We can choose passthrough or MITM
    // based on whether we need to inject credentials.
}

// Parse the limited set of supported fields.
// impl FromStr for ProxyDecl

// Proxy mostly looks like ProxyDecl, except Template is
// replaced by Secret, and `ProxyAuthDecl` is replaced by `ProxyAuth`.

/// Handlebars template newtype.
pub type Template(String);

/// Secret newtype. Both `Debug` and `Display` should be overriden to
/// hide the secret value.
pub type Secret(String);

#[derive(Clone, Debug, Default, Deserialize)]
pub enum ProxyAction {
    #[default]
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ProxyAuthDecl {
    Basic { username: Template, password: Template },
    Bearer { token: Template },
}

// impl Decl for ProxyAuthDecl

#[derive(Clone, Debug)]
pub enum ProxyAuth {
    Basic { username: Secret, password: Secret },
    Bearer { token: Secret },
}

pub struct ResolveContext {
    // Handlebars stuff goes here.
}

impl ResolveContext {
    pub fn render_template(&self, template: &Template) -> Result<String> {
        todo!()
    }
}
```

### Credential file permissions (deferred hardening)

**Remembered:** `secrets.toml` holds real credentials at rest on the host,
but we currently do no enforcement of its file mode. Cheap, valuable
hardening — planned to land alongside Stage 4, since that is the first
stage that actually consumes secrets server-side:

- On `SecretsFile::load_or_init` (or a validate pass), check the file mode
  and refuse (or warn) if the file is group/world-readable (anything other
  than `0600`).
- chmod `0600` the file when we create it; warn when an existing file is
  too permissive.
- `config.toml` holds only templates, never plaintext secrets, so it does
  not need the same treatment.

This is deliberately *not* a password-manager/keyring story — our primary
use case is SSH into headless Linux, where keychains are limited. Revisit
in a future iteration if more than plaintext-on-disk is warranted.

## SSL foundation phasing (revised after review)

We bit off too much when we aimed at full MITM credential injection in one
pass: several prerequisites were missing, and the HTTPS side turns out to
sit on an unimplemented SSL foundation. Do the foundation *first*, in a
strict order, so each step is independently testable and lands green.

The two-phase split already in Stage 4 (4.1 HTTP-forward injection vs 4.2
HTTPS MITM) is right, but **4.1 is done** and 4.2 must wait on the SSL
work below — the HTTPS injection tests cannot green until the CA plumbing
exists.

### The CA1 + CA2 model

There are two independent certificate authorities in our world:

- **CA1** — *outside*, the test upstream's CA. In tests this is a
  dedicated `rcgen` test CA that signs the upstream's leaf, with the CA
  PEM kept as a test artifact. (Today the test upstream is a bare
  throwaway *self-signed* leaf with no CA; nothing can verify it except
  `curl -k`.) In production there is no CA1 — the "outside" CA1 is the
  real public web of trust.
- **CA2** — *inside*, the proxy's per-session MITM CA. The proxy signs
  leaf certs with CA2 for hosts it MITMs, and persists CA2's PEM to a
  temp file exposed via `ProxyHandle::ca_cert_path()`.

In test mode we set env vars (e.g. `SSL_CERT_FILE`) to point
`openssl-probe::probe()` at **CA1**, making CA1 masquerade as "the system
store" (it does not contain any real roots, which is fine and hermetic).
The proxy then appends its own **CA2** to the sandbox bundle.

### Which SSL context sees which roots

There are **two** trust legs, each deciding independently what to
verify against — keep them straight; they do not share one bundle:

| Leg | Who verifies | Trusts |
|-----|--------------|--------|
| **Sandbox leg** (curl, git inside sandbox) | sandboxed tools | merged bundle = `CA1` (as "system") + `CA2` appended |
| **Upstream-client leg** (proxy's own TLS client, used only when MITM-forwarding) | redoubtful itself | `CA1` (the upstream's CA) — does **not** need CA2 |

Consequences for the three request paths:

- **Passthrough / tunnel** (host without injection config, so
  `should_intercept` is false): the proxy pipes raw bytes. The sandboxed
  client does TLS *directly* with the upstream, and verifies the upstream's
  **CA1-issued** leaf against CA1 in the sandbox bundle. The proxy CA2 is
  never involved. (Today this is only why the tunnel tests use `curl -k`.)
- **MITM** (host with injection config, so `should_intercept` is true):
  the proxy terminates TLS and presents a **CA2**-signed leaf; the
  sandboxed client verifies against CA2 in the bundle. The proxy then
  reconnects to the upstream with its own client, which must verify the
  upstream against **CA1** — this is the `with_http_connector` + custom
  root-store work below.

### The two current sources of "CA truth" (the problem)

Today redoubtful has two *separate* trust stores that should be one:

1. **Sandbox leg**: `src/config/mounts.rs` ro-binds the whole host `/etc`
   into the sandbox, so sandboxed curl/git read the host's real
   `/etc/ssl/certs` bundle.
2. **Upstream-client leg**: `src/sandbox/proxy.rs` uses
   `.with_rustls_connector(...)` → `.with_webpki_roots()` — baked-in
   Mozilla roots, *not* the system store and *not* openssl-probe.

`docs/SSL_DESIGN.md` describes unifying them under `openssl-probe`, but
**that is unimplemented** (the doc's status is "Reference design notes").
This is the first prerequisite to build.

### Revised phasing order

1. **Single source of CA truth.** Make the proxy's upstream-client leg
   trust the same roots the sandbox sees, via `with_http_connector`
   (for `docs/SSL_DESIGN.md` reasons) + `openssl-probe`/custom root store
   (not `.with_webpki_roots()`). This is the pre-existing "discovered
   gap" the SSL design was written to close.
2. **An actual CA1.** Convert the test upstream from a bare self-signed
   leaf to a CA-issued leaf (dedicated `rcgen` test CA, PEM kept as a
   test artifact), and point the test environment's `openssl-probe` /
   `SSL_CERT_FILE` at CA1.
3. **Drop `-k` in the existing passthrough tests.** Only meaningful once
   the sandbox has proper certs (the CA1+CA2 bundle), so curl can verify
   against a real CA1-issued upstream. The tunnel tests carry a `// TODO`
   currently waiting on this.
4. **MITM** (`should_intercept` per-host: `allowed && has_injection_config`),+
   inject on the decrypted inner request, wire the per-session CA2 into
   the sandbox (bind-mount the merged CA1+CA2 bundle + set the CA env
   vars). *Then* the HTTPS injection tests go green.

### Known config bugs fixed while wiring the red test

Two real bugs surfaced while getting the HTTP-forward injection test
green — both worth remembering:

- **`ProxyAuthDecl` needed `#[serde(untagged)]`** for the TOML
  `auth = { token = "..." }` shape. It was in the plan but missing in
  code. Fixed in `src/config/proxy.rs` with deserialization unit tests.
- **TOML array-of-tables nesting:** `[[proxies]]` under `[profile.x]`
  attaches to the *top* level (rejected by `ConfigFile`, profile-only).
  Must use the full dotted path `[[profile.x.proxies]]`. Guarded with a
  unit test in `src/config/config_file.rs`.

## Plans for implementation stages

### Stage 1: Implement `ResolveContext` and thread through `ProxyDecl::resolve`

**Goal:** Add a `ResolveContext` parameter to the `Decl::resolve` signature so that
future `ProxyDecl::resolve` implementations can render Handlebars templates against
secrets loaded from `~/.config/redoubtful/secrets.toml`. This is a cross-cutting
infrastructure change that touches every `Decl` implementation.

#### Tricky issues identified

1. **Signature change is invasive.** `Decl::resolve(&self) -> Result<Self::Resolved>`
   is implemented in 6 modules and called in ~20+ places (including tests). Every
   call site must be updated. This is mechanical but wide-ranging.

2. **`secrets.toml` auto-init mirrors `config.toml`.** We already have the
   `load_or_init` pattern in `config_file.rs` — secrets need the same auto-create
   behavior with a sample file. But unlike `config.toml`, secrets are *not*
   profile-scoped; they are a single flat (or `[section]`) TOML table consumed
   by any proxy declaration anywhere.

3. **Handlebars missing-variable policy.** If `{{secrets.example.api-key}}`
   references a path that doesn't exist in `secrets.toml`, we must fail with a
   clear error — not silently render empty or crash inside the template engine.
   The handlebars-rust crate provides `set_strict_mode(true)` which raises a
   `RenderError` when a template accesses an undefined variable, which is
   exactly what we need.

4. **`ResolveContext` lives in `config/`.** Resolution happens during
   `Decl::resolve()`, after which the resolved output (plain `String`s) no
   longer needs the context. The context is only needed at config-resolution
   time, so it belongs alongside the other config logic in `config/`.

5. **Tests need a cheap context.** Many existing tests call `.resolve()` in
   isolation without needing secrets. We need `ResolveContext::empty()` for
   tests so they don't depend on the secrets file existing on disk.

#### Step 1: Add `handlebars` dependency

**File:** `Cargo.toml`

```sh
cargo add handlebars
```

`serde` is already a dependency (needed for handlebars' JSON value types).

#### Step 2: Create `src/config/resolve_context.rs` (new module)

**File:** `src/config/resolve_context.rs` (new)

```
ResolveContext
├── registry: handlebars::Handlebars<'static>   // pre-warmed template engine
└── render_template(&self, template: &str) -> Result<String>
```

Key design decisions:

- **Pre-warmed Handlebars registry.** The registry is constructed once in
  `ResolveContext::new()` with secrets registered under the `"secrets"` key.
  Template rendering is just `registry.render_template(tmpl, &ctx)` — no per-call
  setup.

- **Strict mode enabled.** `registry.set_strict_mode(true)` ensures that
  accessing an undefined variable (e.g. `{{secrets.foo.bar}}` where the path
  doesn't exist in `secrets.toml`) raises a `RenderError` instead of silently
  rendering an empty string.

- **`render_template` returns `Result<String>`.** The strict mode error is
  propagated through `Result` to the caller.

- **`ResolveContext::empty()` for tests.** Constructs a context with an empty
  secrets map. Tests that don't exercise template rendering can use this.

- **`ResolveContext::new()` for production.** Loads secrets from the XDG path,
  auto-inits the file if missing, and builds the handlebars registry.

#### Step 3: Implement `secrets.toml` loading with auto-init

**File:** `src/config/resolve_context.rs`

```
const DEFAULT_SECRETS: &str = include_str!("../../assets/secrets.toml.default");

fn load_or_init_secrets(path: &Path) -> Result<serde_json::Value>
```

- Auto-init writes a sample `secrets.toml.default` (with comments and
  placeholder values) on first run, mirroring the `config.toml` pattern.
- Loading parses as `toml::Value` (free-form), then converts to
  `serde_json::Value` that handlebars can consume.
- TOML sections like `[example] api-key = "x"` become JSON
  `{ "example": { "api-key": "x" } }` — handlebars dot-notation
  (`{{secrets.example.api-key}}`) works natively.
- If the file doesn't exist (after auto-init), we return an empty JSON object.

**New file:** `assets/secrets.toml.default`

```
# redoubtful secrets — credentials for proxy configuration.
#
# This file lives at ~/.config/redoubtful/secrets.toml. It was
# auto-generated on first run; edit it freely. Do not commit this
# file to version control.
#
# Secrets are referenced in proxy configuration using Handlebars
# templating: {{secrets.<section>.<key>}}
#
# Example:
#
# [github]
# token = "ghp_..."
#
# Then in config.toml:
#   [[proxies]]
#   host = "api.github.com"
#   auth = { token = "{{secrets.github.token}}" }
```

**File:** `src/errors.rs` — add error variants:

```rust
#[error("could not read secrets file `{}`", path.display())]
CouldNotReadSecrets {
    path: PathBuf,
    #[source]
    source: io::Error,
}

#[error("could not parse secrets file `{}`", path.display())]
CouldNotParseSecrets {
    path: PathBuf,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

#[error("template error: {message}")]
TemplateRender {
    message: String,
}
```

#### Step 4: Change the `Decl` trait signature

**File:** `src/config/mod.rs`

Add the submodule declaration and import:

```rust
pub mod resolve_context;

// In the Decl trait:
```

```rust
// Before:
pub trait Decl {
    type Resolved;
    fn validate(&self) -> Result<()>;
    fn resolve(&self) -> Result<Self::Resolved>;
}

// After:
pub trait Decl {
    type Resolved;
    fn validate(&self) -> Result<()>;
    fn resolve(
        &self,
        ctx: &self::resolve_context::ResolveContext,
    ) -> Result<Self::Resolved>;
}
```

#### Step 5: Update all 7 `impl Decl` blocks

Each impl must accept the `ctx` parameter. For leaf types, it's unused.
For container types, it's threaded to inner `resolve()` calls.

| File | Type | Leaf or Container |
|------|------|-------------------|
| `src/config/env_var.rs` | `EnvVarDecl` | leaf — `_ctx` |
| `src/config/env_vars.rs` | `EnvVarDecls` | container — thread to `decl.resolve(ctx)` |
| `src/config/mount.rs` | `MountDecl` | leaf — `_ctx` |
| `src/config/mounts.rs` | `MountDecls` | container — thread to `d.resolve(ctx)` |
| `src/config/forward.rs` | `ForwardDecl` | leaf — `_ctx` |
| `src/config/forwards.rs` | `ForwardDecls` | container — thread to `d.resolve(ctx)` |
| `src/config/profile.rs` | `ProfileDecl` | container — thread to all 3 sub-decls |

Leaf change pattern:
```rust
fn resolve(&self, _ctx: &crate::config::resolve_context::ResolveContext) -> Result<Self::Resolved> {
    // unchanged body
}
```

Container change pattern:
```rust
fn resolve(&self, ctx: &crate::config::resolve_context::ResolveContext) -> Result<Self::Resolved> {
    let mounts = self.mounts.iter().map(|d| d.resolve(ctx)).collect()?;
    // ...
}
```

#### Step 6: Update `ConfigFile::finalize_config_with_cli` signature

**File:** `src/config/config_file.rs`

The entry point must accept the context and pass it through:

```rust
// Before:
pub fn finalize_config_with_cli(cli: &ProfileDecl) -> Result<Profile> {
    // ...
    chain.push(decl.resolve()?);
    chain.push(cli.resolve()?);
    // ...
}

// After:
pub fn finalize_config_with_cli(
    cli: &ProfileDecl,
    ctx: &crate::config::resolve_context::ResolveContext,
) -> Result<Profile> {
    // ...
    chain.push(decl.resolve(ctx)?);
    chain.push(cli.resolve(ctx)?);
    // ...
}
```

#### Step 7: Update `cmd_run` and `cmd_show` call sites

**File:** `src/cmd/run.rs`

```rust
// Before:
let user_profile = ConfigFile::finalize_config_with_cli(&profile)?;

// After:
use crate::config::resolve_context::ResolveContext;
let ctx = ResolveContext::new()?;
let user_profile = ConfigFile::finalize_config_with_cli(&profile, &ctx)?;
```

**File:** `src/cmd/show.rs`

Same change — construct context, pass to `finalize_config_with_cli`.
`show` doesn't need secrets, but constructing the context is cheap
and keeps the API uniform.

#### Step 8: Update all test call sites

Tests that call `.resolve()` directly (roughly 15 test functions across
6 files) must pass a context. Add a test helper:

**Approach:** `ResolveContext::empty()` returns a context with zero
secrets. All existing tests use this — none of them exercise template
rendering.

In each test module, construct the context once (or per-test — it's
cheap):

```rust
let ctx = crate::config::resolve_context::ResolveContext::empty();
let resolved = decl.resolve(&ctx).expect("resolves");
```

Tests affected:

| File | ~test count |
|------|------------|
| `src/config/env_var.rs` | 2 |
| `src/config/env_vars.rs` | 3 |
| `src/config/forward.rs` | 1 |
| `src/config/forwards.rs` | 1 |
| `src/config/mount.rs` | 1 |
| `src/config/mounts.rs` | 2 |
| `src/config/profile.rs` | 4 |

#### Step 9: Wire module into crate

**File:** `src/config/mod.rs`

Add submodule declaration (alongside the other `pub mod` declarations):
```rust
pub mod resolve_context;
```

#### Step 10: Verify with `just check`

Run `just check` (which runs `cargo check` and presumably `cargo test`).
All existing tests should pass unchanged in behavior — the context
parameter is new but existing types don't use it.

#### Summary of files touched

| File | Action |
|------|-------|
| `Cargo.toml` | Add `handlebars` dependency |
| `src/config/mod.rs` | Add `pub mod resolve_context` + change `Decl::resolve` signature |
| `src/config/resolve_context.rs` | **New** — ResolveContext, secrets loading, auto-init |
| `assets/secrets.toml.default` | **New** — Sample secrets file |
| `src/errors.rs` | Add 3 error variants |
| `src/config/mod.rs` | Change `Decl::resolve` signature |
| `src/config/env_var.rs` | Update `impl Decl for EnvVarDecl` |
| `src/config/env_vars.rs` | Update `impl Decl for EnvVarDecls` + tests |
| `src/config/mount.rs` | Update `impl Decl for MountDecl` + tests |
| `src/config/mounts.rs` | Update `impl Decl for MountDecls` + tests |
| `src/config/forward.rs` | Update `impl Decl for ForwardDecl` + tests |
| `src/config/forwards.rs` | Update `impl Decl for ForwardDecls` + tests |
| `src/config/profile.rs` | Update `impl Decl for ProfileDecl` + tests |
| `src/config/config_file.rs` | Update `finalize_config_with_cli` + tests |
| `src/cmd/run.rs` | Construct context, pass to `finalize_config_with_cli` |
| `src/cmd/show.rs` | Construct context, pass to `finalize_config_with_cli` |

**Total: ~16 files (2 new, 14 modified).**

**Expected risk level:** Low — purely mechanical signature change with
no behavior change to existing types. The new functionality (template
rendering) is not exercised until Stage 2.

### Stage 2: Implement and unit test new config types

**Goal:** Add the proxy configuration types (`ProxyAction`, `Template`, `Secret`,
`ProxyAuthDecl`/`ProxyAuth`, `ProxyDecl`/`Proxy`, `ProxyDecls`/`Proxies`) with
full `Decl`, `Finalize`, and (for `ProxyDecl`) `FromStr` implementations, plus
unit tests for each. Wire `ProxyDecls` into `ProfileDecl` so proxy declarations
flow through the existing config pipeline (TOML profile + CLI merge).

This stage does **not** touch the proxy server runtime — that's Stage 3.

#### Tricky issues identified

1. **`--proxy` CLI syntax is compact but unambiguous.** The spec supports
   `--proxy=example.net[=allow]`. The `=` separator is chosen because hostnames
   and URLs never contain bare `=` outside of query strings (which we don't
   support in this compact form). The `FromStr` parser must handle the `:` for
   non-standard ports: `--proxy=example.net:80=deny`. We parse `HOST[:PORT][=ACTION]`.

2. **`Template` needs `Deserialize` as a newtype around `String`.** Headers and
   params are `BTreeMap<String, Template>`. `Template` is a simple wrapper
   (`pub struct Template(pub String)`) that derives `Deserialize` — serde
   handles the newtype automatically for single-field wrappers.

3. **`Secret` needs custom `Debug` and `Display`.** Both must redact the
   value (e.g. `Secret("***")`) so secrets never leak in diagnostic output or
   `show` JSON output. `serde::Serialize` also needs overriding to redact.

4. **`ProxyAuthDecl` uses `#[serde(untagged)]` enum.** The TOML shape `{ token = "..." }`
   vs `{ username = "...", password = "..." }` requires untagged deserialization
   so the variant is inferred from which keys are present. This matches the
   spec's `auth = { token = "{{secrets.github.token}}" }` and
   `auth = { username = "...", password = "..." }` forms.

5. **`Proxies::is_proxy_server_needed` is a global check.** It controls
   whether we spawn a proxy server process at all — not per-destination.
   It returns `true` if `public_web` is `Allow` (public web traffic flows
   through the proxy) or if any proxy entry is explicitly `Allow`
   (when `public_web` is `Deny`). No per-host logic; that's the proxy
   server's job once running.

6. **`ProxyDecl::resolve` renders Handlebars templates.** The `headers`, `params`,
   and `auth` fields contain `Template` values that must be rendered against
   `ResolveContext` to produce `Secret` values. This is the first Decl type
   that actually uses `ctx.render_template()` — all existing types pass `_ctx`.

7. **`Proxies::merge_right_biased` needs deduplication by host.** When merging
   two proxy lists, if the same host appears in both, the right-hand proxy
   replaces the left (right-biased). We use `BTreeMap<String, Proxy>`
   (like `EnvVars`) for deterministic ordering and natural key-based dedup.

#### Step 1: Create `src/config/proxy.rs` (new module)

**File:** `src/config/proxy.rs` (new)

```
proxy.rs
├── ProxyAction (enum: Allow [default], Deny)
├── ProxyAuthDecl (enum: Basic { username, password }, Bearer { token })
├── ProxyAuth (enum: Basic { username, password }, Bearer { token })
├── ProxyDecl (struct: host, port, action, headers, params, auth)
│   ├── FromStr for CLI parsing
│   └── Decl impl (resolve: renders templates → Proxy)
└── Proxy (struct: host, port, action, headers, params, auth)
```

**Template** and **Secret** live in `src/config/mod.rs` alongside the `Decl`
and `Finalize` traits — they're small, standalone newtypes that don't depend
on anything in `proxy.rs`, and `Secret`'s redacting `Debug`/`Display`/
`Serialize` may be useful for other config domains in the future.

**Template** (in `src/config/mod.rs`):

```rust
/// A Handlebars template string, unresolved.
///
/// Carried in `ProxyDecl.headers`, `ProxyDecl.params`, and
/// `ProxyAuthDecl` fields. Resolved to `Secret` via
/// `ResolveContext::render_template` during `Decl::resolve`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Template(pub String);
```

**Secret** (in `src/config/mod.rs`):

```rust
/// A resolved secret string.
///
/// `Debug`, `Display`, and `Serialize` all redact the value to
/// `"***"` so secrets never appear in logs, diagnostics, or
/// `redoubtful show --json` output.
#[derive(Clone)]
pub struct Secret(pub String);

impl Debug for Secret { /* "Secret(\"***\")" */ }
impl Display for Secret { /* "***" */ }
impl Serialize for Secret { /* "***" */ }
```

**ProxyAction:**

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyAction {
    #[default]
    Allow,
    Deny,
}

impl FromStr for ProxyAction { /* parse "allow"/"deny" */ }
```

**ProxyAuthDecl:**

```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProxyAuthDecl {
    Basic {
        username: Template,
        password: Template,
    },
    Bearer { token: Template },
}
```

**ProxyAuth:**

```rust
#[derive(Debug, Clone)]
pub enum ProxyAuth {
    Basic { username: Secret, password: Secret },
    Bearer { token: Secret },
}
```

**ProxyDecl:**

```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyDecl {
    pub host: String,
    #[serde(default = "https_port")]
    pub port: u16,
    #[serde(default)]
    pub action: ProxyAction,
    #[serde(default)]
    pub headers: BTreeMap<String, Template>,
    #[serde(default)]
    pub params: BTreeMap<String, Template>,
    #[serde(default)]
    pub auth: Option<ProxyAuthDecl>,
}
```

Where `https_port()` returns `443`.

**FromStr for ProxyDecl** — parse `HOST[:PORT][=ACTION]`:

- Split on `=` (max 2 parts): left is `HOST[:PORT]`, right is action.
- Split left on `:` (max 2 parts): host, optional port.
- If action absent, default to `Allow`.
- If port absent, default to `443` (resolved in `Decl::resolve`).
- Reject empty host, invalid port numbers.

**Decl impl for ProxyDecl** — the first Decl that uses `ctx`:

```rust
fn resolve(&self, ctx: &ResolveContext) -> Result<Proxy> {
    let headers = self.headers.iter()
        .map(|(k, v)| Ok((k.clone(), Secret(ctx.render_template(&v.0)?))))
        .collect::<Result<BTreeMap<_>>>()?;
    // same for params, auth
    Ok(Proxy { host, port, action, headers, params, auth })
}
```

**Proxy** — the resolved form:

```rust
#[derive(Debug, Clone)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    pub action: ProxyAction,
    pub headers: BTreeMap<String, Secret>,
    pub params: BTreeMap<String, Secret>,
    pub auth: Option<ProxyAuth>,
}
```

**Tests for `proxy.rs`:**

| Test | Covers |
|------|--------|
| `proxy_decl_fromstr_host_only` | `"example.net"` → host, port=443, Allow |
| `proxy_decl_fromstr_host_port` | `"example.net:80"` → host, port=80, Allow |
| `proxy_decl_fromstr_host_action` | `"example.net=deny"` → host, port=443, Deny |
| `proxy_decl_fromstr_full` | `"example.net:80=deny"` → all fields |
| `proxy_decl_fromstr_rejects_empty_host` | `"=allow"` → error |
| `proxy_decl_fromstr_rejects_bad_port` | `"example.net:abc"` → error |
| `proxy_decl_fromstr_rejects_bad_action` | `"example.net=wat"` → error |
| `proxy_decl_fromstr_rejects_multiple_equals` | `"a=b=c"` → error |
| `proxy_decl_resolve_no_templates` | Plain values pass through without ctx |
| `proxy_decl_resolve_renders_templates` | `{{secrets.x.y}}` → rendered Secret |
| `proxy_decl_resolve_renders_auth_basic` | Basic auth templates resolved |
| `proxy_decl_resolve_renders_auth_bearer` | Bearer token template resolved |
| `proxy_decl_resolve_missing_secret_errors` | Strict mode: undefined variable → TemplateRender error |
| `secret_debug_redacts` | `Debug` shows `"***"` |
| `secret_display_redacts` | `Display` shows `"***"` |
| `secret_serialize_redacts` | JSON output shows `"***"` |

#### Step 2: Create `src/config/proxies.rs` (new module)

**File:** `src/config/proxies.rs` (new)

```
proxies.rs
├── ProxyDecls (struct: public_web, proxies)
│   ├── clap::Args (for CLI: --public-web, --proxy)
│   ├── Deserialize (for TOML)
│   └── Decl impl (resolve → Proxies)
├── Proxies (struct: public_web, proxies)
│   ├── Finalize impl
│   └── is_proxy_server_needed(&self) -> bool
└── https_port() default function (shared with proxy.rs)
```

**ProxyDecls:**

```rust
#[derive(Debug, Clone, Default, clap::Args, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyDecls {
    #[arg(long = "public-web", num_args = 0..=1, default_missing_value = "allow")]
    #[serde(default)]
    pub public_web: Option<ProxyAction>,

    #[arg(short = 'p', long = "proxy", value_name = "HOST[:PORT][=ACTION]")]
    #[serde(default, rename = "proxies")]
    pub proxies: Vec<ProxyDecl>,
}
```

**Proxies:**

**Proxies:**

```rust
#[derive(Debug, Clone)]
pub struct Proxies {
    /// Whether public web access is allowed. After resolution this is
    /// always set — `base_config` sets the `Allow` default and
    /// `merge_right_biased` preserves it.
    pub public_web: ProxyAction,
    /// Proxy entries keyed by host. `BTreeMap` for deterministic ordering
    /// and natural key-based dedup in `merge_right_biased` (like `EnvVars`).
    proxies: BTreeMap<String, Proxy>,
}
```

`ProxyDecls.public_web` is `Option<ProxyAction>` (user may omit it), but the
resolved `Proxies.public_web` is plain `ProxyAction` — the resolution step
fills in the `Allow` default, so downstream consumers never need `.unwrap_or()`.

**Finalize impl for Proxies:**

- `merge_right_biased`: merge `proxies` BTreeMap by key (right wins),
  `public_web` is direct replacement (right wins; no `Option` on the
  resolved type).
- `base_config`: `public_web = ProxyAction::Allow`, empty proxies.
- `Default`: `public_web = ProxyAction::Allow`, empty proxies (needed for
  `Finalize` trait bound).

**is_proxy_server_needed:**

This is a global check — it controls whether we spawn a proxy server
process at all. It returns `true` when any outbound traffic would pass
through the proxy:

```rust
pub fn is_proxy_server_needed(&self) -> bool {
    // If public web is allowed, we need a proxy for public traffic.
    if self.public_web == ProxyAction::Allow {
        return true;
    }
    // If public web is denied, check if any proxy is explicitly allowed.
    self.proxies.values().any(|p| p.action == ProxyAction::Allow)
}
```

- `public_web == Allow` → always need a proxy (public web traffic flows
  through it, possibly with credential injection on known hosts).
- `public_web == Deny` → need a proxy only if some proxy entry is
  explicitly `Allow` (otherwise there's nowhere for traffic to go).

**Tests for `proxies.rs`:**

| Test | Covers |
|------|--------|
| `proxy_decls_default_is_empty` | Default has None public_web, empty proxies |
| `proxy_decls_resolve_yields_proxies` | Resolved proxies with public_web |
| `proxies_base_config_defaults_public_web_allow` | Base config sets Allow |
| `proxies_merge_right_biased_deduplicates_by_host` | Same host: right wins |
| `proxies_merge_right_biased_concatenates_different_hosts` | Different hosts: both present |
| `is_proxy_server_needed_public_web_allow_returns_true` | public_web=Allow → true |
| `is_proxy_server_needed_public_web_deny_no_proxies_returns_false` | Deny + no proxies → false |
| `is_proxy_server_needed_public_web_deny_with_allowed_proxy_returns_true` | Deny + one allowed proxy → true |
| `is_proxy_server_needed_public_web_deny_all_deny_returns_false` | Deny + all proxies deny → false |

#### Step 3: Add error variants to `src/errors.rs`

```rust
#[error("proxy host is empty")]
ProxyEmptyHost,

#[error("proxy port `{port}` is not a valid port number")]
ProxyInvalidPort { port: String },

#[error("proxy action `{action}` is invalid (expected `allow` or `deny`)")]
ProxyInvalidAction { action: String },
```

#### Step 4: Wire `ProxyDecls` into `ProfileDecl`

**File:** `src/config/profile.rs`

Add `proxy_decls: ProxyDecls` field to `ProfileDecl` (flattened via `#[clap(flatten)]`).
Update the `Raw` struct in the hand-written `Deserialize` impl to include
`public_web` and `proxies` keys.

Update `impl Decl for ProfileDecl` to resolve `proxy_decls` and include
`Proxies` in the `Profile` resolved type.

Update `Profile` struct to include `proxies: Proxies`.

Update `impl Finalize for Profile` to delegate to proxies.

**File:** `src/config/mod.rs` — add `pub mod proxy;` and `pub mod proxies;`.

#### Step 5: Update existing tests

- `ProfileDecl` tests that construct the struct manually must include
  `proxy_decls: ProxyDecls::default()`.
- `Profile` tests must include `proxies: Proxies::default()`.
- `ProfileDecl::normalize_config_paths` doesn't delegate to proxies
  (no paths to normalize in proxy specs).
- `ProfileDecl::validate` delegates to `proxy_decls.validate()`.

#### Summary of files touched

| File | Action |
|------|-------|
| `src/config/mod.rs` | Add `pub mod proxy`, `pub mod proxies`, `Template`, `Secret` |
| `src/config/proxy.rs` | **New** — ProxyAction, ProxyAuthDecl/Auth, ProxyDecl/Proxy |
| `src/config/proxies.rs` | **New** — ProxyDecls, Proxies, Finalize, is_proxy_server_needed |
| `src/errors.rs` | Add 3 proxy error variants |
| `src/config/profile.rs` | Add `proxy_decls` field, update Raw, Decl, Profile, Finalize |
| `src/config/config_file.rs` | No change (pipeline is already generic via Decl/Finalize) |
| `src/cmd/run.rs` | No change (Profile now has `.proxies` available) |
| `src/cmd/show.rs` | No change (Profile now has `.proxies` available) |

**Total: ~7 files (2 new, 5 modified).**

**Expected risk level:** Low — new types are additive to the existing
config pipeline. The `ProfileDecl` and `Profile` changes are mechanical
(one new field per struct, one new delegate per impl). The `FromStr`
parser for `ProxyDecl` and the `ctx.render_template()` usage in
`ProxyDecl::resolve` are the only non-mechanical new code, and both
are heavily unit-tested.

**Test coverage target:** 100% of the new types' public behavior.
Every variant of `ProxyAction`, every branch of `FromStr`, every
field of `ProxyDecl::resolve` (including the Handlebars rendering
path), and every behavior of `Proxies::is_proxy_server_needed` and
`Proxies::merge_right_biased` has a dedicated test case.

**Integration with Stage 3:** Stage 3 will consume `Proxies` from the
resolved `Profile` and configure the proxy server accordingly. The
`is_proxy_server_needed` method is the primary interface — it tells
the proxy layer whether to intercept a given destination. The `Proxy`
struct's `headers`, `params`, and `auth` fields carry the credential
injection data needed by the proxy server's request rewriting logic.

### Stage 3: Modify proxy server to support passthrough config

**Scope:** Allow/deny routing based on `Proxies` config. Credential injection (headers, params, auth) deferred to Stage 4.

#### Key design decisions

1. **`start_proxy` takes `&Proxies`.** Signature becomes `async fn start_proxy(proxies: &Proxies) -> Result<ProxyHandle>`. It clones the `Proxies`, wraps the clone in `Arc`, and passes the `Arc` to the handler. `ProxyHandle` stays thin — no structural changes needed.

2. **Deny via HTTP 403 after CONNECT.** Hudsucker's `should_intercept` controls MITM, not allow/deny. When `should_intercept` returns `false`, hudsucker tunnels the connection regardless. To deny a destination: return `true` from `should_intercept` (so we intercept), then in `handle_request` return an HTTP 403 response with a descriptive body and `Via` header. This matches real-world proxy convention: `200 Connection established` on CONNECT, then the actual request fails with 403.

3. **Case-insensitive hostname matching.** `Proxies` is keyed by normalized hostname. A new `src/hostname.rs` module provides `normalize_hostname` (downcase for now, extensible for future security-related normalization). Called during `ProxyDecl::resolve` to normalize stored keys, and in the handler when looking up the target host.

4. **`Arc<Proxies>` in the handler.** `TunnelOnlyHandler` becomes a small struct holding `Arc<Proxies>` (and `Arc<normalize_hostname>` if needed, or just a function reference). Hudsucker clones the handler per connection — cloning `Arc` is cheap.

5. **`public_web` deny semantics.** When `public_web = Deny`, any host not explicitly in the proxy map is denied (same 403 path as above). When `public_web = Allow`, unknown hosts pass through as tunnels.

6. **HTTP vs HTTPS — TBD.** Hudsucker calls itself an HTTP/S proxy and `handle_request` says "called for each HTTP request." We set both `HTTP_PROXY` and `HTTPS_PROXY` in the sandbox. We assume for now that hudsucker handles plain HTTP requests similarly (routed through the same handler), but **this needs investigation** — may require distinguishing CONNECT targets from Host-header-based routing in `handle_request`.

#### Step 1: Create `src/hostname.rs` (new module)

**File:** `src/hostname.rs` (new)

```rust
/// Normalize a hostname for use as a proxy key.
///
/// Currently just lowercases the string. Extensible for future
/// security-related normalization (IDN punycode, trailing dots,
/// etc.) without changing the public API or all call sites.
pub fn normalize_hostname(host: &str) -> String {
    host.to_lowercase()
}
```

**Tests:**

| Test | Covers |
|------|--------|
| `normalize_lowercase` | `"Example.Net"` → `"example.net"` |
| `normalize_already_lowercase` | `"example.net"` → `"example.net"` (no-op) |
| `normalize_mixed_case` | `"GITHUB.COM"` → `"github.com"` |
| `normalize_with_port_stripped` | Caller's responsibility — this function does NOT strip ports |

**File:** `src/lib.rs` — add `pub mod hostname;`.

#### Step 2: Normalize hostnames in `ProxyDecl::resolve`

**File:** `src/config/proxy.rs`

In `impl Decl for ProxyDecl`, call `normalize_hostname` on `self.host`
before storing in `Proxy`. This ensures all keys in the `Proxies`
`BTreeMap` are lowercase.

```rust
// In ProxyDecl::resolve:
fn resolve(&self, ctx: &ResolveContext) -> Result<Self::Resolved> {
    // ... existing template resolution ...
    Ok(Proxy {
        host: crate::hostname::normalize_hostname(&self.host),
        // ... rest unchanged ...
    })
}
```

**Tests in `src/config/proxy.rs`:** Update existing tests that assert
on `proxy.host` to expect lowercase. Add one explicit test:

| Test | Covers |
|------|--------|
| `proxy_decl_resolve_normalizes_host_case` | `"Example.Net"` → `"example.net"` in resolved `Proxy` |

**Tests in `src/config/proxies.rs`:** Tests that construct `Proxy`
manually already use lowercase hosts — no change needed. Tests that
construct `ProxyDecl` then resolve should verify normalization.

#### Step 3: Add `Proxies::get` for host lookup

**File:** `src/config/proxies.rs`

`proxies` field is currently private. Add a `get` method so the
handler can look up a host:

```rust
/// Look up the proxy entry for a (presumably already-normalized)
/// hostname. Returns `None` if the host is not explicitly configured.
pub fn get(&self, host: &str) -> Option<&Proxy> {
    self.proxies.get(host)
}
```

Also add a `public_web` accessor that returns `ProxyAction` directly
(rather than `Result<ProxyAction>`), since after finalization it's
always `Some`. Or keep the existing `Result` API — either is fine.

**Tests:**

| Test | Covers |
|------|--------|
| `proxies_get_existing_host` | `get("example.net")` returns `Some` |
| `proxies_get_missing_host` | `get("unknown.net")` returns `None` |
| `proxies_get_case_sensitive` | `get("Example.Net")` returns `None` (caller must normalize) |

#### Step 4: Replace `TunnelOnlyHandler` with `PassthroughHandler`

**File:** `src/sandbox/proxy.rs`

The current `TunnelOnlyHandler` is a unit struct that always returns
`false` from `should_intercept`. Replace it with a handler that:
- Holds `Arc<Proxies>`
- In `should_intercept`, checks allow/deny and returns `true` for
  denied hosts (so `handle_request` is called)
- In `handle_request`, returns an HTTP 403 for denied hosts

```rust
use std::sync::Arc;

use crate::{
    hostname::normalize_hostname,
    config::proxies::Proxies,
};

/// Proxy handler that enforces allow/deny rules from the
/// [`Proxies`] config.
///
/// Allowed hosts: `should_intercept` returns `false` → pure CONNECT
/// tunnel, raw bytes piped end-to-end (no MITM).
///
/// Denied hosts: `should_intercept` returns `true` → hudsucker
/// intercepts the CONNECT, `handle_request` returns HTTP 403.
/// The client sees `200 Connection established` on CONNECT, then
/// the actual HTTP request fails with 403.
///
/// Credential injection (headers, params, auth) is deferred to
/// Stage 4 — allowed hosts always tunnel in this stage.
#[derive(Clone)]
struct PassthroughHandler {
    proxies: Arc<Proxies>,
}

impl HttpHandler for PassthroughHandler {
    /// Decide whether to intercept (MITM) or tunnel.
    ///
    /// - Denied host → intercept (so we can return 403)
    /// - Allowed host → tunnel (raw bytes, no interception)
    async fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        req: &Request<Body>,
    ) -> bool {
        let host = match req.uri().host() {
            Some(h) => normalize_hostname(h),
            None => return true, // no host → intercept and deny
        };

        match self.proxies.get(&host) {
            Some(proxy) => {
                // Explicitly configured host: deny if action is Deny
                proxy.action == crate::config::proxy::ProxyAction::Deny
            }
            None => {
                // Not in explicit list: follow public_web default
                match self.proxies.public_web() {
                    Ok(crate::config::proxy::ProxyAction::Allow) => false,
                    Ok(crate::config::proxy::ProxyAction::Deny) => true,
                    Err(_) => true, // safety: unknown state → deny
                }
            }
        }
    }

    /// Return HTTP 403 for denied hosts.
    ///
    /// This is only called when `should_intercept` returned `true`.
    /// At this point the CONNECT tunnel has been established (`200
    /// Connection established`), but the actual HTTP request is
    /// blocked here.
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> hudsucker::RequestOrResponse {
        let host = req.uri().host().unwrap_or("unknown");
        trace!(host, "denied request");

        let response = hyper::Response::builder()
            .status(hyper::StatusCode::FORBIDDEN)
            .header("Via", "1.1 redoubtful-proxy")
            .body(Body::from(format!(
                "Access to {} is denied by redoubtful proxy configuration.\n",
                host
            )))
            .expect("403 response builds");

        hudsucker::RequestOrResponse::Response(response)
    }
}
```

**Design notes:**

- `req.uri().host()` extracts the target hostname from the request URI.
  For CONNECT requests, this is the `CONNECT host:port` authority. For
  intercepted HTTPS, this is the `Host` header / URI authority.
- If `host()` returns `None` (malformed URI), we intercept and deny
  as a safety default.
- `normalize_hostname` is called on the request host before lookup,
  matching the normalization applied during `ProxyDecl::resolve`.
- The `handle_request` default impl returns `RequestOrResponse::Request`
  (forward to upstream). We override it to return `Response` (short-circuit)
  for denied requests.
- `trace!` for denied requests helps diagnose allow/deny decisions.

#### Step 5: Update `start_proxy` to accept `&Proxies`

**File:** `src/sandbox/proxy.rs`

Change the signature:

```rust
// Before:
pub async fn start_proxy() -> Result<ProxyHandle>

// After:
pub async fn start_proxy(proxies: &Proxies) -> Result<ProxyHandle>
```

Inside `start_proxy`, clone and wrap in `Arc`:

```rust
let proxies = Arc::new(proxies.clone());

let proxy = Proxy::builder()
    // ... unchanged ...  
    .with_http_handler(PassthroughHandler {
        proxies: proxies.clone(),
    })
    // ... unchanged ...
```

#### Step 6: Update `cmd_run` call site

**File:** `src/cmd/run.rs`

Pass `&user_profile.proxies` to `start_proxy`:

```rust
// Before:
let proxy_handle = start_proxy().await?;

// After:
let proxy_handle = start_proxy(&user_profile.proxies).await?;
```

Remove the `proxies: _` dead-code discard:

```rust
// Before:
let Profile {
    mounts,
    forwards,
    env,
    proxies: _,
} = profile_with_proxy;

// After:
let Profile {
    mounts,
    forwards,
    env,
    proxies: _proxies, // passed to start_proxy above
} = profile_with_proxy;
```

Or better, don't destructure `proxies` at all since it's only used
for `start_proxy`:

```rust
let Profile {
    mounts,
    forwards,
    env,
    ..
} = profile_with_proxy;
```

#### Step 7: Update `proxy_profile` (no change needed)

`proxy_profile` returns a `Profile` with `Proxies::default()` and
contributes env vars + port forward. This is unchanged — the actual
`Proxies` config comes from the user's profile, not the proxy profile.
The merge ensures proxy env vars take precedence.

#### Step 8: Update the proxy smoke test

**File:** `src/sandbox/proxy.rs`

```rust
#[tokio::test]
async fn start_proxy_binds_a_port_and_shuts_down_cleanly() {
    let proxies = Proxies::default();
    let handle = start_proxy(&proxies).await.expect("proxy starts");
    assert!(handle.port > 0, "ephemeral port assigned");
    handle.shutdown().await;
}
```

#### Step 9: Add handler unit tests

**File:** `src/sandbox/proxy.rs`

Add tests for `should_intercept` logic:

| Test | Setup | Assert |
|------|-------|--------|
| `should_intercept_allows_explicit_allow` | public_web=Deny, explicit Allow for `example.net` | `false` (tunnel) |
| `should_intercept_denies_explicit_deny` | public_web=Allow, explicit Deny for `example.net` | `true` (intercept) |
| `should_intercept_allows_unknown_when_public_allow` | public_web=Allow, host not in map | `false` (tunnel) |
| `should_intercept_denies_unknown_when_public_deny` | public_web=Deny, host not in map | `true` (intercept) |
| `should_intercept_case_insensitive` | `example.net` in map, request for `Example.Net` | matches (normalized) |
| `should_intercept_denies_no_host` | URI with no host | `true` (safety default) |

Tests construct a `PassthroughHandler` with a pre-populated `Proxies`
and call `should_intercept` directly with a constructed
`Request<Body>`.

#### Step 10: Update the module doc

**File:** `src/sandbox/proxy.rs`

Update the module-level doc comment from "Stage 1: tunnel-only" to
reflect that the proxy now supports allow/deny configuration.

#### Summary of files touched

| File | Action |
|------|-------|
| `src/lib.rs` | Add `pub mod hostname;` |
| `src/hostname.rs` | **New** — `normalize_hostname` function |
| `src/config/proxy.rs` | Normalize host in `resolve`, add test |
| `src/config/proxies.rs` | Add `get` method + tests |
| `src/sandbox/proxy.rs` | Replace handler, update `start_proxy` sig, update test |
| `src/cmd/run.rs` | Pass `&user_profile.proxies` to `start_proxy` |

**Total: ~6 files (1 new, 5 modified).**

**Expected risk level:** Low-moderate. The `normalize_hostname` and
`Proxies::get` additions are purely additive. The handler replacement
is the riskiest part — it changes the default behavior from "always
tunnel" to "check config first". The `should_intercept` logic is
straightforward branching, well-tested by unit tests. The `handle_request`
override is only exercised for denied hosts (explicit deny or
public_web=Deny + unknown host).

**Integration with Stage 4:** Stage 4 will modify `should_intercept`
to return `true` for hosts that need credential injection (so
`handle_request` can rewrite headers/params/auth), and `handle_request`
will forward the modified request instead of returning 403. The
`normalize_hostname` function will be used to extract and normalize
hosts from both CONNECT and intercepted HTTP requests.

### Stage 4: Modify proxy server to support credential injection

> **TLS trust design → `docs/SSL_DESIGN.md` (canonical) + the "SSL
> foundation phasing" section above.** Stage 4's HTTPS/MITM side sits on
> an **unimplemented SSL foundation** (the `with_http_connector` / custom
> root-store work is a pre-existing gap, not yet landed). Per the revised
> phasing, do the SSL foundation first, so Phase 4.2 is only possible
> after CA1+CA2 exist. Phase 4.1 (HTTP-forward injection) is **done**
> and independent of all of it.
>
> The doc above resolves the two critical HTTPS questions this stage
> used to leave open: (a) how redoubtful's *upstream client* trusts the
> real server (`with_http_connector` + an `openssl-probe`/`rustls-native-certs`
> root store, a single source of SSL truth), which is the exact seam HTTPS
> injection tests need; and (b) that WebSockets can be dropped or carried
> on the same root store without breaking OpenAI-style LLM streaming or
> MCP SSE.

**Scope:** Inject `headers`, `params`, and `auth` (Basic/Bearer) that were
resolved into each [`Proxy`] during Stage 2. Split into two phases:

- **Phase 4.1 — HTTP-forward injection** (no MITM): plain HTTP proxied via
  `HTTP_PROXY` arrives at `handle_request` as an absolute-form URI; we
  rewrite headers/params/auth and forward. **DONE and green.**
  Implemented via a `src/sandbox/rewrite.rs` module
  (`Rewrite::from_proxy` builds it when a host carries headers / params /
  auth; headers / query-params / Basic+Bearer auth, URI normalization via
  `url`), wired into `handle_request`'s allowed path. `should_intercept`
  stays `false`. Independent of TLS.
- **Phase 4.2 — HTTPS MITM + CA trust**: flip `should_intercept` per-host to
  MITM, inject on the decrypted inner request, and wire the per-session CA
  into the sandbox so clients trust the proxy's leaf certs. **Blocked on
  the SSL foundation phasing above** (single CA truth, CA1, sandbox bundle).

The config side (resolved `Proxy.headers/params/auth` as redacted `Secret`)
is already done in Stage 2. This stage is entirely server-side
(`src/sandbox/proxy.rs`) plus launcher wiring (`src/cmd/run.rs`,
`src/sandbox/bwrap.rs`) for the CA.

#### Key design decisions

1. **Injection fundamentally needs MITM for HTTPS — but not for HTTP.**
   Verified against hudsucker 0.24.0 (`src/proxy/internal.rs`):
   - `proxy()` calls `handle_request` as the first hook for **every** request
     (HTTP and CONNECT). For plain HTTP the request is already decrypted, so
     we inject and return `Request`.
   - For a CONNECT `handle_request` passes it through; `process_connect` then
     calls `should_intercept`. `false` → raw byte tunnel (client's own TLS, no
     injection possible). `true` → MITM: hudsucker terminates TLS with a leaf
     cert signed by our per-session CA, then feeds the **decrypted** inner
     request back through `proxy()` → `handle_request` again (absolute-form
     URI — `serve_stream` rebuilds it with `scheme=https` + CONNECT authority;
     normal method). We inject there and forward.
   - So: HTTP injection never needs `should_intercept`; HTTPS injection is
     impossible without it. Phase 4.1 keeps `should_intercept = false`.

2. **`should_intercept` = MITM gate, purely for allowed hosts that need
   injection.** Denied hosts keep short-circuiting in `handle_request` (the
   403 path, unchanged from Stage 3) before `should_intercept` is ever
   consulted, so `should_intercept` only needs to answer "do we MITM this
   CONNECT?" = `allowed && has_injection_config`.

3. **`handle_request` must distinguish CONNECT from a real request.**
   `req.method() == Method::CONNECT` (authority-only URI) → return untouched
   so `process_connect` / `should_intercept` take over. Any other method
   (GET/POST/PUT... from HTTP-forward or MITM'd HTTPS) → inject, then return
   `Request`. This is the "HTTP vs HTTPS — TBD" from Stage 3, now resolved:
   the distinction is method, not scheme.

4. **Injection is idempotent-friendly.** Headers overwrite (set beats
   existing); query params merge and let the injected value win per key;
   auth sets a single `Authorization` header. A host is never rewritten
   twice in one pass.

5. **CA trust wiring is the hard, risk-prone half.** The proxy already
   persists the per-session CA cert to a temp file exposed via
   `ProxyHandle::ca_cert_path()` (currently `#[expect(dead_code)]`). Phase 4.2
   must make sandboxed clients trust it, without touching the host trust
   store. The plan uses a **merged bundle** (host system bundle — found via
   `openssl-probe::probe()` + our CA) bind-mounted read-only into the sandbox,
   with every common CA env var pointing at it.

#### Tricky issues identified

- **URI form is narrower than feared — verified in hudsucker 0.24.0.**
  `serve_stream` (`src/proxy/internal.rs:337`) *rebuilds* every HTTP/1.x
  request URI to **absolute-form** (`scheme` + `authority` + path) before
  calling `proxy()` → `handle_request`. So both of our injection paths arrive
  absolute-form:
  - HTTP-forward: client sends `GET http://host/path?q` (already absolute).
  - MITM'd HTTPS: `serve_stream` adds `scheme=https` + CONNECT `authority`.
  Origin-form (`/path`) is only a rare edge (a few HTTP clients send it
  straight to an HTTP proxy). So the messy part collapses to "normalize any
  URI form to a parseable `url::Url`, merge params, write back" — and can be
  packaged as **one private function** in a dedicated rewrite module (see
  Step 2).
- **Credential-merge ordering confirmed (and a real `public_web` bug found
  and fixed).** In `cmd_run`, `finalize_config_with_cli` (line 99) runs the
  full load → fold-merge → finalize pass, which is where the user's
  `Proxies` (with rendered `Secret` credentials) is finalized.
  `start_proxy(&user_profile.proxies)` (line 118) hands that to the handler
  **before** `proxy_profile(port)` merges in (line 121). So credentials are
  resolved and captured correctly. **Bug found on review:**
  `Proxies::merge_right_biased` used `public_web: other.public_web` (plain
  replacement), which is inconsistent with the codebase's scalar-extra
  convention (`Mounts::readonly`, `EnvVars::path` use right-biased
  `Option::or`). That let a right-side `None` wipe a specified `Some` — so
  the default `public_web = Allow` from `base_config` was clobbered to `None`
  during `finalize`, meaning public web was **denied by default** (and the
  `public_web()` accessor's `todo!("should be set by base_config")` could
  fire). **Fixed:** `public_web: other.public_web.or(self.public_web)`, with
  regression tests. This also resolves the proxy-profile clobber concern as a
  side effect: `proxy_profile`'s default `None` no longer wipes the user's
  finalized value.
- **`Mounts::mount` is private.** `proxy_profile` needs to add the CA mount
  in Phase 4.2, but `Mounts::mount` is `fn mount` (module-private; only
  `Forwards::forward` is `pub` today). Make it `pub(crate)`.
- **Trust-store detection: use `openssl-probe` (no hand-rolled distro list).**
  The crate is *normally* used to configure an app's own SSL when linked
  against musl / bundled OpenSSL — but it exposes exactly what we want
  without touching our process env:
  - `openssl_probe::probe() -> ProbeResult` returns `cert_file: Option<PathBuf>`
    and `cert_dir: Vec<PathBuf>`. It honors an existing `SSL_CERT_FILE`/`SSL_CERT_DIR`
    (if they point at existing files) first, then falls back to known paths.
  - Linux `cert_file` candidates cover Debian/Ubuntu (`/etc/ssl/certs/ca-certificates.crt`),
    CentOS/RHEL/Fedora (`/etc/pki/...`), Alpine (`/etc/ssl/cert.pem`), OpenSUSE, etc.
  - We call `probe()` directly for the result; we deliberately **do not** call
    `try_init_openssl_env_vars()` (that mutates our process env). `probe()` is
    the clean "just give me the answer" path the user hoped existed.
  - Use `probe().cert_file` as the system bundle to concatenate with our CA. If
    only `cert_dir` is present (no single file), fall back to concatenating the
    hashed certs in that dir (rare; note as an edge). Honoring a custom
    `SSL_CERT_FILE` is a bonus — it respects users with non-default trust stores.
- **Tool env-var matrix.** Different tools honor different vars, with two
  semantics: *replace* (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
  `GIT_SSL_CAINFO`) and *append* (`NODE_EXTRA_CA_CERTS`). Set the replace-typed
  vars to the **merged** bundle (system + our CA, so public HTTPS still
  verifies); `NODE_EXTRA_CA_CERTS` can point at the same merged bundle (Node
  treats it as additional — harmless). See Step 5.
- **No DNS in the sandbox.** The proxy resolves upstream host-side; a model
  host like `prometheus.lan` must resolve on the *host*, not the sandbox. Not
  new, but it constrains any E2E test. The Stage 5 routing harness dodges DNS
  entirely by using the `127.0.1.1` IP literal (see `docs/
  proxy-testing-challenges.md`).

#### Step 1 (4.1): Add `Proxy::has_injection` flag

**File:** `src/config/proxy.rs`

```rust
impl Proxy {
    /// Whether this destination carries any credential-injection config.
    pub fn has_injection(&self) -> bool {
        !self.headers.is_empty() || !self.params.is_empty() || self.auth.is_some()
    }
}
```

**Tests** in `src/config/proxy.rs`: `has_injection_false_when_blank`,
`has_injection_true_with_header`, `_with_param`, `_with_auth`.

#### Step 2 (4.1): New `src/sandbox/rewrite.rs` module (package the messy URI work)

**Files:** `src/sandbox/rewrite.rs` (new), `src/sandbox/mod.rs` (wire), `Cargo.toml`.

Keep injection out of the handler so the URI normalization is **one
self-contained, exhaustively-tested module** rather than inline handler
scraps. A single entry point takes a `Proxy` config and mutates a request:

```rust
use hyper::{Body, Request};
use crate::config::proxy::{Proxy, ProxyAuth};
use crate::config::Secret;
use std::collections::BTreeMap;

/// A proxy's credential-injection config, ready to apply to a request.
/// Built from a resolved [`Proxy`]; fields re-use the redacting `Secret`
/// type so Debug/Display never leak values.
#[derive(Debug, Clone)]
pub struct Rewrite {
    headers: BTreeMap<String, Secret>,
    params: BTreeMap<String, Secret>,
    auth: Option<ProxyAuth>,
}

impl Rewrite {
    /// Build from a `Proxy` if it has anything to inject.
    pub fn from_proxy(p: &Proxy) -> Option<Self> { ... }

    /// Apply headers, query params, and auth to `req`.
    pub fn apply(&self, req: &mut Request<Body>);
}
```

- `apply` calls three private fns: `inject_headers`, `merge_query_params`,
  `inject_auth`. Do **not** log injected values (secrets).
- `merge_query_params` is the one messy function and the whole reason the
  module exists. Contract: *given any absolute- or origin-form `hyper::Uri`,
  append `params` to its query (idempotent per key: injected value wins) and
  write back a valid `hyper::Uri` preserving the original form.* Internally:
  - if the URI has scheme+authority → parse as-is with `url::Url`;
  - else (rare origin-form) → parse `http://sandbox.invalid` + path/query and
    write back only path+query;
  - `query_pairs_mut().append_pair(k, v)` per param (auto-encodes);
  - rebuild via `Uri::from_parts` from the original `uri.into_parts()`.
- `inject_auth` — set a single `Authorization` header:
  - `Basic { username, password }` → `Basic <b64(username:password)>`
  - `Bearer { token }` → `Bearer <token>`

**New dependencies** (`cargo add`): `url` (query merging), `base64` (Basic).

**Tests** in `src/sandbox/rewrite.rs` (pure — build a `Request<Body>`, call
`apply`, assert on the mutated request):

| Test | Assert |
|------|--------|
| `inject_headers_sets_each_header` | headers present, old value overwritten |
| `inject_params_merges_preserving_existing` | existing `?a=1` + `{b:2}` → `?a=1&b=2` |
| `inject_params_encodes_special_chars` | value with space/`&`/`=` is percent-encoded |
| `inject_params_origin_form` | origin-form `/path` gets query appended |
| `inject_auth_basic` | `Authorization: Basic <b64(user:pass)>` |
| `inject_auth_bearer` | `Authorization: Bearer <token>` |
| `apply_injection_noop_with_blank_config` | request unchanged |
| `injected_values_never_reach_debug_log` | no secret string in any tracing |

#### Step 3 (4.1): Inject in `handle_request` allowed path

**File:** `src/sandbox/proxy.rs`

In the allowed branch of `handle_request`, before returning `Request`:

```rust
if req.method() == Method::CONNECT {
    // HTTPS: pass through; MITM decision is should_intercept (Phase 4.2).
    return hudsucker::RequestOrResponse::Request(req);
}
let mut req = req;
if let Some(proxy) = self.proxies.get(&hostname) {
    if proxy.has_injection() {
        debug!(host = %host, "credential proxy: injecting into request");
        apply_injection(&mut req, proxy);
    }
}
hudsucker::RequestOrResponse::Request(req)
```

Denied path (403) is unchanged. Phase 4.1 `should_intercept` stays `false`.

#### Step 4 (4.2): Flip `should_intercept` for MITM-needed hosts

**File:** `src/sandbox/proxy.rs` and `src/config/proxies.rs`

Add to `Proxies`:

```rust
/// Whether to MITM a CONNECT to `host`: allowed *and* needs injection.
pub fn should_mitm(&self, host: &Hostname) -> bool {
    matches!(self.get(host), Some(p) if p.action == ProxyAction::Allow && p.has_injection())
}
```

`should_intercept` returns `self.proxies.should_mitm(&hostname)` (host
normalized; `None` host → `false`, since there is nothing to inject).

**Tests** in `src/config/proxies.rs`:

| Test | Setup | Assert |
|------|-------|--------|
| `should_mitm_allowed_with_injection` | Allow + auth | `true` |
| `should_mitm_allowed_no_injection` | Allow, blank | `false` (tunnel) |
| `should_mitm_denied_with_injection` | Deny + auth | `false` (403 path) |
| `should_mitm_unknown` | not in map | `false` |

#### Step 5 (4.2): Build a merged CA bundle and wire trust (openssl-probe)

**File:** `src/sandbox/ca_bundle.rs` (new, bundle build + `openssl-probe`),
`src/config/mounts.rs` (`pub(crate)` mount), `src/sandbox/proxy.rs`
`proxy_profile` (mount + env), `src/cmd/run.rs` (pass `ca_cert_path` in).

1. `find_system_ca_bundle() -> Option<Vec<u8>>` — call `openssl_probe::probe()`
   and read `cert_file`. Fall back to `cert_dir` (concatenate hashed certs;
   rare) if no single file. Log `cert_file`/`cert_dir` at debug for
   diagnosability. **Use `probe()`, never `try_init_openssl_env_vars()`** (it
   would mutate our process env). Bonus: this honors a user's custom
   `SSL_CERT_FILE`.
2. `build_sandbox_ca_bundle(system: &[u8], our_ca: &[u8]) -> Vec<u8>` —
   concatenate system bundle + our CA PEM into a fresh host-side
   `NamedTempFile` (cleaned on teardown).
3. Bind-mount the merged bundle ro into the sandbox at
   `/etc/ssl/certs/ca-certificates.sandbox.crt` (make `Mounts::mount`
   `pub(crate)` so `proxy_profile` can add it).
4. `proxy_profile(port, ca_bundle_sandbox_path)` sets every common var to the
   sandbox path:
   - replace-semantics: `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
     `GIT_SSL_CAINFO`
   - append-semantics: `NODE_EXTRA_CA_CERTS` (same merged bundle — harmless)
   Update `cmd_run` to pass `proxy_handle.ca_cert_path()` in.

**No host-side trust-store mutation.** The CA never leaves the per-session
`NamedTempFile` except into the sandbox bundle. If `probe()` finds no system
bundle at all, fail loudly (a merged bundle would silently trust *only* our
CA, breaking public HTTPS) rather than guess.

#### Step 6 (4.2): Docs + dead-code cleanup

- Update the `proxy.rs` module doc: remove "Credential injection deferred to
  Stage 4" and describe both phases.
- Remove `#[expect(dead_code)]` on `ProxyHandle::ca_cert_path` (now consumed),
  `Proxies::get` is now used by `should_mitm`, and the `#[allow(dead_code)]`
  on `Proxy`/`ProxyAuth` fields that feed injection.
- Update `docs/SECURITY_PHILOSOPHY.md` and the header status line.

#### Credential file permissions (companion hardening)

Add to `SecretsFile::load_or_init` (and/or a validate pass in
`resolve_context.rs`): enforce `0600` on the secrets file — refuse or warn if
it is group/world-readable, chmod `0600` on create. See the
"Credential file permissions" note above. This stage is the right moment:
it is the first that reads secrets **into the running proxy**.

#### Summary of files touched

| File | Action |
|------|--------|
| `src/config/proxy.rs` | Add `Proxy::has_injection` (+ tests) |
| `src/config/proxies.rs` | Add `Proxies::should_mitm` (+ tests) |
| `src/sandbox/rewrite.rs` | **New** — `Rewrite` struct + URI/header/auth injection (+ tests) |
| `src/sandbox/ca_bundle.rs` | **New** — `openssl-probe` discovery + merged-bundle build (+ tests) |
| `src/config/mounts.rs` | Make `Mounts::mount` `pub(crate)` |
| `src/sandbox/proxy.rs` | Handler routing, `should_intercept`, `proxy_profile` sig (mount + CA env) |
| `src/cmd/run.rs` | Pass `ca_cert_path` into proxy profile |
| `src/config/resolve_context.rs` | secrets file `0600` enforcement |
| `Cargo.toml` | Add `url`, `base64`, `openssl-probe` |

**Total:** ~8 files + 3 deps.

**Expected risk level:** Moderate. Phase 4.1 (injection) is additive and
unit-testable without TLS. Phase 4.2 (MITM + CA trust) is the riskiest: wrong
`should_intercept` flips break real HTTPS, and a missing/failed system-bundle
probe breaks public web. `ca_bundle.rs` and `rewrite.rs` isolate the
hard-to-reason-about parts so the handler stays simple and the tricky logic
is exhaustively unit-testable.

**Integration with Stage 5 (testing):** The E2E harness in
`docs/proxy-testing-challenges.md` is the vehicle for validating both
routing (Stage 3) and injection (Stage 4) end-to-end. The routing half is
now implemented (HTTP only) — see Stage 5 below. Injection E2E is still
deferred: it will reuse the same harness with an echo upstream (plus CA
trust wiring for HTTPS).

### Stage 5: E2E testing (partial: routing + HTTP-forward injection done, HTTPS injection pending)

**Status:** The HTTP **routing** half and the **HTTP-forward injection**
half of the E2E harness are implemented and validated. Routing was pulled
abead of Stage 4, ahead of the credential-injection work. Injection came
in with Phase 4.1. Both drive a real `curl` through `redoubtful run` →
the hudsucker handler → a controllable hermetic upstream (via the
`127.0.1.1` trick; see `docs/proxy-testing-challenges.md`), closing the
gap that let the Stage 3 routing bug through.

The upstream harness was unified into one echo-capable axum server
(`tests/cli/utils/http.rs`): it returns the sentinel first, then reflects
back the query string, `Authorization`, and `X-Test-Token` when present.
This lets plain reachability, deny, and credential-injection assertions
share one upstream (sentinel-only when nothing is injected). See
`docs/SSL_DESIGN.md`.

**What's done:**

- Two host-side integration tests in `tests/cli.rs`:
  - `http_through_proxy_reaches_upstream_when_allowed` — default
    `public_web = allow`, asserts the upstream sentinel reaches the sandbox.
  - `http_through_proxy_is_403_when_denied` — `--public-web=deny`, asserts
    the redoubtful 403 body and that the upstream sentinel did *not* arrive.
- The hermetic target is `127.0.1.1` (loopback block, but *outside* the
  client's `NO_PROXY`), with an axum-based upstream and a host-side
  reachability positive-control for each test.
- Because these spawn bwrap + pasta they run under `just check` on a real
  host (not `just check-sandbox`, which runs only unit tests).

**Also done (HTTPS routing):** the HTTPS passthrough pair (`https_*`), a
mirror of the HTTP pair that drives the CONNECT/raw-byte tunnel instead of
HTTP-forward, and needs **no** CA wiring. Both HTTP and HTTPS now mock
with the same axum + axum-server upstream (an optional rustls acceptor is
TLS); see `docs/SSL_DESIGN.md`.

**Done (HTTP-forward injection):** `credential_injection_injects_headers_params_and_auth`
drives a real `curl` through `redoubtful run` → the handler's HTTP-forward
grant with `headers`/`params`/`auth` configured, and asserts the echo
upstream reflects the injected values back. Greens with Phase 4.1.

**Still to plan (HTTPS injection):** the HTTPS *injection* tests need the
full TLS/CA foundation first — the upstream-client seam
(`with_http_connector`) and the test HTTPS upstream signed by **CA1**
(see `docs/SSL_DESIGN.md`, canonical), then the per-session CA2 trust
wiring (`SSL_CERT_FILE`/`GIT_SSL_CAINFO`, bind-mounted merged CA1+CA2
bundle). Per the revised phasing, this is the LAST step, after single-source
CA truth and an actual CA1.

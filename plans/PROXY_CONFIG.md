# Proxy Configuration Sketch

> **Status:** Human-written spec with Qwen3-written detailed plans. Supercedes `docs/ARCHITECTURE.md` and `docs/SECURITY_PHILOSOPHY.md`. Stage 1 complete; Stage 2 complete; Stage 3 still needs implementation.

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

### Stage 3: Modify proxy server to support config

TODO: Plan

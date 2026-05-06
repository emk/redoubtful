# Proxy Configuration Sketch

> **Status:** Human-written spec. Supercedes `docs/ARCHITECTURE.md` and `docs/SECURITY_PHILOSOPHY.md`. Stage 1 plan detailed; Stages 2–3 still need plans.

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
    #[clap(long = "proxy", short = "-P")]
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
    // Will we actually need a proxy layer?
    pub fn is_proxy_server_needed(&self, host: &str) -> bool {
        // Test if our proxy would let anything through.
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

TODO: Plan

### Stage 3: Modify proxy server to support config

TODO: Plan

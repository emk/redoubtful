# Proxy configuration as a Profile

> **Status:** Done. Planned and implemented by Qwen 3.6 26B running locally, with some critical code in `run.rs` hand-rewritten in the plan to include less obvious constraints.

## Problem

The sandbox proxy (HTTPS tunnel) configuration is scattered across the codebase:

- `proxy_env_vars(port)` in `src/sandbox/proxy.rs` returns `Vec<(&'static str, String)>`, which `cmd_run` manually loops over calling `env.set()`.
- `pasta_argv()` accepts `proxy_port: Option<u16>` as a separate parameter alongside `forwards: &Forwards`, with custom logic to prepend the proxy port to the `-T` list.

This is ad-hoc infrastructure that bypasses the profile/`Finalize` pipeline. The proxy contributes both env vars (proxy URLs) and a port forward (the ephemeral port), which are exactly the things a `Profile` models via `EnvVars` and `Forwards`.

## Goal

Represent the proxy's contribution as a `Profile` with `Forwards` and `EnvVars` set correctly, then layer it over the user's finalized configuration using `merge_right_biased`. This removes the manual env-var injection loop and the separate `proxy_port` parameter, unifying all sandbox configuration through a single path.

## Plan

### 1. Add a public constructor to `Forwards`

**File:** `src/config/forwards.rs`

The existing `Forwards::forward()` is `#[cfg(test)]`. Make it public so production code can construct `Forwards` programmatically:

```rust
pub fn forward(&mut self, host_port: u16, sandbox_port: u16) -> &mut Self {
    self.forwards.push(Forward { host_port, sandbox_port });
    self
}
```

### 2. Change `proxy_env_vars` to return `EnvVars`

**File:** `src/sandbox/proxy.rs`

Refactor `proxy_env_vars(port: u16) -> Vec<(&'static str, String)>` to `proxy_env_vars(port: u16) -> EnvVars`. This keeps the env-var list beside the proxy itself but returns a type the profile system understands.

### 3. Add `proxy_profile(port) -> Profile`

**File:** `src/sandbox/proxy.rs`

```rust
pub fn proxy_profile(port: u16) -> Profile {
    let mut forwards = Forwards::default();
    forwards.forward(port, port);
    Profile {
        mounts: Mounts::default(),
        forwards,
        env: proxy_env_vars(port),
    }
}
```

This returns a *resolved* (not declared) `Profile` containing exactly the proxy's contribution: one same-port forward and the 8 proxy env vars.

### 4. Export `proxy_profile` from the sandbox module

**File:** `src/sandbox/mod.rs`

Add `proxy_profile` to the re-exports alongside `proxy_env_vars` and `start_proxy`.

### 5. Simplify `cmd_run`

**File:** `src/cmd/run.rs`

Replace the current two-step pattern:

```rust
// OLD: finalize first, then mutate manually
let Profile { mounts, forwards, mut env } = ConfigFile::finalize_config_with_cli(&profile)?;
let proxy_handle = start_proxy().await?;
for (name, value) in proxy_env_vars(proxy_handle.port) {
    env.set(name, value);
}
```

With a single merge into the resolved (pre-finalize) profile:

```rust
// Finalize the user's configuration.
let user_profile = ConfigFile::finalize_config_with_cli(&profile)?;

// Start our proxy. This must happen _after_ finalizing the user's
// configuration, because that may someday have proxy-related
// parameters. We then merge in our proxy profile. Since this happens
// after finalization, we can't use "extra" fields in the proxy
// profile. Finalization is a one-time thing.
let proxy_handle = start_proxy().await?;
let profile_with_proxy = user_profile.merge_right_biased(&proxy_profile(proxy_handle.port));

let Profile { mounts, forwards, env } = profile_with_proxy;
```

This layers the proxy's `EnvVars` over the user's, so they win on any key collision (right-biased), and layers the proxy's forward into the forwards list. Since this happens after finalization, there's no second `finalize()` call — the merge is just the right-biased combination of two resolved inventories. The proxy profile can't use extra fields (`path`, `path_add`, `readonly`) because finalization is a one-time operation; it contributes only raw `EnvVars` and `Forwards`.

### 6. Simplify `pasta_argv`

**File:** `src/sandbox/pasta.rs`

Remove the `proxy_port: Option<u16>` parameter. The proxy port is now just the first entry in `forwards` (added by `proxy_profile`), so `forwards.format_for_pasta()` already includes it:

```rust
// OLD signature:
pub fn pasta_argv(forwards: &Forwards, proxy_port: Option<u16>, child_argv: Vec<OsString>) -> Vec<OsString>

// NEW signature:
pub fn pasta_argv(forwards: &Forwards, child_argv: Vec<OsString>) -> Vec<OsString>
```

The `-T` logic simplifies from:

```rust
let tcp_ns = match (proxy_port, forwards.is_empty()) {
    (None, true) => "none".to_string(),
    (None, false) => forwards.format_for_pasta(),
    (Some(p), true) => p.to_string(),
    (Some(p), false) => format!("{p},{}", forwards.format_for_pasta()),
};
```

To:

```rust
let tcp_ns = if forwards.is_empty() {
    "none".to_string()
} else {
    forwards.format_for_pasta()
};
```

Update the `#[instrument]` fields and doc comments accordingly.

### 7. Update tests

- **`src/sandbox/pasta.rs`**: All 7 existing tests pass `proxy_port` to `pasta_argv`. Remove the argument from all call sites. The two proxy-specific tests (`argv_uses_proxy_port_alone_when_no_user_forwards` and `argv_prepends_proxy_port_to_user_forwards`) should be merged into the general "forwards present" tests, since the proxy port is now just another forward with no special treatment.
- **`src/sandbox/proxy.rs`**: Update the `proxy_env_vars_populates_all_eight_names_with_matching_url` test to work with `EnvVars` instead of `Vec<(&str, String)>`.

### 8. Update imports

- **`src/cmd/run.rs`**: Add imports for `proxy_profile` (remove `proxy_env_vars` from the import since it's no longer called directly).
- **`src/sandbox/proxy.rs`**: Add imports for `EnvVars`, `Profile`, `Mounts`, `Forwards` from the config module.

## Order of changes

1. Add public `Forwards::forward()` — no behavior change, just visibility.
2. Refactor `proxy_env_vars` to return `EnvVars` — internal change to proxy.rs.
3. Add `proxy_profile()` — new function.
4. Simplify `pasta_argv` signature — remove proxy_port parameter.
5. Simplify `cmd_run` — merge proxy profile instead of manual injection.
6. Update tests.
7. Run `just check` to verify.

## Risks and trade-offs

- **Proxy port no longer visually first in `-T` debug logs.** Previously the proxy port was prepended before user forwards for debug trace readability. Now it's just the first forward in the merged list. This is a minor debug-log cosmetic change; the proxy port is still identifiable as an ephemeral high-number port.
- **Proxy env vars win on collision.** With right-biased merge, proxy vars override user-declared vars with the same name. This is the correct behavior: the user shouldn't be able to accidentally break the proxy by setting `HTTPS_PROXY` to something else.
- **Proxy profile is resolved, not declared.** Unlike user profiles that go through the `Decl` → `resolve()` → `finalize()` pipeline, the proxy profile is constructed directly as a `Profile`. This is fine because the proxy has no declarations to validate — it has exactly one same-port forward and 8 known env vars. There's no `uses` chain, no path normalization, no validation to skip.

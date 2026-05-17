# Canonical `Hostname` type

> **Status:** Done

## Summary

Replaced the free `normalize_hostname(&str) -> String` function with a `Hostname` newtype that normalizes at construction. Normalization happens at parse time (not resolve time), so user-facing types carry canonical values from the start.

## Changes

### `src/hostname.rs` — `Hostname` newtype

- `Hostname(String)` — stored lowercase, non-empty.
- `Hostname::new(&str) -> Result<Self>` — canonical constructor.
- `FromStr` — delegates to `new()`.
- `Serialize` / `Deserialize` — transparent string, normalizes on deserialize.
- `Display` — returns the normalized string.
- `AsRef<str>` — cheap access to the interior.
- Derives `Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash`.

### `ProxyDecl::host` — `String` → `Hostname`

Normalized at parse time via `FromStr` (CLI) and `Deserialize` (TOML). Empty-host validation moves from `validate()` to parse time.

### `Proxy::host` — `String` → `Hostname`

Resolution is just `self.host.clone()` — no normalization call needed.

### `Proxies` — `BTreeMap<Hostname, Proxy>`

Lookup methods (`get`, `should_allow`) take `&Hostname`. Callers construct `Hostname` at the boundary.

### `PassthroughHandler::should_intercept`

Uses `h.parse::<Hostname>().ok()` instead of `normalize_hostname(h)`.

### `normalize_hostname` — removed

No call sites remain.

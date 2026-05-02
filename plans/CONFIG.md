# Plan: TOML config and stackable profiles

> **Status:** Implemented, and heavily revised in the process.

## Goal

Give the user named profiles ("rust", "opencode", "git-config", …) that bundle equivalents of CLI flags, so

```
redoubtful run -p rust -p opencode -- claude
```

does the same thing as typing all of those `-m`, `-e`, `--path-add` flags by hand. Profiles compose by being layered last-wins, mirroring CLI semantics. Configuration lives in `~/.config/redoubtful/config.toml`, written on first run with a working set of shipped profiles; an empty file means no profiles defined.

The credential-proxy parts of the original `specs/ARCHITECTURE.md` schema (route table, secrets injection) are deferred — they layer on top of this once the proxy itself exists, and the route surface is too unwieldy to express on the CLI without a config file in the first place.

## Design decisions

### Profiles are facets, not a class hierarchy

Mental model: Rust traits, not CLOS multiple inheritance. Each profile is an orthogonal facet — `git-config`, `rust`, `node`, `claude-code`. The user composes them at the call site (`-p git-config -p rust -p claude-code`), or bundles them into project-level profiles (`[profile.my-frontend] uses = ["git-config", "node", "claude-code"]`).

A `uses = [...]` key lets one profile pull in others. Strict no-repeats: a profile reached via two paths is a config error, not a diamond to resolve. No C3 linearization. No implicit `default` profile. No hidden defaults.

### Composition is a monoid fold

After scalars become `Option<T>` (see below), opts compose as:

- **Scalars:** `b.or(a)` — last operand wins. `Option::or` right-biased.
- **Lists:** `a.extend(b)` — append in declared order.

Empty opts is the identity, merge is associative, so resolution is `profiles.fold(Opts::empty(), Opts::merge)` then merge CLI last. The existing `default_baseline` + `apply` pipeline consumes the merged opts unchanged.

### One Opts struct serves CLI and TOML

The existing `MountOpts`, `ForwardOpts`, `EnvOpts` get `#[derive(serde::Deserialize)]` alongside their existing `#[derive(clap::Args)]`. The change for booleans uses clap's `num_args = 0..=1, default_missing_value = "true"` pattern so CLI ergonomics are preserved while TOML round-trips cleanly:

```rust
#[arg(long, num_args = 0..=1, default_missing_value = "true")]
#[serde(default)]
pub readonly: Option<bool>,
```

`--readonly` → `Some(true)`; `--readonly=false` → `Some(false)`; absent → `None`. Profile TOML uses `readonly = true | false` and produces the same `Option<bool>`.

The only existing scalar that changes type is `MountOpts::readonly: bool` → `Option<bool>`. `EnvOpts::path` is already `Option<String>`. Lists (`mount`, `forward`, `env`, `path_add`) stay `Vec<T>` — empty and unset are equivalent for append semantics.

### Spans live in the source enum, not in the specs

`MountSource`, `ForwardSource`, and `EnvSource` gain a `Profile { name: String, span: SourceSpan }` variant. The Spanned wrapper exists only during TOML deserialization; it's unwrapped at conversion time, the span flows into the source enum, and the inner spec type is unchanged.

Effect: a "missing host path" diagnostic from `redoubtful run -p rust` renders with miette pointing at the exact line of `config.toml` that asked for it, and names the profile.

### Path normalization: only `~/`, only on TOML inputs

A `trait NormalizeConfigPaths { fn normalize_config_paths(&mut self) -> Result<()> }` is implemented on the profile-loaded structs and recursively on the inner specs. Called once after TOML deserialization, before merging. Only handles a leading `~/` (expanded against `$HOME`). No `~user/`, no `$VAR`, no relative paths — error on any unhandled `~` and reject relative paths with a friendly diagnostic. CLI input bypasses this entirely; the shell already expanded `~/`.

### First-run dump

If `~/.config/redoubtful/config.toml` is missing, the next `redoubtful run` (or `show`) writes the embedded default config to that path before proceeding, with a one-line stderr notice naming the file.

The shipped content is a *nicely-commented* working config: each profile has a one-or-two-line explanatory header documenting what it's for and why each mount is there. The profile bodies are real (not commented-out). Users see both "what this gives me" and "live config I can copy from." A unit test deserializes the embedded asset to verify it parses cleanly — the file ships intact and we never accidentally release a broken default.

The dump path writes the embedded asset **byte-for-byte** via `include_str!` + `fs::write` — never re-serialized through `toml`'s writer (which would strip the explanatory comments). Round-trip preservation is the test path's job, not the dump path's.

An *empty* `config.toml` is honored as "no profiles." The "file absent" case gets the populated starting point. We accept the cost: once written, the user owns the file. Future binary releases shipping new profile definitions don't propagate. A `redoubtful config diff` (or similar) is acknowledged as future work, not v1.

### Shipping policy: only interactively-verified profiles

Profiles ship in `assets/config.toml.default` only after Eric has used them interactively against a real agent and confirmed they work. This is an ongoing process — the shipped set grows over time as profiles are validated. v1 ships only `opencode` (the one documented in README's usage example). No port-forwarding profile yet, even though it's trivial: users running local-LLM servers tend to remap off popular ports, and shipping a `[profile.llama]` with `forward = [8080]` would either be wrong-by-default or invite a `#disabled` line right after install.

### CLI surface

- New flag on `run` and `show`: `-p, --profile NAME`, repeatable. No comma-separated form for v1.
- Existing `-p, --path-add` short flag becomes `-P` (long form unchanged). Safe to rename at v0.0.1.
- No new subcommand. Auto-init on first run.

## Module layout

- `src/config.rs` (new): TOML loading, profile resolution, the merge function, miette wiring for parse errors. Re-exports `Config`, `Profile`, `resolve_profiles`.
- `src/cmd/run.rs`, `src/cmd/show.rs`: gain `-p` flags, call `config::resolve_profiles` before constructing baseline lists.
- `src/mounts.rs`, `src/forward.rs`, `src/env.rs`:
  - Add `Deserialize` impls.
  - Switch `MountOpts::readonly` to `Option<bool>` with the clap pattern above.
  - Each `*Source` enum gains `Profile { name: String, span: SourceSpan }`.
  - Each Opts gains a `merge(self, other: Self) -> Self` method.
  - Each Opts grows a profile-shaped sibling — see "Spans live in the source enum" — that owns `Vec<Spanned<…Spec>>` for deserialization. The sibling implements `NormalizeConfigPaths` and `into_opts(name: &str) -> ProfileContribution` which produces the per-profile entries (with `Profile { name, span }` source) plus scalar overrides.
- `src/errors.rs`: new variants for config load failures, profile-not-found, profile cycles/repeats, invalid profile names, unhandled tilde patterns.
- `assets/config.toml.default` (new): embedded default config, pulled in via `include_str!`.

## Data type sketch

```rust
// src/config.rs

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "profile")]
    pub profiles: HashMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default)]
    pub uses: Vec<String>,

    // The flattened siblings — same fields as the CLI Opts but with
    // Spanned<…Spec> inner types and Option<T> scalars throughout.
    #[serde(flatten)]
    pub mounts: MountProfile,
    #[serde(flatten)]
    pub forwards: ForwardProfile,
    #[serde(flatten)]
    pub envs: EnvProfile,
}

pub fn load_config(path: &Path) -> Result<Config>;
pub fn resolve_profiles(
    config: &Config,
    requested: &[String],
) -> Result<ResolvedProfileOpts>;
```

`ResolvedProfileOpts` is the post-fold view: per-domain lists of `(spec, MountSource::Profile { name, span })` plus the merged scalar overrides. `cmd::run` then composes it with CLI opts (right-biased on scalars, append on lists) and feeds the result into the existing `default_baseline` + `apply` pipeline.

## Profile resolution algorithm

```
resolve(config, requested):
    seen = ordered set
    for name in requested:
        visit(config, name, seen)
    return seen as ordered list, then fold

visit(config, name, seen):
    if name in seen: error "profile X already included"
    profile = config.profiles[name] or error "unknown profile X"
    for dep in profile.uses:
        visit(config, dep, seen)
    seen.add(name)
```

Strict: `seen.contains(name)` is an error, not a skip. Error message names the two paths to the duplicate.

## Example shipped config

```toml
# ~/.config/redoubtful/config.toml
#
# Edit freely. Empty file = no profiles defined.
# Profile names are lowercase C identifiers.

# Profile for running `opencode` inside the sandbox. Mirrors the
# invocation documented in README's Usage section:
#   redoubtful run -m ~/.opencode -m ~/.config/opencode \
#                  -P ~/.opencode/bin opencode
[profile.opencode]
mount = [
    { host = "~/.opencode" },
    { host = "~/.config/opencode" },
]
path_add = ["~/.opencode/bin"]
```

(Wording and final commentary to be locked down during phase 4.)

## Implementation phases

### Phase 1: parser scaffolding + miette spans

- Add `toml = "0.8"` (or current). Build `load_config(path)` returning a parsed `Config`.
- Wire `toml::de::Error::span()` → `miette::SourceSpan`; attach the file content as `#[source_code]`.
- Test: malformed TOML, type errors, unknown fields all render with spans pointing at the right lines.
- No profile resolution yet.

### Phase 2: opts changes + merge

- Switch `MountOpts::readonly` to `Option<bool>` with the clap dual-arg pattern.
- Add `Deserialize` derives on each Opts.
- Add `merge` to each Opts; property-test associativity (`a.merge(b).merge(c) == a.merge(b.merge(c))`).
- Add `Profile { name, span }` variants to source enums.
- `NormalizeConfigPaths` impls on profile-side structs.

### Phase 3: profile resolution + CLI integration

- `resolve_profiles` with strict no-repeats and DFS walk of `uses`.
- Wire `-p, --profile` into `run` and `show`. Rename `--path-add` short flag to `-P`.
- `show` prints provenance per entry: `(from profile rust, config.toml:42)` for profile-sourced lines.
- Validation errors carrying profile sources render via miette with file + span.

### Phase 4: shipped profiles + first-run dump

- Embed `assets/config.toml.default` via `include_str!`.
- Auto-init: if config file is absent at the moment we'd read it, write defaults byte-for-byte and emit a one-line stderr notice.
- v1 ships only `[profile.opencode]`, mirroring the README's documented invocation. Additional profiles land in subsequent releases as Eric validates them interactively.

## Tests

In `tests/cli.rs`:

- `redoubtful run -p git-config -- ls ~/.gitconfig` succeeds.
- `redoubtful run -p does-not-exist -- /bin/true` errors with "unknown profile" naming the file.
- `redoubtful run -p a -p b` where both `uses` `c` errors with "already included" naming both paths.
- `redoubtful show -p rust` emits provenance for each entry.
- Missing config auto-creates and emits the notice.
- Empty config (`touch ~/.config/redoubtful/config.toml`) is honored as "no profiles."

In `src/config.rs` unit tests:

- The embedded `assets/config.toml.default` deserializes cleanly via `include_str!` + `toml::from_str`. No profile is named with an invalid identifier; every host path normalizes; every profile's `uses` references an existing profile. Catches stale shipped defaults at compile-time-adjacent.
- TOML parse errors render with spans.
- Type errors (e.g., `access = "wat"`) point at the offending value.
- `merge` associativity property test.
- DFS resolution: simple chain, branching `uses`, strict no-repeats triggers, unknown profile errors, cycles errors.
- Path normalization: `~/foo` expands; `~bob/foo` errors; `relative` errors.

## Out of scope (revisit later)

- Project-local config (`.redoubtful.toml` in repo). Trust direction is wrong for v1; would need to be readonly-mounted and `uses`-only.
- Comma-separated `-p a,b,c`. Trivial to add later.
- `redoubtful config diff` / `config update` for shipped-vs-edited drift.
- Implicit `default` profile.
- Credential-proxy route table in config. Lands when the proxy lands.
- TOML override of `[profile.X]` from a project file extending the global profile of the same name.
- A `--no-profile` flag to disable a profile that a project default would otherwise activate. (No defaults exist, so no need yet.)

## File changes summary

| Status | Path                                              |
|--------|---------------------------------------------------|
| New    | `src/config.rs`                                   |
| New    | `assets/config.toml.default`                      |
| Edit   | `src/main.rs` — wire `cmd_run`/`cmd_show` profile loading |
| Edit   | `src/cmd/run.rs` — `-p` flag, profile resolution call |
| Edit   | `src/cmd/show.rs` — `-p` flag, provenance display |
| Edit   | `src/mounts.rs` — `Option<bool>` readonly, Deserialize, merge, Profile source variant, profile-side struct |
| Edit   | `src/forward.rs` — Deserialize, merge, Profile source variant, profile-side struct |
| Edit   | `src/env.rs` — Deserialize, merge, Profile source variant, profile-side struct |
| Edit   | `src/errors.rs` — config/profile error variants    |
| Edit   | `Cargo.toml` — add `toml`                         |
| Edit   | `tests/cli.rs` — profile integration tests       |

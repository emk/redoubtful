# Migrate forward.rs / mounts.rs / profile.rs to `Decl + Finalize`

> **Status:** Implemented, with some revisions and refinements.

## Why this exists

`src/config/mod.rs` defines two traits — `Decl` (validate + resolve) and `Finalize` (merge + base + finalize) — that should own every config domain. Today only `env_var` / `env_vars` uses them. The other two domains plus the `profile` aggregator still use a bespoke `default_baseline(host-args) + apply(user-decls)` shape that `profile.rs::build_inventories` orchestrates by hand.

Goal: every domain implements `Decl` + `Finalize`, `profile.rs::build_inventories` collapses to `resolve → merge_all_right_biased → finalize`, and the `default_baseline` / `apply` shims retire.

The work landed for env_var/env_vars (commit pending) is the canonical example; this plan applies the same pattern, with domain-specific notes per file.

## The pattern

For each domain, four types in a singular/plural × Decl/Resolved cross:

| Role | Singular | Plural |
|------|----------|--------|
| Declared (CLI/TOML input) | `XxxDecl` | `XxxDecls` |
| Resolved (runtime input) | `Xxx` | `Xxxs` |

(Stale doc-comments still call these `XxxSpec` / `XxxOpts` / `XxxEntry` / `XxxList`. Sweep them as you migrate.)

### File split

Singular type and its tests live in `xxx.rs`; plural type, baseline construction, and orchestration tests live in `xxxs.rs`. `mod.rs` exports both. The singular file holds parsing-shaped tests (FromStr, validate, single resolve); the plural file holds the heavy machinery (base_config, merge, finalize, set/unset/iter). The remaining domain to migrate (`mounts.rs`) is currently a single file — splitting is part of the migration.

### Within-file ordering

Inside each file, `XxxDecl` (input form) appears **before** `Xxx` (resolved form), so the file reads top-to-bottom in pipeline order: declaration → resolution. `forward.rs` reads `ForwardDecl` → `Forward`, `forwards.rs` reads `ForwardDecls` → `Forwards`, and `env_var.rs` / `env_vars.rs` follow the same shape. Each type's impls (inherent and trait) follow that type — impls are not grouped at the bottom. Tests at the very end.

### Two kinds of fields on `Xxxs`

Walk every field of the plural Resolved type and decide which it is:

1. **Normal field** — the actual inventory the runtime consumes (e.g. `vars: BTreeMap<…>`, `mounts: Vec<Mount>`, `forwards: Vec<Forward>`). One entry per user spec. Merged via `merge_right_biased` like a Vec / Map. Survives `finalize()` into the final inventory.

2. **Extra field** — a scalar or list that parameterizes how `base_config` builds the baseline (`readonly: Option<bool>`, `path: Option<String>`, `path_add: Vec<String>`). Flows in through `Decl::resolve` from user input, gets consumed by `base_config`, then zeroed by `clear_extra_fields` so the final inventory carries only the resolved baseline + user entries.

Test for extra-field-ness: *if I deleted this field, what couldn't `base_config` compute?* If "the baseline shape" — extra. If "nothing — the runtime already consumes it directly" — normal.

### Things that come from the host env, not from `self`

HOME, cwd, possibly `XDG_RUNTIME_DIR`, etc. aren't user-declared — they're the runtime context. `base_config` reads them via `std::env::var_os(...)` / `std::env::current_dir()` directly. Don't add fields for these on `Xxxs`. Drop on absent (the broader sandbox setup errors first via `mounts.rs::home_dir` / `current_dir`).

### `default_baseline` becomes a thin wrapper

`profile.rs::build_inventories` calls `Xxxs::default_baseline(<host-args>, <user-extras>)` for every domain. Migrating one domain at a time means the others still need that signature. Rewrite the body to use the new pipeline:

```rust
pub fn default_baseline(host_args, user_extras) -> Self {
    let mut resolved = Self {
        <user-extras>: ...,
        ..Self::default()
    }
    .finalize();
    // Honor explicit host args byte-for-byte over base_config's
    // host-env reads — matters for tests that pass fake home/cwd.
    apply_host_args(&mut resolved, host_args);
    resolved
}
```

The wrapper retires when `profile.rs` migrates and stops calling it.

### Custom `Serialize` to preserve `show --json` shape

`tests/cli.rs` deserializes `redoubtful show --json` into structs that pre-date the refactor. Adding extras (`path`, `readonly`, …) to a plural type would expose them through naive `#[derive(Serialize)]`. Implement `Serialize` to emit just the inventory in the same shape callers already expect — the env case emits `vars.values()` as a JSON array; mounts/forwards do the analogous array-of-entries. Extras stay internal.

### `apply` / `apply_xxx_spec` stay, for now

`profile.rs::build_inventories` still applies decls layer-by-layer via `XxxDecls::apply(&mut Xxxs)`. Keep that surface working. Both retire when profile.rs migrates.

## Lessons from the env_var/env_vars pass (read first)

- **`base_config(&self) -> Self` has no context arg.** Anything it needs comes from `self` (extras), the host env, or both — not from a parameter list.
- **HOME goes in `base_config`, not via a new field.** Same source as `mounts.rs::home_dir`. Tests can read the live `$HOME` (read-only, concurrency-safe).
- **`OsString` over `String` for env values.** Linux env values are bytes; we use `OsString` so non-UTF-8 host bytes pass through. The single lossy hop is at the JSON-serialize boundary (`#[serde(serialize_with = "to_string_lossy")]`). Mounts/forwards probably don't need this — paths *can* be non-UTF-8 too, but `MountDecl.host: Spanned<PathBuf>` already captures that. Audit each domain.
- **`just check` runs `cargo clippy --all-targets -- -D warnings`.** Clippy compiles bin and test targets separately; a trait method exercised only by tests still trips `dead_code` against the bin. Use `#[allow(dead_code)]` with a "production callers land when profile.rs migrates" reason — *not* `#[expect]`, which itself triggers `unfulfilled_lint_expectations` when the test target's compilation pulls the method in.
- **clippy `field_reassign_with_default`**: build with `Self { field: ..., ..Self::default() }`, not `let mut x = Self::default(); x.field = ...;`.
- **Behavior changes surface in `tests/cli.rs`.** Run the full integration suite. Update expected ordering / shape only for *deliberate* behavior changes; investigate every other failure.
- **Doc sweep:** `XxxSpec`/`XxxOpts`/`XxxEntry`/`XxxList`-style references rot through every domain; rewrite as you migrate. Don't touch domains you're not migrating in this pass.
- **Tests split + rename:** parsing/validate/single-resolve tests in `xxx.rs`; set/unset/iter/base_config/finalize/merge in `xxxs.rs`. Test names: `xxx_spec_*` → `xxx_decl_*`, `xxx_opts_*` → `xxx_decls_*`, `xxx_list_*` → `xxxs_*`, `xxx_entry_*` → `xxx_*`.

## Step-by-step for one domain

1. **Read the existing file end-to-end.** Identify the four types, the existing `default_baseline` shape, the existing tests, and every caller in `profile.rs` / `bwrap.rs` / `pasta.rs` / `cmd/*` / `tests/cli.rs`.
2. **Classify each field on the plural Resolved type as Normal or Extra.** Write the breakdown into your plan file before coding, and confirm with the user. In some cases the non-Decl struct may not contain the
extra fields from the Decl struct. In this case, the extra fields may need to be added, as in `EnvVars`.
3. **Split the file** into `xxx.rs` (singular) and `xxxs.rs` (plural). Update `src/config/mod.rs` to export both.
4. **Implement `Decl`** for `XxxDecl` (resolves to either `Xxx` typically, or `Option<Xxx>` if it should be "skipped" when building `Xxxs`) and `XxxDecls` (resolves to `Xxxs`).
5. **Implement `Finalize`** for `Xxxs`:
   - `merge_right_biased(&self, &other) -> Self`: extras get right-biased `Option::or` for scalars, `extend` for lists. Normal fields merge per their type (`Vec::extend`, `BTreeMap` upsert).
   - `base_config(&self) -> Self`: build from extras + host env. **Order matters** for some inventories (mounts especially — see per-domain notes).
   - `clear_extra_fields(&mut self)`: zero all extras so the final inventory carries only the resolved baseline + user entries.
6. **Rewrite `default_baseline`** as a thin wrapper around the new pipeline. Honor explicit host args via post-finalize override where they differ from host-env reads (matters for tests with fake homes/cwds).
7. **Implement custom `Serialize`** if `show --json` would otherwise expose extras, or have the wrong format.
8. **Split + rewrite tests:**
   - Singular tests → `xxx.rs::tests`.
   - Plural tests → `xxxs.rs::tests`.
   - `default_baseline_*` tests become `base_config_*` (exercising the pipeline directly), plus one or two `default_baseline_wrapper_*` smoke tests for the shim.
   - Rename old-quartet test prefixes.
9. **Doc/comment sweep** in the two new files. Update file-level docs to describe the new pipeline. Don't touch domains not being migrated.
10. **Drop now-unreachable `Error` variants** (e.g. `NonUnicodeEnvVar` went away with `OsString` in env). Audit `errors.rs` after the migration compiles.
11. **Verify:** `cargo check`, `cargo test`, `just check` in that order. Any `tests/cli.rs` change that surfaces a deliberate behavior change goes in the same commit.

## Per-domain scope notes

### `forward.rs` (DONE — historical reference)

Current types:
- `ForwardDecl { host_port: Spanned<u16>, sandbox_port: Option<Spanned<u16>> }`
- `ForwardDecls { forward: Vec<ForwardDecl> }` — `clap::Args` + `Deserialize`
- `Forward { host_port: u16, sandbox_port: u16 }`
- `Forwards` — newtype around `Vec<Forward>`, with `default_baseline()` (no args, returns empty), `forward()`, `iter()`, `is_empty()`, `format_for_pasta()`

Field classification:
- **Extras: none.** `ForwardDecls` carries no scalars beyond the `forward` list. `Forwards::default_baseline()` returns empty today.
- **Normal:** `forwards: Vec<Forward>`.

So `Finalize` for `Forwards` is trivial:
- `merge_right_biased`: `Vec::extend`.
- `base_config`: `Self::default()` (empty list).
- `clear_extra_fields`: default no-op (no extras to clear).

After: `forward.rs` keeps `ForwardDecl`/`Forward`; new `forwards.rs` gets `ForwardDecls`/`Forwards`.

Watch for: pasta argv builder (`src/pasta.rs`) consumes `Forwards::iter()` and `format_for_pasta()` — keep both. Custom `Serialize` was *not* needed: with no extras to hide, `#[serde(transparent)]` already produces the array-of-`Forward` shape `tests/cli.rs::ForwardJson` deserializes.

### `mount.rs` / `mounts.rs` (DONE — historical reference)

Current types:
- `MountDecl { host: Spanned<PathBuf>, sandbox: Option<Spanned<PathBuf>>, access: Option<MountAccess> }`
- `MountDecls { mount: Vec<MountDecl>, readonly: Option<bool> }`
- `Mount { sandbox: PathBuf, kind: MountKind }` with `MountKind` covering `Mount{host,access}` / `Symlink{target}` / `Tmpfs` / `Dev` / `Proc`
- `Mounts` — newtype around `Vec<Mount>`
- `MountAccess::from_readonly(Option<bool>) -> MountAccess` (helper, keep)
- Module-level `home_dir()` / `current_dir()` helpers — keep where they are, both files use them.

Field classification:
- **Extras: `readonly: Option<bool>`** — parameterizes the cwd-bind access. Lives on `Mounts` (after migration), consumed by `base_config` (via `MountAccess::from_readonly(self.readonly)`), cleared by `clear_extra_fields`.
- **Normal:** `mounts: Vec<Mount>`.

Things to nail:
- **`home` and `cwd` come from the host env.** `base_config` reads them via `home_dir()` / `current_dir()` (already exist; both return `Result`). On error, drop the entry and trace — production paths always provide both, so this is the testable-fallback.
- **Order is load-bearing.** The default baseline emits `--tmpfs $HOME` *before* `--bind $PWD $PWD` so the bind overlays the tmpfs. CLI/profile mounts append after the cwd bind to punch through the tmpfs the same way. `merge_right_biased` for `Mounts` therefore can't be a symmetric `extend` — it's "left wins on order" (base before user). Decide the merge semantics before implementing.
- **`Mounts` is a `Vec<Mount>` (order matters)**, unlike `EnvVars::vars` which is a `BTreeMap` (order-irrelevant). Pick the data structure consciously.
- **`default_baseline` wrapper** today takes `home: &Path, cwd: &Path, cwd_access: MountAccess`. Cleanest first pass: keep that signature, have the wrapper construct `Mounts { readonly: <derived from cwd_access>, ..default }` and feed through `finalize()`, then post-finalize-override the cwd-bind path/access with the explicit args (mirrors what env's wrapper does for HOME).

After: a new `mount.rs` (singular) for `MountDecl`/`Mount`/`MountKind`/`MountAccess`; existing `mounts.rs` keeps the plural pieces but slims to `MountDecls`/`Mounts` plus `Finalize`.

Watch for: `bwrap.rs` consumes `Mounts::iter()` — keep. Custom `Serialize` needed (preserve the array-of-Mount shape `tests/cli.rs::ShowJson::mounts: Vec<MountJson>` expects).

### `profile.rs` (largest, last)

Once forward + mounts are on the new pipeline, `profile.rs` collapses substantially:

- **`ProfileDecl` gets a `Decl` impl.** `Resolved` is a new `Profile` aggregate (`mounts: Mounts, forwards: Forwards, env: EnvVars`) — or extend `ProfileDecl::resolve` to return a tuple, depending on what reads cleaner.
- **`Profile` gets a `Finalize` impl** that delegates each method to its three sub-types.
- **`build_inventories` collapses** to: `load_or_init` → normalize paths → `resolve_profiles` → resolve each `ProfileDecl` → `merge_all_right_biased` → `finalize`. The `fold_profile_scalars` helper becomes redundant (right-biased `Option::or` on extras handles last-wins automatically).
- **Drop the apply shims:** `XxxDecls::apply`, `apply_env_spec`, `apply_mount_spec` (if any), `XxxDecls::default_baseline` wrappers — all gone.
- **Lift `#[allow(dead_code)]`** on `Decl::resolve` and `Finalize::merge_all_right_biased` in `mod.rs` — they have production callers now.
- **Move `tests/cli.rs` config tests** to unit tests where possible (`TODO.md` line 31).

Most mechanical of the three once the prerequisites land.

## Final cleanup (after all three migrate)

- Delete every `default_baseline` shim and every `apply` / `apply_xxx_spec`.
- Lift `#[allow(dead_code)]` from `Decl::resolve` and `Finalize::merge_all_right_biased` in `mod.rs`.
- Re-read `mod.rs`'s file-level doc — it currently mentions `Resolve` and `MergeRightBiased` (aspirational); the actual traits are `Decl` and `Finalize`. Rewrite.
- Move `tests/cli.rs` config tests to unit tests (per `TODO.md`).
- `errors.rs`: prune any variants whose construction sites all retired with the apply path.
- Final doc sweep across `bwrap.rs` / `pasta.rs` / `cmd/*` for any remaining stale references.

## Verification (per domain)

1. `cargo check` — clean. The two `Decl::resolve` / `Finalize::merge_all_right_biased` `#[allow(dead_code)]` warnings are expected until profile.rs migrates.
2. `cargo test` — full unit + integration suite. Update `tests/cli.rs` only for *deliberate* behavior changes; investigate everything else.
3. `just check` — runs `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny check`, `cargo test --all-features`. Required to pass before commit (per AGENTS.md).
4. **Behavior-change spot-check:** `tests/cli.rs` tests that hardcode ordering, JSON shape, or specific error codes can break for benign reasons. Match each break to a user-visible change you intended.

## File map (target state, after all three migrate)

```
src/config/
  mod.rs              — Decl + Finalize traits (lift allow(dead_code) when profile lands)
  env_var.rs          — EnvVarDecl + EnvVar + tests
  env_vars.rs         — EnvVarDecls + EnvVars + tests + custom Serialize
  forward.rs          — ForwardDecl + Forward + tests
  forwards.rs         — ForwardDecls + Forwards + tests + custom Serialize
  mount.rs            — MountDecl + Mount + MountKind + MountAccess + home_dir/current_dir + tests
  mounts.rs           — MountDecls + Mounts + tests + custom Serialize
  profile.rs          — ProfileDecl + Profile + tests; build_inventories collapses
```

(If a split feels off — e.g. `MountKind` arguably belongs on the plural side, or `home_dir` should live where mounts and env both reach it — raise the question with the user.)

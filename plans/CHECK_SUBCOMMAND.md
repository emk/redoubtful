# Plan: `redoubtful check` subcommand and shared preflight

> **Status:** Implemented, in theory. Incorporates the AppArmor decisions from `docs/APPARMOR_USERNS.md` (Tier 2 is the default remediation) and the data-shape refinement based on some suggestions by Qwen. Pending Eric's review.

## Goal

Give the user a single command that validates the host can actually
run the sandbox, with friendly diagnostics naming the missing piece
when something is wrong. Same diagnostic surface is reused as a
preflight inside `redoubtful run` so a misconfigured host fails with
the friendly message instead of bwrap's `setting up uid map:
Permission denied`.

## Module layout

- Rename `src/deps.rs` → `src/check.rs`. Owns the three checks, the
  shared printer, and the embedded profile template.
- New `src/cmd/check.rs` is the subcommand handler.
- `src/cmd/mod.rs` gains `pub mod check;`.
- `src/main.rs` adds the `Check` variant and drops the
  `deps::probe_required()` call (preflight moves into `cmd_run`).
- `assets/apparmor/redoubtful.profile.template` holds the Tier 2
  profile with a `{REDOUBTFUL_PATH}` placeholder. Pulled in via
  `include_str!`.

## Data types (in `check.rs`)

```rust
pub struct CheckResult {
    pub name: &'static str,         // "bwrap", "pasta", "userns"
    pub outcome: CheckOutcome,
}

pub enum CheckOutcome {
    Pass { detail: String },
    Skip { reason: String },
    Fail { message: String, remediation: String },
}

pub async fn run_all_checks() -> Result<Vec<CheckResult>>;
pub fn print_report(out: &mut impl Write, results: &[CheckResult])
    -> io::Result<()>;
pub fn any_failed(results: &[CheckResult]) -> bool;
```

`run_all_checks` returns `Result` only because `current_exe()`
failure when constructing the userns remediation is fatal (see
"Tier 2 emission" below). All check outcomes are also logged from
inside `run_all_checks` via `tracing::{info,warn}!` so log-level
diagnostics exist regardless of which subcommand invoked it — the
log lines are the diagnostic record; the human report is only
emitted by the printer.

## The three checks

In order, with `userns` short-circuiting only on the `bwrap`
prerequisite:

1. **`bwrap`** — existing `probe("bwrap", "bubblewrap")` from `deps.rs`.
2. **`pasta`** — existing `probe("pasta", "passt")` from `deps.rs`.
3. **`userns`** — composite:
   1. If bwrap probe failed → `Skip { reason: "bwrap not on PATH" }`.
   2. Read `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`.
      Absent or `"0"` → `Pass { detail: "AppArmor userns
      restriction not in effect" }`.
   3. Restriction `"1"` → run `bwrap --unshare-user --unshare-pid
      --bind / / -- /bin/true`. Exit 0 → `Pass { detail: "AppArmor
      profile in place" }`.
   4. Non-zero exit → `Fail { message, remediation }`. Remediation
      embeds the Tier 2 profile with `current_exe()` substituted.

`--unshare-user --unshare-pid` is the minimum invocation that
exercises the AppArmor userns mediation; no mounts or networking
needed for the probe. We do *not* also exercise pasta — pasta and
bwrap hit the same AppArmor mediation the same way, so a single
bwrap probe is sufficient.

## Tier 2 emission (default remediation)

Per `README.md`'s install instructions and `docs/APPARMOR_USERNS.md`
Tier 2, the recommended fix is a Flatpak-style `flags=(unconfined) {
userns, }` profile attached to redoubtful's binary path. The
remediation prints:

1. One paragraph: Ubuntu 24.04+ restricts unprivileged userns by
   default; we need a per-binary AppArmor profile to opt back in.
2. The Tier 2 profile inline, with `{REDOUBTFUL_PATH}` replaced by
   the canonicalized `current_exe()`.
3. The commands to install it: write to `/etc/apparmor.d/redoubtful`
   (no extension, matching `firefox`/`chrome`/`flatpak` convention),
   then `sudo apparmor_parser -r /etc/apparmor.d/redoubtful`.
4. Pointer: "See `docs/APPARMOR_USERNS.md` for Tier 1 (more secure,
   chained per-binary profile with cap-stacking) and Tier 3 (less
   secure, sysctl disable) alternatives."

If `current_exe()` fails, return
`Error::could_not_get_current_exe(source)` rather than emitting a
profile with a placeholder. A sandbox binary that can't introspect
its own path is not in a state where we should be giving security
advice.

## Profile template

`assets/apparmor/redoubtful.profile.template`:

```
# AppArmor profile for redoubtful.
# Save as /etc/apparmor.d/redoubtful and load with:
#   sudo apparmor_parser -r /etc/apparmor.d/redoubtful
abi <abi/4.0>,

profile redoubtful {REDOUBTFUL_PATH} flags=(unconfined) {
  userns,
  include if exists <local/redoubtful>
}
```

Same shape as `/etc/apparmor.d/firefox`. Profile name is just
`redoubtful` — if a user has multiple installs at different paths,
the install-collision is theirs to rename.

## Subcommand wiring

- `cmd::check::cmd_check`: calls `run_all_checks`, calls
  `print_report` to **stdout** (this is the primary output of the
  command), returns `Err(Error::exit(1))` if any failed,
  `Ok(())` otherwise.
- `cmd::run::cmd_run`: calls `run_all_checks` at the top; on any
  failure, calls `print_report` to **stderr** and returns
  `Err(Error::exit(1))`. On all-pass, proceeds silently into the
  existing flow.
- `main.rs`: adds `Command::Check(cmd::check::Args)` (empty `Args`
  for now, reserved for future `--json` etc.); removes the
  `deps::probe_required()` call from the top-level `run()`.

## Aesthetics

`owo-colors` for ANSI color, gated by
`if_supports_color(Stream::{Stdout,Stderr}, …)` so it auto-disables
on non-TTY and `NO_COLOR=1`. Literal UTF-8 emoji glyphs in source:
✅ pass, ❌ fail, ⏭ skip.

Sample successful output (`redoubtful check`):

```
Checking redoubtful prerequisites…

  ✅ bwrap     bubblewrap 0.9.0
  ✅ pasta     passt 2024_10_30.ee7d0b6
  ✅ userns    AppArmor userns restriction not in effect

All checks passed.
```

Sample failure output (also what `redoubtful run` emits to stderr
on failure):

```
Checking redoubtful prerequisites…

  ✅ bwrap     bubblewrap 0.9.0
  ✅ pasta     passt 2024_10_30.ee7d0b6
  ❌ userns    bwrap could not create a user namespace

     Ubuntu 24.04+ blocks unprivileged user namespaces by default.
     Install an AppArmor profile to allow redoubtful to create them:

       sudo tee /etc/apparmor.d/redoubtful >/dev/null <<'EOF'
       # AppArmor profile for redoubtful.
       abi <abi/4.0>,

       profile redoubtful /home/eric/.cargo/bin/redoubtful flags=(unconfined) {
         userns,
         include if exists <local/redoubtful>
       }
       EOF
       sudo apparmor_parser -r /etc/apparmor.d/redoubtful

     See docs/APPARMOR_USERNS.md for Tier 1 (more secure) and
     Tier 3 (less secure) alternatives.

1 check failed.
```

(Single rendering — the `tee … <<'EOF'` block is both readable and
copy-pasteable as one unit.)

## Cargo deps

Add: `owo-colors = "4"`. Nothing else.

## Errors

Add to `src/errors.rs`:

```rust
/// Could not determine the path of the running redoubtful binary.
CouldNotGetCurrentExe { #[source] source: io::Error },
```

with a matching constructor. Used only by the userns remediation
path.

## Testing

Integration tests in `tests/cli.rs` (run with `NO_COLOR=1` so
assertions match plain text):

- `redoubtful check` on a healthy host → exit 0, three ✅ lines.
- `redoubtful check` with bwrap masked off `$PATH` → exit 1, ❌
  bwrap, ⏭ userns with "bwrap not on PATH".
- `redoubtful run -- /bin/true` on a healthy host → no preflight
  output on stderr, exit 0.
- `redoubtful run -- /bin/true` with bwrap masked → preflight
  failure report on stderr, exit 1.

Skip a real "AppArmor restriction triggers" integration test —
that's host-dependent and would require a restricted Ubuntu box.
Cover the userns failure path with unit tests on the printer
output instead.

Unit tests in `check.rs`:

- Profile template substitution: `{REDOUBTFUL_PATH}` is replaced
  with a fake path and the result still parses as the expected
  shape.
- `print_report` snapshots for each `CheckOutcome` variant
  (color disabled).
- `any_failed` correctness across mixed result vectors.

## File changes summary

| Status | Path                                                  |
|--------|-------------------------------------------------------|
| New    | `src/check.rs` (replaces `src/deps.rs`)               |
| New    | `src/cmd/check.rs`                                    |
| New    | `assets/apparmor/redoubtful.profile.template`         |
| Edit   | `src/cmd/mod.rs` — add `pub mod check;`               |
| Edit   | `src/main.rs` — add `Check` subcommand; drop top-level preflight |
| Edit   | `src/cmd/run.rs` — call `check::run_all_checks` up front |
| Edit   | `src/errors.rs` — add `CouldNotGetCurrentExe`         |
| Edit   | `Cargo.toml` — add `owo-colors`                       |
| Edit   | `tests/cli.rs` — preflight integration tests          |

## Out of scope (revisit later)

- `redoubtful check --json`. Reserved on the `Args` struct, no flag
  yet.
- Tier 1 profile emission (e.g. `--apparmor=tier1`). The doc has the
  recipe; defer until someone wants it.
- Detecting an existing redoubtful AppArmor profile on disk and
  skipping the bwrap probe. The probe is cheap; this is premature.

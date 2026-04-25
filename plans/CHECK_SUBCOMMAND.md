# Plan: `redoubtful check` subcommand

> **Status:** Drafted 2026-04-25. Skeleton agreed; AppArmor remediation
> text is TBD pending the empirical investigation in progress (see
> `plans/apparmor-test-redoubtful.profile` and
> `docs/APPARMOR_USERNS.md`).

## Goal

Give the user a single command that validates the host can actually
run the sandbox, with friendly diagnostics naming the missing piece
when something is wrong. Same diagnostic surface is reused as a
preflight inside `redoubtful run` so a misconfigured host fails with
the friendly message instead of bwrap's `setting up uid map:
Permission denied`.

## Module layout

- Rename `src/deps.rs` → `src/check.rs`. Hosts the checks plus a
  small result / printer model.
- New `src/cmd/check.rs` wraps it as the `check` subcommand.
- `cmd/run.rs` (and/or `main.rs`) calls into `check` as preflight.

## The checks

Each check produces `{ name, status, detail }` where `status` is
pass/fail and `detail` is an optional one-liner.

1. **`bwrap` present.** Existing `probe("bwrap", "bubblewrap")` from
   `deps.rs`. Reports the version on success, the missing-package
   diagnostic on failure.
2. **`pasta` present.** Existing `probe("pasta", "passt")`. Same shape.
3. **Sandbox can create a user namespace.** *Source of truth* for the
   AppArmor situation: actually invoke a probe sandbox command and
   see if it succeeds. Folds in pasta because pasta also creates a
   userns and hits the same restriction. If the probe fails, then
   read `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` to
   decide whether to print the AppArmor remediation block or a more
   generic "couldn't create user namespace" error.

The third check's exact probe command and remediation text are TBD —
see "Open" below.

## Output format

- Human-readable, one line per check: name + pass/fail + optional
  detail.
- On failure, append the relevant remediation block after the
  per-check lines.
- No JSONL or other structured form for now.
- Exit non-zero on any failed check.

## Wiring

- **`redoubtful check`**: runs all checks, always prints all three
  lines, appends remediation if anything failed.
- **`redoubtful run`**: runs all three checks before launching the
  sandbox. On all-pass, stays silent (current behavior). On any
  failure, prints the same output `check` would have produced, then
  exits non-zero.

Same diagnostic for both surfaces — users see one consistent
explanation regardless of how they hit the failure.

## Open

- **AppArmor remediation text.** The exact wording of the
  remediation block for check 3 depends on what we decide about the
  redoubtful-scoped profile vs. the upstream `bwrap-userns-restrict`
  vs. the sysctl. Empirical investigation in progress; see
  `docs/APPARMOR_USERNS.md` and the test profile in
  `plans/apparmor-test-redoubtful.profile`.
- **Probe command for check 3.** Likely something like `bwrap
  --unshare-user --unshare-pid -- /bin/true`, but may need to also
  exercise pasta if we determine the failure modes differ.

# Implementation steps

An overview of our implementation plan is in [`ARCHITECTURE.md`](../specs/ARCHITECTURE.md), though the 

- [x] Verify that sandbox user has write access to working directory.
- [x] Figure out APPARMOR_USERNS.md
- [x] Set up very basic networking
- [x] Combine "mounts" and "forwards" subcommands into a single command
- [x] Log full command-line invocation using debug!.
- [x] `bwrap --clearenv` + explicit `--setenv` (host env currently leaks
  into sandbox; spec gap, security regression)
- [x] Implement `check`
  - Smoke-test `pasta --config-net … /bin/true` (catches "installed but
    not allowed to set up netns" before the user hits it for real)
- [x] TOML config + stackable `-p, --profile` flag (per `plans/CONFIG.md`)
  - `~/.config/redoubtful/config.toml`, embedded default with
    `[profile.opencode]`, first-run dump, miette-spanned errors
  - Renames `--path-add`'s short flag from `-p` to `-P`
- [ ] Fix config code
  - [x] tag = "kind" is probably not what we want.
  - [x] Not enough "flatten" in Config
  - [x] remove eprintln!("redoubtful: wrote default config to {}", path.display());
  - [x] Command-line opts should probably become a profile, then get merged.
  - [x] fold_profile_scalars appears to not use monoid reduction??? Can we carry through attribution if we do this right?
  - [x] "apply" functions with `resolved: &[(&str, &Profile)]` should also use monoid reduction?
  - [x] `NormalizeConfigPaths` is declared once as a giant function, instead of once per type affected
  - [x] Remove references to Phase 1 through 4: Implementation detail.
  - [x] Why do we have custom deserialize?
  - [x] Massive duplication between run and show, again.
  - [ ] cli.rs has lots of config tests that should be unit tests, not config tests.
  - [ ] config_path should probably use a crate, `xdg` looks good.

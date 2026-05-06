# Implementation steps

An overview of our implementation plan is in [`ARCHITECTURE.md`](../specs/ARCHITECTURE.md), though the details have changed since that was last updated.

- [ ] Fix config code
  - [ ] cli.rs has lots of config tests that should be unit tests, not config tests.
  - [ ] config_path should probably use a crate, `xdg` looks good.
  - [ ] De-dup the code that auto-creates default config and secret files.

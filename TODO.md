# Implementation steps

An overview of our implementation plan is in [`ARCHITECTURE.md`](../specs/ARCHITECTURE.md), though the details have changed since that was last updated.

- [ ] Fix config code
  - [ ] cli.rs has lots of config tests that should be unit tests, not config tests.
  - [ ] Refactor common config-dir code (which is pretty trivial)
  - [ ] De-dup the code that auto-creates default config and secret files.
  - [ ] De-dup new tests, especially proxy stuff
  - [ ] Proptest merge_right_biased to make sure it fulfills monad laws.

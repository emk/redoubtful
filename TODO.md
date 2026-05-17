# Implementation steps

An overview of our implementation plan is in [`ARCHITECTURE.md`](../specs/ARCHITECTURE.md), though the details have changed since that was last updated.

- [ ] Fix config code
  - [ ] cli.rs has lots of config tests that should be unit tests, not config tests.
  - [x] Refactor common config-dir code (which is pretty trivial)
  - [ ] De-dup the code that auto-creates default config and secret files.
  - [ ] De-dup new tests, especially proxy stuff
  - [ ] Proptest merge_right_biased to make sure it fulfills monad laws.
  - [ ] Consider using Proxies::get.
  - [ ] Proxies::should_allow needs to apply normalization. Or just switch to a `Hostname` newtype.
  - [ ] Also, `should_allow` should log on the fallback branch.
  - [ ] cli.rs test that rejects an HTTPS connection (requires cert handling)
  - [ ] `handle_request` should return JSON error.

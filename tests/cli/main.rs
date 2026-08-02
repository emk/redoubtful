//! Integration tests for the `redoubtful` CLI.
//!
//! The load-bearing assertions for the v0 sandbox are
//! [`run_hides_unexpected_paths_in_home`] (no $HOME leaks) and
//! [`run_keeps_cwd_visible`] (project dir actually usable inside).
//! Everything else exercises plumbing.
//!
//! `run_hides_unexpected_paths_in_home` consumes the binary's own
//! `show --json` output as the source of truth for what the sandbox
//! is supposed to expose. We list `$HOME` *inside* the sandbox, then
//! assert that every entry visible there corresponds to a mount the
//! binary said it intended to expose.
//!
//! Caveat (deliberate): this test implicitly assumes the user's
//! real `$HOME` is not magically empty. If it is, the assertion
//! passes trivially without verifying the tmpfs is doing anything.
//! In any realistic dev or CI environment, `$HOME` has dotfiles,
//! ~/.cargo, etc. — so the corner case is acknowledged but not
//! engineered around.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod cmd;
mod config;
mod sandbox;
pub mod utils;

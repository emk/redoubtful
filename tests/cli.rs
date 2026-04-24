//! Integration tests for the `redoubtful` CLI.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};

/// Our CLI command.
fn cmd() -> Command {
    Command::cargo_bin("redoubtful").expect("binary exists")
}

#[test]
fn version_flag_prints_package_version() {
    cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_flag_prints_usage() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Usage:").and(contains("redoubtful")));
}

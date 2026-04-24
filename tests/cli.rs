//! Integration tests for the `redoubtful` CLI.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[test]
fn version_flag_prints_package_version() {
    Command::cargo_bin("redoubtful")
        .expect("binary exists")
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_flag_prints_usage() {
    Command::cargo_bin("redoubtful")
        .expect("binary exists")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Usage:").and(contains("redoubtful")));
}

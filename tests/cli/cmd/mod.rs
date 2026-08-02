//! Tests for specific CLI entry points (as opposed to deeper behaviors).

use predicates::{prelude::PredicateBooleanExt, str::contains};

use crate::utils::cmd;

pub mod check;
pub mod run;
pub mod show;

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

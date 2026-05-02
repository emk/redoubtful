//! Tiny exec-passthrough used to test AppArmor binary attachment.
//!
//! AppArmor attaches profiles by absolute binary path. To test the
//! "redoubtful-scoped userns grant" pattern, we need a real binary at
//! a fixed path so we can attach a profile to it. This wrapper just
//! `execve`s its argv — no setup, no logic, no allocation that
//! matters. Equivalent to `env(1)` but at a path we control.
//!
//! Usage:
//!     target/debug/examples/wrapper <cmd> [args...]
//!
//! Build with `cargo build --example wrapper`. Path attaches at
//! `<repo>/target/debug/examples/wrapper`.

use std::{os::unix::process::CommandExt, process::Command};

fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(prog) = args.next() else {
        eprintln!("usage: wrapper <cmd> [args...]");
        return std::process::ExitCode::from(2);
    };
    let err = Command::new(&prog).args(args).exec();
    eprintln!("wrapper: exec {prog:?} failed: {err}");
    std::process::ExitCode::from(1)
}

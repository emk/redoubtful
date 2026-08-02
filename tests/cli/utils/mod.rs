//! Shared integration test utilities.

use std::{path::PathBuf, time::Duration};

use assert_cmd::Command;

pub mod http;
pub mod show_json;
pub mod tcp;

/// Per-process isolated `XDG_CONFIG_HOME` for the test suite,
/// pre-populated with an empty `redoubtful/config.toml`.
///
/// Without this, every `redoubtful run`/`show` invocation triggered
/// by the integration tests would cascade to `load_or_init`'s
/// first-run dump path against the developer's real `$HOME`,
/// writing the shipped default to `~/.config/redoubtful/config.toml`
/// the first time anyone ran `cargo test`. Worse, the dump's
/// stderr notice would land in the same buffer as real stderr
/// assertions (`run_silent_on_preflight_success` etc.) and cause
/// nondeterministic failures on the first vs. subsequent test runs.
///
/// The empty config short-circuits both side effects: an existing
/// (zero-byte) file means "no profiles defined", `load_or_init`
/// reads it without writing anything, and stderr stays clean.
/// `OnceLock<TempDir>` keeps the dir alive for the entire test
/// process; the OS reaps it at exit via TempDir's `Drop`.
pub fn shared_xdg_config_home() -> &'static std::path::Path {
    use std::sync::OnceLock;

    use tempfile::TempDir;
    static DIR: OnceLock<TempDir> = OnceLock::new();
    let dir = DIR.get_or_init(|| {
        let d = tempfile::tempdir().expect("tempdir for XDG_CONFIG_HOME");
        let cfg_dir = d.path().join("redoubtful");
        std::fs::create_dir_all(&cfg_dir).expect("mkdir redoubtful");
        std::fs::write(cfg_dir.join("config.toml"), "")
            .expect("write empty config");
        d
    });
    dir.path()
}

/// Our CLI command. Sandbox runs typically complete in well under
/// a second on a developer laptop; the 30s timeout is a CI-hang
/// circuit-breaker, not a steady-state expectation.
///
/// `XDG_CONFIG_HOME` is overridden to the shared per-process
/// tempdir so the test never touches the developer's real config.
pub fn cmd() -> Command {
    let mut c = Command::cargo_bin("redoubtful").expect("binary exists");
    c.timeout(Duration::from_secs(30));
    c.env("XDG_CONFIG_HOME", shared_xdg_config_home());
    c
}

/// `cmd()` with the test process's environment scrubbed. Used by env
/// tests so they don't accidentally inherit (and then assert against)
/// whatever the developer happens to have set in their shell —
/// notably real `*_API_KEY` values, which would defeat the leak
/// tests.
///
/// We re-set just the host vars `redoubtful` itself needs:
/// `HOME` (consumed by `home_dir()` during sandbox setup), `PATH`
/// (so the test process's `redoubtful` invocation can find `pasta`
/// and `bwrap`), and `XDG_CONFIG_HOME` (the shared isolated config
/// dir — see [`shared_xdg_config_home`] for why). Everything else
/// stays empty until tests opt in via `.env(...)`.
pub fn cmd_clean() -> Command {
    let mut c = cmd();
    c.env_clear();
    let home = std::env::var_os("HOME").expect("test process needs HOME");
    let path = std::env::var_os("PATH").expect("test process needs PATH");
    c.env("HOME", home);
    c.env("PATH", path);
    c.env("XDG_CONFIG_HOME", shared_xdg_config_home());
    c
}

/// `cmd()` with a synthesized empty `$PATH` so bwrap and pasta
/// cannot be located. Used by preflight tests that want to assert
/// the failure-path report.
pub fn cmd_empty_path() -> Command {
    let dir = tempfile::tempdir().expect("tempdir for empty PATH");
    // Leak the tempdir so its path stays valid for the entire test —
    // the directory just needs to exist while assert_cmd runs the
    // child. Cleanup is best-effort via the OS-tempdir reaper.
    let path: PathBuf = dir.keep();
    let mut c = cmd();
    // NO_COLOR makes the report assertions stable regardless of
    // whether the test runner is attached to a TTY.
    c.env("PATH", path).env("NO_COLOR", "1");
    c
}

/// A `cmd_clean()` whose `XDG_CONFIG_HOME` points at a fresh
/// tempdir containing `redoubtful/config.toml = <toml>`. Each test
/// gets its own dir; the tempdir is leaked because cleanup races
/// with `assert_cmd` running the child process (best-effort cleanup
/// happens via the OS tempdir reaper).
pub fn cmd_with_config(toml: &str) -> Command {
    let dir = tempfile::tempdir().expect("tempdir for profile config");
    let config_dir = dir.path().join("redoubtful");
    std::fs::create_dir(&config_dir).expect("create redoubtful subdir");
    std::fs::write(config_dir.join("config.toml"), toml)
        .expect("write profile fixture");
    let path: PathBuf = dir.keep();
    let mut c = cmd_clean();
    c.env("XDG_CONFIG_HOME", path);
    c
}

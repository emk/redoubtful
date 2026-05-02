//! Host directory lookups: `$HOME`, the current working directory,
//! and the XDG-style location of the user config file.

use std::path::PathBuf;

use crate::prelude::*;

/// Read `$HOME` from the environment as a path.
pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| Error::missing_env_var("HOME"))
}

/// Read the current working directory.
pub fn current_dir() -> Result<PathBuf> {
    std::env::current_dir().map_err(Error::could_not_get_cwd)
}

/// XDG-style location for `~/.config/redoubtful/config.toml`.
///
/// Honors `XDG_CONFIG_HOME` if set (per the XDG Base Directory
/// Specification); otherwise falls back to `~/.config`. Returns an
/// error only if neither `$XDG_CONFIG_HOME` nor `$HOME` is
/// available, which is the same precondition the rest of redoubtful
/// already requires.
pub fn config_path() -> Result<PathBuf> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let base = match xdg {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => home_dir()?.join(".config"),
    };
    Ok(base.join("redoubtful").join("config.toml"))
}

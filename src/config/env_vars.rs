//! The environment variables the sandboxed process sees.
//!
//! `bwrap` is invoked with `--clearenv` followed by an explicit
//! `--setenv NAME VALUE` for every variable we want inside. This
//! module owns the inventory.
//!
//! Pipeline: the user declares vars via [`EnvVarDecls`] (`-e`,
//! `--path`, `--path-add` from the CLI; the matching keys in a
//! `[profile.NAME]` block from TOML). [`Decl::resolve`] turns one
//! `EnvVarDecls` into an [`EnvVars`] (literal values land in
//! `vars`; passthroughs do `env::var_os` and either land in `vars`
//! or get dropped). Multiple `EnvVars` from layered profiles + CLI
//! merge with [`Finalize::merge_right_biased`]. Finally,
//! [`Finalize::finalize`] consults `self.path` / `self.path_add`
//! to bake the canonical baseline (HOME + PATH + passthroughs +
//! `LC_*`) underneath the merged user vars. The user always wins
//! over the baseline through the right-biased merge.
//!
//! Threat model. The primary goal is **credential scrubbing**: a
//! prompt-injectable coding agent has no business seeing host
//! `*_API_KEY`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, etc. The secondary
//! goal is **silent-breakage avoidance**: env vars that point at host
//! paths the sandbox can't see (`XDG_RUNTIME_DIR`, `XAUTHORITY`,
//! `DBUS_SESSION_BUS_ADDRESS`, …) get dropped by default rather than
//! pointing the agent at non-existent files.
//!
//! Allowlist, three buckets:
//!
//! 1. **Host passthrough** — identity (`USER`, `LOGNAME`, `SHELL`),
//!    TUI (`TERM`, `COLORTERM`, `NO_COLOR`, `FORCE_COLOR`,
//!    `CLICOLOR`, `CLICOLOR_FORCE`, `TERMINFO`, `TERMINFO_DIRS`,
//!    `COLUMNS`, `LINES`, `TERM_PROGRAM`, `TERM_PROGRAM_VERSION`),
//!    locale (`LANG` plus every `LC_*` enumerated dynamically from
//!    the host env), misc (`TZ`, `EDITOR`, `VISUAL`, `PAGER`).
//!    Resolved against `std::env::var_os` here; if unset on the host
//!    the entry is dropped. Non-UTF-8 host values pass through
//!    byte-for-byte ([`EnvVar::value`] is `OsString`).
//!
//! 2. **Sandbox-injected** — `HOME` (read from `$HOME` in
//!    `base_config`, matching the path `mounts.rs::home_dir` uses
//!    so env and mounts agree); `PATH` (canonical, overridable via
//!    `--path`, with extra directories prependable via repeated
//!    `-P/--path-add`).
//!
//! 3. **Dropped** — everything else, automatically, via bwrap's
//!    `--clearenv`.
//!
//! User overrides via `-e/--env VAR[=VALUE]`:
//!   - `-e FOO=bar` sets a literal value (`bar` may be empty)
//!   - `-e FOO` (no `=`) is a passthrough: forward host's `$FOO` if
//!     set, drop the entry if unset
//!
//! Resolution timing. Passthroughs are resolved against the host env
//! eagerly at `Decl::resolve` time, not deferred to `bwrap_argv`.
//! That way `redoubtful show --json` and `redoubtful run` produce
//! identical env state for identical invocations — `show` describes
//! what `run` would actually pass, not an abstract policy.
//!
//! References:
//!
//!   bwrap(1) `--clearenv`, `--setenv`:
//!     <https://man.archlinux.org/man/bwrap.1.en>
//!   Project architecture spec, "Environment variables set inside
//!   the sandbox" + "The bwrap invocation":
//!     `specs/ARCHITECTURE.md`

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt as _,
    path::Path,
};

use serde::{Serialize, Serializer, ser::SerializeSeq};

use super::env_var::EnvVar;
use crate::{
    config::{
        Decl, Finalize, NormalizeConfigPaths, env_var::EnvVarDecl,
        resolve_context,
    },
    prelude::*,
};

/// Canonical sandbox `PATH`. We synthesize this rather than inheriting
/// the host's because the host's `PATH` typically contains
/// user-specific entries (`~/.local/bin`, `~/.cargo/bin`, `/snap/bin`,
/// …) that either don't exist inside the sandbox (tmpfs `$HOME`) or
/// aren't bind-mounted in. Inheriting them adds broken entries the
/// agent then has to skip — better to start with a known-good list.
/// Override with `--path` if a project genuinely needs more.
const CANONICAL_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Names whose host values get forwarded into the sandbox if set.
/// Curated for coding-agent TUIs — the goal is correct rendering and
/// usable defaults (locale, editor, terminal capabilities). Anything
/// not here is dropped by `--clearenv` unless the user passes `-e`.
///
/// `HOME` is absent: [`Finalize::base_config`] reads `$HOME`
/// directly (matching the source `mounts.rs::home_dir` uses, so
/// env and the bind-mount layer agree on the path). `PATH` is
/// also absent: `base_config` builds it from `self.path` / `self
/// .path_add` so the canonical-or-override base is set once and
/// `--path-add` entries land in the right (reverse) order.
///
/// `LC_*` is handled separately by walking `std::env::vars_os()`
/// — bwrap has no wildcard `--setenv` and the standard list of
/// `LC_*` names is open-ended (POSIX defines a baker's dozen,
/// glibc adds more), so dynamic enumeration is the honest answer.
const PASSTHROUGH_NAMES: &[&str] = &[
    // Identity. The user's name shows up in git commits, build
    // metadata, etc.; LOGNAME and SHELL come along for parity with
    // ordinary shells.
    "USER",
    "LOGNAME",
    "SHELL",
    // TUI rendering. `TERM` is the bare minimum for any terminfo
    // lookup; `COLORTERM` advertises truecolor capability;
    // `NO_COLOR`/`FORCE_COLOR`/`CLICOLOR*` are widely respected
    // toggles; `TERMINFO`/`TERMINFO_DIRS` let user-installed
    // terminfo entries (e.g. `xterm-kitty`) be found if the host
    // path happens to land somewhere visible inside; `COLUMNS`/
    // `LINES` are usually obtained via the `TIOCGWINSZ` ioctl on
    // the controlling tty, but a few apps fall back to env;
    // `TERM_PROGRAM`/`TERM_PROGRAM_VERSION` are set by some
    // terminals (iTerm2, vscode) and occasionally consulted.
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "TERMINFO",
    "TERMINFO_DIRS",
    "COLUMNS",
    "LINES",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    // Locale. `LANG` is the umbrella; `LC_*` is enumerated
    // dynamically by `base_config` (see the loop there).
    "LANG",
    // Misc usability. `TZ` overrides the system timezone; the
    // editor trio is consulted by git, cargo, kubectl edit, …;
    // `PAGER` is consulted by less-using tools (git, man, etc.).
    "TZ",
    "EDITOR",
    "VISUAL",
    "PAGER",
];

/// Shared env options.
///
/// Flattened with `#[command(flatten)]` into any subcommand that
/// builds an [`EnvVars`] (`run`, `show`), and routed into the
/// matching slot of [`crate::config::profile::ProfileDecl`] so
/// the same struct describes both CLI flags and `[profile.NAME]`
/// blocks.
///
/// `path` / `path_add` are [`OsString`] end-to-end: the eventual
/// sandbox `PATH` value is byte-clean ([`EnvVar::value`] is
/// `OsString`), and forcing these intermediate fields through
/// `String` would silently corrupt non-UTF-8 entries (a
/// non-UTF-8 `$HOME`, a directory with a 0xff byte, etc.) on the
/// way down. The TOML→`OsString` boundary lives in
/// [`crate::config::profile::ProfileDecl`]'s hand-written
/// [`serde::Deserialize`] impl; TOML itself is UTF-8 only.
//
// `Deserialize` is intentionally *not* derived: TOML deserialization
// goes through `ProfileDecl`'s hand-written impl, which repacks a
// flat `Raw` view into `EnvVarDecls`. Removing the derive prevents a
// future "let's just `#[serde(flatten)]` this" edit from accidentally
// reintroducing a `String`-based deserialization path.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct EnvVarDecls {
    /// Set or pass through an environment variable. Repeatable.
    /// `-e FOO=bar` sets `FOO=bar`; `-e FOO` forwards the host's
    /// `$FOO` (drops the entry if unset).
    #[arg(short = 'e', long = "env", value_name = "VAR[=VALUE]")]
    pub env: Vec<EnvVarDecl>,

    /// Override the canonical `PATH` baked into the sandbox. Consider `--path-add` instead.
    #[arg(long = "path", value_name = "PATH")]
    pub path: Option<OsString>,

    /// Add an extra directory to the front of the sandbox `PATH`.
    /// Repeatable. Multiple `-P` entries are prepended in *reverse*
    /// declaration order, so a later `-P` ends up first in PATH —
    /// matching the `export PATH=$DIR:$PATH` shell idiom and the
    /// "later overrides earlier" CLI-flag convention.
    #[arg(short = 'P', long = "path-add", value_name = "DIR")]
    pub path_add: Vec<OsString>,
}

impl NormalizeConfigPaths for EnvVarDecls {
    /// Expand `~/` in `path` (a colon-joined list, expanded
    /// segment-wise) and each entry of `path_add`. Regular `env`
    /// entries hold opaque values, not paths in general, so they're
    /// untouched.
    fn normalize_config_paths(&mut self, home: &Path) -> Result<()> {
        if let Some(p) = self.path.as_mut() {
            *p = expand_path_list(p, home)?;
        }
        for entry in &mut self.path_add {
            *entry =
                super::expand_tilde(Path::new(entry), home)?.into_os_string();
        }
        Ok(())
    }
}

/// Expand each `:`-separated segment of `p` independently, then
/// rejoin. Used for the `path` override (the canonical-PATH
/// replacement string, not the additions list — those each go
/// through [`super::expand_tilde`] standalone).
///
/// Operates on raw bytes (`b':'` as the separator) so non-UTF-8
/// segments survive byte-for-byte: the eventual `PATH` value the
/// sandbox sees is byte-clean, and a lossy hop here would defeat
/// that.
fn expand_path_list(p: &OsStr, home: &Path) -> Result<OsString> {
    let mut out = OsString::new();
    for (i, segment) in p.as_bytes().split(|&b| b == b':').enumerate() {
        if i > 0 {
            out.push(":");
        }
        let expanded =
            super::expand_tilde(Path::new(OsStr::from_bytes(segment)), home)?;
        out.push(expanded.as_os_str());
    }
    Ok(out)
}

impl Decl for EnvVarDecls {
    type Resolved = EnvVars;

    /// Validate every [`EnvVarDecl`] (empty/NUL name rejection).
    fn validate(&self) -> Result<()> {
        // TODO: Validate `path` and `path_add`.
        for spec in &self.env {
            spec.validate()?;
        }
        Ok(())
    }

    fn resolve(
        &self,
        ctx: &resolve_context::ResolveContext,
    ) -> Result<Self::Resolved> {
        let mut vars = BTreeMap::new();
        for decl in &self.env {
            if let Some(env_var) = decl.resolve(ctx)? {
                vars.insert(env_var.name.clone(), env_var);
            }
        }
        Ok(EnvVars {
            vars,
            path: self.path.clone(),
            path_add: self.path_add.clone(),
        })
    }
}

/// The resolved `--setenv` inventory the sandbox starts with.
///
/// `vars` is the actual name→[`EnvVar`] map the bwrap argv builder
/// emits one `--setenv NAME VALUE` triple per. `path` and
/// `path_add` are *extra fields* (in [`Finalize`] terms): user
/// declarations flow through `Decl::resolve` into them, then
/// [`Finalize::base_config`] reads them to bake PATH and
/// [`Finalize::clear_extra_fields`] zeroes them out so the final
/// inventory is just `vars`.
///
/// `vars` is a `BTreeMap` so re-overriding a name (e.g. user `-e
/// PATH=…` over the baseline) cleanly upserts and `show --json`
/// emits each name exactly once. Order isn't load-bearing — the
/// sandboxed process sees a flat env, not a sequence.
///
/// `Serialize` emits the entries as a JSON array (one
/// `{"name", "value"}` object per [`EnvVar`]) for `show --json`,
/// hiding the extra fields. After `finalize()` the extras are
/// already cleared; before that they're internal pipeline state
/// not meant for the JSON output.
#[derive(Debug, Default, Clone)]
pub struct EnvVars {
    /// Env var name/value pairs to set in the sandbox.
    vars: BTreeMap<String, EnvVar>,

    /// User-declared `--path` override — consumed by
    /// [`Finalize::base_config`] to build the canonical PATH, then
    /// cleared by [`Finalize::clear_extra_fields`]. `OsString` so a
    /// non-UTF-8 segment (e.g. via tilde expansion against a
    /// non-UTF-8 `$HOME`) survives end-to-end.
    path: Option<OsString>,

    /// User-declared `-P/--path-add` directories. Consumed by
    /// [`Finalize::base_config`], which prepends them in *reverse*
    /// order (so a later `-P` ends up first in PATH — see the
    /// `EnvVarDecls::path_add` doc), then cleared by
    /// [`Finalize::clear_extra_fields`].
    path_add: Vec<OsString>,
}

impl Serialize for EnvVars {
    /// Emit `vars` as a JSON array, ignoring the `path` /
    /// `path_add` extras. Matches what `show --json` consumers
    /// expect: a flat sequence of `{"name", "value"}` records,
    /// one per env var the sandbox will see.
    fn serialize<S: Serializer>(
        &self,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.vars.len()))?;
        for entry in self.vars.values() {
            seq.serialize_element(entry)?;
        }
        seq.end()
    }
}

impl EnvVars {
    /// Upsert by name. If an entry with the same `name` already
    /// exists, replace it; otherwise append.
    ///
    /// Upsert (rather than append) keeps the inventory free of
    /// duplicate `--setenv` triples when a user overrides a baseline
    /// var (e.g. `redoubtful run -e PATH=/only/this`). Bwrap takes
    /// the last `--setenv` for any given name, so append would also
    /// be correct *at runtime*, but `show --json` would show two
    /// entries for `PATH` which is just confusing.
    pub fn set(&mut self, name: &str, value: impl Into<OsString>) -> &mut Self {
        self.vars.insert(
            name.to_owned(),
            EnvVar {
                name: name.to_owned(),
                value: value.into(),
            },
        );
        self
    }

    /// Iterate over entries.
    pub fn iter(&self) -> impl Iterator<Item = &EnvVar> {
        self.vars.values()
    }

    /// Number of entries. Used for tracing fields.
    pub fn len(&self) -> usize {
        self.vars.len()
    }
}

impl Finalize for EnvVars {
    fn merge_right_biased(&self, other: &Self) -> Self {
        let mut vars = self.vars.clone();
        vars.extend(other.vars.iter().map(|(k, v)| (k.clone(), v.clone())));
        let path = other.path.clone().or_else(|| self.path.clone());
        let mut path_add = self.path_add.clone();
        path_add.extend(other.path_add.iter().cloned());
        Self {
            vars,
            path,
            path_add,
        }
    }

    fn base_config(&self) -> Self {
        let mut base = EnvVars::default();

        // HOME from the host env — same source `mounts.rs::home_dir`
        // uses, so env and the bind-mount layer agree on the path.
        // Drop silently if unset; the broader sandbox setup errors
        // on missing HOME via `mounts.rs::home_dir` before we get
        // here in production.
        if let Some(home) = std::env::var_os("HOME") {
            base.set("HOME", home);
        }

        // PATH = path_add (reverse order) ++ (self.path or
        // CANONICAL_PATH). Reverse order so a later `-P` ends up
        // first in PATH — matches `export PATH=$DIR:$PATH` and the
        // "later overrides earlier" CLI option convention. See the
        // `path_add` struct doc for the rationale.
        //
        // Built as `OsString` so a non-UTF-8 segment (whether from
        // `path_add` directly or a tilde expansion against a
        // non-UTF-8 `$HOME`) survives byte-for-byte. `OsString::push`
        // takes `impl AsRef<OsStr>`, so both `OsString` segments and
        // the literal `":"` separator work without intermediate
        // conversions.
        let canonical = OsStr::new(CANONICAL_PATH);
        let path_base = self.path.as_deref().unwrap_or(canonical);
        let mut path_value = OsString::new();
        for dir in self.path_add.iter().rev() {
            path_value.push(dir);
            path_value.push(":");
        }
        path_value.push(path_base);
        base.set("PATH", path_value);

        // Curated passthroughs. `var_os` preserves non-UTF-8 host
        // bytes — the `EnvVar.value: OsString` type lets them flow
        // through to bwrap. Unset on host is the only drop case.
        for name in PASSTHROUGH_NAMES {
            if let Some(value) = std::env::var_os(name) {
                base.set(name, value);
            } else {
                trace!(name, "passthrough env var unset on host; dropping");
            }
        }

        // `LC_*` dynamic enumeration. POSIX defines `LC_ALL`,
        // `LC_TIME`, `LC_NUMERIC`, `LC_COLLATE`, `LC_CTYPE`,
        // `LC_MESSAGES`, `LC_MONETARY`, plus glibc adds `LC_PAPER`,
        // `LC_NAME`, `LC_ADDRESS`, `LC_TELEPHONE`, `LC_MEASUREMENT`,
        // `LC_IDENTIFICATION`. Hardcoding any list is fragile —
        // distros add new ones. `vars_os` so non-UTF-8 values pass
        // through; non-UTF-8 *names* are an oddity we skip
        // (`EnvVar.name` is `String`, and POSIX env names are
        // ASCII in practice).
        for (key_os, value) in std::env::vars_os() {
            if let Some(key) = key_os.to_str()
                && key.starts_with("LC_")
            {
                base.set(key, value);
            }
        }

        base
    }

    fn clear_extra_fields(&mut self) {
        // These were used to construct PATH in the base config, so they've done their job,
        // and we must remove them.
        self.path = None;
        self.path_add.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use toml::Spanned;

    use super::*;

    /// Look up an `EnvVar` by name; panic with a clear message if
    /// missing. Most assertions in this module want the entry's
    /// `value` and not much else.
    fn entry<'a>(env: &'a EnvVars, name: &str) -> &'a EnvVar {
        env.iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("{name} entry expected"))
    }

    // ===== EnvVars::set / unset =====

    #[test]
    fn env_vars_set_appends_then_upserts() {
        let mut env = EnvVars::default();
        env.set("A", "1");
        env.set("B", "2");
        assert_eq!(env.len(), 2);

        // Upsert A — replaces, doesn't append.
        env.set("A", "1b");
        assert_eq!(env.len(), 2);
        assert_eq!(entry(&env, "A").value, OsStr::new("1b"));

        // BTreeMap ordering — alphabetical by name.
        let names: Vec<&str> = env.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn env_vars_set_accepts_str_string_and_os_string() {
        // `Into<OsString>` covers the three input shapes callers
        // actually have: a literal `&str`, an owned `String` (from
        // CLI/TOML), and an `OsString` (from `env::var_os`).
        let mut env = EnvVars::default();
        env.set("A", "literal");
        env.set("B", String::from("owned-string"));
        env.set("C", OsString::from("os-string"));
        assert_eq!(entry(&env, "A").value, OsStr::new("literal"));
        assert_eq!(entry(&env, "B").value, OsStr::new("owned-string"));
        assert_eq!(entry(&env, "C").value, OsStr::new("os-string"));
    }

    // ===== base_config (Finalize) =====

    #[test]
    fn base_config_uses_canonical_path_when_path_unset() {
        let base = EnvVars::default().base_config();
        assert_eq!(entry(&base, "PATH").value, OsStr::new(CANONICAL_PATH));
    }

    #[test]
    fn base_config_respects_path_override() {
        let env = EnvVars {
            path: Some(OsString::from("/only/this:/and/this")),
            ..EnvVars::default()
        };
        let base = env.base_config();
        assert_eq!(
            entry(&base, "PATH").value,
            OsStr::new("/only/this:/and/this"),
        );
    }

    #[test]
    fn base_config_prepends_path_additions_in_reverse_to_canonical() {
        // Reverse order: `["/opt/agent/bin", "/home/me/.cargo/bin"]`
        // → PATH starts with `/home/me/.cargo/bin:/opt/agent/bin:…`.
        // Matches `export PATH=$DIR:$PATH` and the "later overrides
        // earlier" CLI-flag idiom.
        let env = EnvVars {
            path_add: vec![
                OsString::from("/opt/agent/bin"),
                OsString::from("/home/me/.cargo/bin"),
            ],
            ..EnvVars::default()
        };
        let base = env.base_config();
        assert_eq!(
            entry(&base, "PATH").value,
            OsStr::new(&format!(
                "/home/me/.cargo/bin:/opt/agent/bin:{CANONICAL_PATH}"
            )),
        );
    }

    #[test]
    fn base_config_prepends_path_additions_in_reverse_to_override() {
        let env = EnvVars {
            path: Some(OsString::from("/only/this")),
            path_add: vec![
                OsString::from("/extra-first"),
                OsString::from("/extra-second"),
            ],
            ..EnvVars::default()
        };
        let base = env.base_config();
        assert_eq!(
            entry(&base, "PATH").value,
            OsStr::new("/extra-second:/extra-first:/only/this"),
        );
    }

    #[test]
    fn base_config_emits_home_from_host_env() {
        // Read-only check against the test process's $HOME — no env
        // mutation, so concurrency-safe. If the test runner is
        // exotic enough to leave HOME unset, the entry is dropped
        // (per the implementation's contract); skip the assertion.
        let base = EnvVars::default().base_config();
        match std::env::var_os("HOME") {
            Some(host_home) => {
                assert_eq!(entry(&base, "HOME").value, host_home);
            }
            None => {
                assert!(
                    base.iter().all(|e| e.name != "HOME"),
                    "HOME entry must be absent when $HOME unset",
                );
            }
        }
    }

    // ===== Finalize / clear_extra_fields =====

    #[test]
    fn finalize_clears_path_and_path_add() {
        let env = EnvVars {
            path: Some(OsString::from("/only/this")),
            path_add: vec![OsString::from("/extra")],
            ..EnvVars::default()
        };
        let env = env.finalize();
        assert!(
            env.path.is_none(),
            "finalize() should clear path; got {:?}",
            env.path,
        );
        assert!(
            env.path_add.is_empty(),
            "finalize() should clear path_add; got {:?}",
            env.path_add,
        );
        // PATH is now in vars, baked from path + path_add.
        assert_eq!(entry(&env, "PATH").value, OsStr::new("/extra:/only/this"));
    }

    // ===== EnvVarDecls::resolve + Finalize::finalize =====

    #[test]
    fn env_var_decls_resolve_then_finalize_user_var_overrides_baseline() {
        // User declares `-e PATH=/only/this`. After resolve+finalize,
        // the user's PATH wins over base_config's canonical PATH via
        // the right-biased merge (`base.merge_right_biased(&self)`).
        let decls = EnvVarDecls {
            env: vec![EnvVarDecl {
                name: Spanned::new(0..0, "PATH".to_owned()),
                value: Some("/only/this".to_owned()),
            }],
            path: None,
            path_add: Vec::new(),
        };
        let ctx = resolve_context::ResolveContext::empty();
        let env = decls.resolve(&ctx).expect("resolves").finalize();
        assert_eq!(entry(&env, "PATH").value, OsStr::new("/only/this"));
        assert_eq!(
            env.iter().filter(|e| e.name == "PATH").count(),
            1,
            "PATH must be unique post-finalize",
        );
    }

    #[test]
    fn env_vars_merge_right_biased_layers_two_resolved_decls() {
        // Two profiles' resolved EnvVars merged: right wins for
        // overlapping vars, path is right-biased Option::or, and
        // path_add concatenates.
        let mut left = EnvVars::default();
        left.set("A", "from-left");
        left.set("SHARED", "left-wins-when-alone");
        left.path = Some(OsString::from("/left"));
        left.path_add = vec![OsString::from("/left/bin")];

        let mut right = EnvVars::default();
        right.set("B", "from-right");
        right.set("SHARED", "right-wins");
        right.path = Some(OsString::from("/right"));
        right.path_add = vec![OsString::from("/right/bin")];

        let merged = left.merge_right_biased(&right);
        assert_eq!(entry(&merged, "A").value, OsStr::new("from-left"));
        assert_eq!(entry(&merged, "B").value, OsStr::new("from-right"));
        assert_eq!(entry(&merged, "SHARED").value, OsStr::new("right-wins"));
        assert_eq!(merged.path.as_deref(), Some(OsStr::new("/right")));
        assert_eq!(
            merged.path_add,
            vec![OsString::from("/left/bin"), OsString::from("/right/bin")],
        );
    }

    // ===== NormalizeConfigPaths impl =====

    #[test]
    fn normalize_config_paths_expands_path_segments() {
        let mut decls = EnvVarDecls {
            env: Vec::new(),
            path: Some(OsString::from("~/.cargo/bin:/usr/local/bin:~/bin")),
            path_add: Vec::new(),
        };
        decls
            .normalize_config_paths(Path::new("/home/test"))
            .expect("normalizes");
        assert_eq!(
            decls.path.as_deref(),
            Some(OsStr::new(
                "/home/test/.cargo/bin:/usr/local/bin:/home/test/bin",
            )),
        );
    }

    #[test]
    fn normalize_config_paths_expands_path_add_entries() {
        let mut decls = EnvVarDecls {
            env: Vec::new(),
            path: None,
            path_add: vec![
                OsString::from("~/.opencode/bin"),
                OsString::from("/opt/bin"),
            ],
        };
        decls
            .normalize_config_paths(Path::new("/home/test"))
            .expect("normalizes");
        assert_eq!(
            decls.path_add,
            vec![
                OsString::from("/home/test/.opencode/bin"),
                OsString::from("/opt/bin"),
            ],
        );
    }

    #[test]
    fn normalize_config_paths_propagates_invalid_path_add_entry() {
        let mut decls = EnvVarDecls {
            env: Vec::new(),
            path: None,
            path_add: vec![OsString::from("relative/dir")],
        };
        let err = decls
            .normalize_config_paths(Path::new("/home/test"))
            .expect_err("relative path_add entry must error");
        assert!(matches!(err, Error::ConfigInvalidPath { .. }));
    }

    #[test]
    fn normalize_config_paths_leaves_env_values_untouched() {
        // Regular env entries are opaque values, not paths — even a
        // leading `~/` shouldn't be expanded here.
        let mut decls = EnvVarDecls {
            env: vec![EnvVarDecl {
                name: Spanned::new(0..0, "FOO".to_owned()),
                value: Some("~/literal".to_owned()),
            }],
            path: None,
            path_add: Vec::new(),
        };
        decls
            .normalize_config_paths(Path::new("/home/test"))
            .expect("normalizes");
        assert_eq!(decls.env[0].value.as_deref(), Some("~/literal"));
    }

    // ===== Non-UTF-8 byte preservation =====
    //
    // The policy in `AGENTS.md` requires that non-UTF-8 bytes flow
    // through the env-var pipeline byte-for-byte on non-diagnostic
    // paths. These tests fail before the OsString refactor below
    // (the lossy `to_string_lossy().into_owned()` hop replaces the
    // 0xff byte with U+FFFD) and pass after.

    #[test]
    fn expand_path_list_preserves_non_utf8_segment() {
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
        let raw: Vec<u8> = b"/\xff/bin:/usr/bin".to_vec();
        let input = OsString::from_vec(raw.clone());
        let got = expand_path_list(&input, Path::new("/home/test"))
            .expect("non-UTF-8 segment is allowed");
        assert_eq!(got.as_bytes(), raw.as_slice());
    }

    #[test]
    fn expand_path_list_tilde_against_non_utf8_home_preserves_bytes() {
        // `$HOME` with a stray 0xff byte: the join must propagate
        // those bytes verbatim through the OsStr machinery.
        use std::{
            os::unix::ffi::{OsStrExt as _, OsStringExt as _},
            path::PathBuf,
        };
        let home = PathBuf::from(OsString::from_vec(b"/home/\xff".to_vec()));
        let input = OsString::from("~/bin:~/.cargo/bin");
        let got =
            expand_path_list(&input, &home).expect("~/ expansion is fine");
        assert_eq!(
            got.as_bytes(),
            b"/home/\xff/bin:/home/\xff/.cargo/bin".as_slice(),
        );
    }

    #[test]
    fn env_var_decls_path_add_with_non_utf8_lands_in_path_byte_for_byte() {
        // End-to-end: a `path_add` entry containing 0xff flows
        // through `Decl::resolve` + `Finalize::finalize` and shows
        // up in the resulting `PATH` value byte-for-byte. Forcing
        // `path_add` through `String` would replace 0xff with U+FFFD
        // here.
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
        let raw: Vec<u8> = b"/\xff/bin".to_vec();
        let decls = EnvVarDecls {
            env: Vec::new(),
            path: None,
            path_add: vec![OsString::from_vec(raw.clone())],
        };
        let ctx = resolve_context::ResolveContext::empty();
        let env = decls.resolve(&ctx).expect("resolves").finalize();
        let path_value = &entry(&env, "PATH").value;
        let prefix = format!(":{CANONICAL_PATH}");
        let mut expected = raw.clone();
        expected.extend_from_slice(prefix.as_bytes());
        assert_eq!(path_value.as_bytes(), expected.as_slice());
    }
}

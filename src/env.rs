//! The environment variables the sandboxed process sees.
//!
//! `bwrap` is invoked with `--clearenv` followed by an explicit
//! `--setenv NAME VALUE` for every variable we want inside. This
//! module owns the inventory: a curated baseline plus user overrides
//! from `-e/--env` and `--path`, resolved against the host
//! environment at construction time.
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
//!    Resolved against `std::env::var` here; if unset on the host
//!    (or non-UTF-8), the entry is dropped.
//!
//! 2. **Sandbox-injected** — `PATH` (canonical, overridable via
//!    `--path`, with extra directories prependable via repeated
//!    `-p/--path-add`). `HOME` is set from a `&Path` argument the
//!    caller passes to [`EnvList::default_baseline`] — the same
//!    `PathBuf` the bind-mount layer uses, so env and mounts agree
//!    on the path.
//!
//! 3. **Dropped** — everything else, automatically, via bwrap's
//!    `--clearenv`.
//!
//! User overrides via `-e/--env VAR[=VALUE]`:
//!   - `-e FOO=bar` sets a literal value (`bar` may be empty)
//!   - `-e FOO` (no `=`) is a passthrough: forward host's `$FOO` if
//!     set, drop the entry if unset
//!
//! Applied after baseline so user always wins. `set` is upsert-by-name
//! so a re-override produces no duplicate `--setenv` triples.
//!
//! Resolution timing. Passthroughs are resolved against the host env
//! eagerly at construction (here), not deferred to `bwrap_argv`. That
//! way `redoubtful show --json` and `redoubtful run` produce identical
//! env state for identical invocations — `show` describes what `run`
//! would actually pass, not an abstract policy.
//!
//! References:
//!
//!   bwrap(1) `--clearenv`, `--setenv`:
//!     <https://man.archlinux.org/man/bwrap.1.en>
//!   Project architecture spec, "Environment variables set inside
//!   the sandbox" + "The bwrap invocation":
//!     `specs/ARCHITECTURE.md`

use std::path::Path;
use std::str::FromStr;

use serde::Serialize;

use crate::prelude::*;

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
/// `HOME` is absent: [`EnvList::default_baseline`] sets it from the
/// `home: &Path` argument the caller passes (the same `PathBuf` the
/// bind-mount layer uses), not from the host env. `PATH` is also
/// absent: we set the canonical value (or `--path` override) directly.
///
/// `LC_*` is handled separately by walking `std::env::vars()` —
/// bwrap has no wildcard `--setenv` and the standard list of `LC_*`
/// names is open-ended (POSIX defines a baker's dozen, glibc adds
/// more), so dynamic enumeration is the honest answer.
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
    // dynamically by `default_baseline` (see the loop there).
    "LANG",
    // Misc usability. `TZ` overrides the system timezone; the
    // editor trio is consulted by git, cargo, kubectl edit, …;
    // `PAGER` is consulted by less-using tools (git, man, etc.).
    "TZ",
    "EDITOR",
    "VISUAL",
    "PAGER",
];

/// Provenance of an [`EnvEntry`] — extensible.
///
/// `Default` covers the curated baseline (`HOME`, the canonical
/// `PATH`, host passthroughs). `Cli` covers user
/// `-e`/`--path`/`-p` overrides.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvSource {
    /// Hardcoded baseline entry from [`EnvList::default_baseline`].
    Default,
    /// Added or overridden via a `-e`/`--env`/`--path`/`-p` CLI flag.
    Cli,
}

/// One concrete environment-variable assignment that bwrap will see.
///
/// Values are `String` (UTF-8). Literal values originate from CLI
/// `String` input and are always UTF-8; passthroughs use
/// `std::env::var` (not `var_os`) which means a non-UTF-8 host value
/// behaves identically to "unset" — the entry is dropped. This keeps
/// the type plainly serializable to JSON and avoids any
/// `to_string_lossy` surprises in `show --json`.
#[derive(Debug, Clone, Serialize)]
pub struct EnvEntry {
    /// The variable name (e.g. `PATH`). No `=`-style encoding here;
    /// bwrap's `--setenv` takes name and value as separate argv
    /// tokens.
    pub name: String,

    /// The value to assign. May be empty (`-e FOO=` is a real use
    /// case: "set FOO to the empty string").
    pub value: String,

    /// Where the entry came from. Lets `show --json` distinguish
    /// CLI overrides from baseline entries.
    pub source: EnvSource,
}

/// The ordered list of `--setenv` entries the sandbox starts with.
///
/// Newtype around `Vec<EnvEntry>` so the assembly site can call
/// `env.set(...)` without re-constructing field-level boilerplate,
/// and so `show --json` can `serde_json` the whole thing transparently.
///
/// Order is preserved (declaration order) but isn't load-bearing —
/// the sandboxed process sees them as a flat env, not a sequence.
/// Upsert semantics (see [`Self::set`]) keep the list deduplicated
/// even when `-e` re-overrides a baseline name.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(transparent)]
pub struct EnvList(Vec<EnvEntry>);

impl EnvList {
    /// An empty list. Use [`Self::default_baseline`] for the
    /// curated starting point; this exists for tests and for
    /// `show --json` callers that build a list explicitly.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// The curated baseline, with passthroughs already resolved
    /// against the host environment.
    ///
    /// Sets `HOME` to the literal `home` path (matching the
    /// bind-mount layer — caller passes the same `PathBuf` it gives
    /// to `MountList::default_baseline`), sets `PATH` to
    /// `path_override` (or [`CANONICAL_PATH`]) with each entry of
    /// `path_additions` *prepended* in CLI order, then walks
    /// [`PASSTHROUGH_NAMES`] forwarding each host value that's set
    /// and UTF-8, then walks `std::env::vars()` to forward every
    /// `LC_*` it finds.
    ///
    /// Reads `std::env`. Because `std::env::vars`/`var` walk a global
    /// table, the result depends on the calling process's env. That's
    /// intentional: `show --json` and `run` should produce the same
    /// inventory for the same invocation, so both call this function
    /// the same way.
    pub fn default_baseline(
        home: &Path,
        path_override: Option<&str>,
        path_additions: &[String],
    ) -> Self {
        let mut list = Self::new();

        // HOME. The literal path mounts use, not the host env value
        // — env and mounts have to agree on the path or the agent
        // sees a `$HOME` pointing somewhere different from where its
        // files live. `to_string_lossy().into_owned()` is fine in
        // practice: user homes are UTF-8, and even on a pathological
        // non-UTF-8 host the lossy conversion is consistent with
        // what the mount layer already serialized for the same
        // `Path`.
        list.set(
            "HOME",
            home.to_string_lossy().into_owned(),
            EnvSource::Default,
        );

        // PATH. Always set as a literal — never inherit. Host PATH
        // typically has `~/.local/bin`, `~/.cargo/bin`, `/snap/bin`,
        // etc., and none of those exist inside the sandbox (tmpfs
        // `$HOME`, no `/snap` mount). Starting from a known-good
        // canonical PATH avoids broken entries and noise; users who
        // really need more can pass `--path` (whole replacement) or
        // repeated `-p/--path-add` (extra directory).
        //
        // `-p` entries are *prepended* (in CLI order) to the
        // canonical-or-override base, so `-p /a -p /b` yields
        // `/a:/b:<base>`. This matches fish's `fish_add_path`, the
        // POSIX-shell idiom `export PATH=$HOME/.cargo/bin:$PATH`, and
        // every coding-tool installer (rustup, pyenv, nvm, …): when a
        // user adds a custom directory they almost always want it
        // *found first*, both because that's the sole reason to add
        // it and because user dirs typically hold unique binaries
        // anyway (so the "shadowing" risk is theoretical).
        let base = path_override.unwrap_or(CANONICAL_PATH);
        let mut path_value = String::new();
        for dir in path_additions {
            path_value.push_str(dir);
            path_value.push(':');
        }
        path_value.push_str(base);
        list.set("PATH", path_value, EnvSource::Default);

        // Curated passthroughs. `std::env::var` returns `Err` for both
        // unset *and* non-UTF-8 values; we treat both the same way
        // (drop), since coding-agent env vars are UTF-8 in practice
        // and the alternative (`var_os` + `to_string_lossy`) would
        // hide a corruption rather than reveal it.
        for name in PASSTHROUGH_NAMES {
            match std::env::var(name) {
                Ok(value) => {
                    list.set(name, value, EnvSource::Default);
                }
                Err(std::env::VarError::NotPresent) => {
                    trace!(name, "passthrough env var unset on host; dropping");
                }
                Err(std::env::VarError::NotUnicode(_)) => {
                    debug!(
                        name,
                        "passthrough env var has non-UTF-8 value; dropping"
                    );
                }
            }
        }

        // `LC_*` dynamic enumeration. POSIX defines `LC_ALL`,
        // `LC_TIME`, `LC_NUMERIC`, `LC_COLLATE`, `LC_CTYPE`,
        // `LC_MESSAGES`, `LC_MONETARY`, plus glibc adds `LC_PAPER`,
        // `LC_NAME`, `LC_ADDRESS`, `LC_TELEPHONE`, `LC_MEASUREMENT`,
        // `LC_IDENTIFICATION`. Hardcoding any list is fragile —
        // distros add new ones. Iterating the host env is honest:
        // forward whatever `LC_*` actually exists.
        for (key, value) in std::env::vars() {
            if key.starts_with("LC_") {
                list.set(&key, value, EnvSource::Default);
            }
        }

        list
    }

    /// Upsert by name. If an entry with the same `name` already
    /// exists, replace it; otherwise append.
    ///
    /// Upsert (rather than append) keeps the inventory free of
    /// duplicate `--setenv` triples when a user overrides a baseline
    /// var (e.g. `redoubtful run -e PATH=/only/this`). Bwrap takes
    /// the last `--setenv` for any given name, so append would also
    /// be correct *at runtime*, but `show --json` would show two
    /// entries for `PATH` which is just confusing.
    pub fn set(
        &mut self,
        name: &str,
        value: String,
        source: EnvSource,
    ) -> &mut Self {
        if let Some(slot) = self.0.iter_mut().find(|e| e.name == name) {
            slot.value = value;
            slot.source = source;
        } else {
            self.0.push(EnvEntry {
                name: name.to_owned(),
                value,
                source,
            });
        }
        self
    }

    /// Remove the entry with the given name, if any. No-op if absent.
    ///
    /// Used by [`EnvOpts::apply`] for the `-e VAR` (passthrough)
    /// case when `VAR` is unset on the host: the user's explicit
    /// override drops the baseline, even if the baseline had set
    /// the var. (`-e FOO` means "use whatever I have"; if I have
    /// nothing, the sandbox should also have nothing.)
    pub fn unset(&mut self, name: &str) {
        self.0.retain(|e| e.name != name);
    }

    /// Iterate over entries in declaration order.
    pub fn iter(&self) -> std::slice::Iter<'_, EnvEntry> {
        self.0.iter()
    }

    /// Number of entries. Used for tracing fields.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// A single CLI-supplied env override: a name plus either a literal
/// value (`-e FOO=bar`) or a passthrough request (`-e FOO`).
///
/// Parses from `VAR[=VALUE]` via [`FromStr`], which clap picks up
/// automatically — no `value_parser` plumbing required on
/// [`EnvOpts`].
#[derive(Debug, Clone)]
pub struct EnvSpec {
    /// The variable name.
    pub name: String,
    /// What to do with it: set a literal, or passthrough host.
    pub value: EnvSpecValue,
}

/// What `-e VAR[=VALUE]` says to do with the variable.
#[derive(Debug, Clone)]
pub enum EnvSpecValue {
    /// `-e FOO=bar` (or `-e FOO=` for the empty string).
    Literal(String),
    /// `-e FOO` (no `=`): forward host's `$FOO` if set, else drop.
    Passthrough,
}

impl FromStr for EnvSpec {
    type Err = String;

    /// Parse `VAR` (passthrough) or `VAR=VALUE` (literal).
    ///
    /// Distinguishes by *presence of `=`*, not by whether the
    /// post-`=` string is empty: `-e FOO=` is a literal empty
    /// string, while `-e FOO` is a passthrough. This matches the
    /// docker `-e` convention coding-agent users are likely to
    /// already have a mental model for.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (name, value) = match s.split_once('=') {
            Some((name, value)) => {
                (name, EnvSpecValue::Literal(value.to_owned()))
            }
            None => (s, EnvSpecValue::Passthrough),
        };
        if name.is_empty() {
            return Err(format!("env spec {s:?} has empty variable name"));
        }
        // Reject `=` inside the name half. `split_once('=')` already
        // splits at the first `=`, so anything with no `=` lands
        // here as a passthrough name; we only need to guard against
        // names containing whitespace or NUL, which would be a
        // corrupt setenv. Posix env var names are
        // `[A-Za-z_][A-Za-z0-9_]*`; bwrap will refuse `\0` and may
        // refuse `=`. We surface the more obviously broken cases
        // before bwrap does.
        if name.contains('\0') {
            return Err(format!("env spec {s:?} variable name contains NUL"));
        }
        Ok(EnvSpec {
            name: name.to_owned(),
            value,
        })
    }
}

/// Shared CLI options for env flags.
///
/// Flattened with `#[command(flatten)]` into any subcommand that
/// builds an [`EnvList`] (`run`, `show`). Keeps the flag definitions
/// in one place so the audit/test allowlist stays in sync with the
/// runtime.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct EnvOpts {
    /// Set or pass through an environment variable. Repeatable.
    /// `-e FOO=bar` sets `FOO=bar`; `-e FOO` forwards the host's
    /// `$FOO` (drops the entry if unset).
    #[arg(short = 'e', long = "env", value_name = "VAR[=VALUE]")]
    pub env: Vec<EnvSpec>,

    /// Override the canonical `PATH` baked into the sandbox
    /// (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`).
    /// Useful when a project really needs an interpreter that lives
    /// outside the standard system path; use sparingly.
    #[arg(long = "path", value_name = "PATH")]
    pub path: Option<String>,

    /// Add an extra directory to the front of the sandbox `PATH`.
    /// Repeatable. Coding agents often install in unusual locations
    /// (`~/.local/bin`, `/opt/<vendor>/bin`, language-specific
    /// `~/.cargo/bin`/`~/.npm-global/bin`/...); rather than rebuild
    /// the whole canonical PATH with `--path` just to add one entry,
    /// `-p DIR` prepends `DIR` to the canonical (or `--path`) value
    /// so the added tools are found first — same behavior as fish's
    /// `fish_add_path` and the `PATH=$DIR:$PATH` idiom. Each `-p`
    /// adds one directory; multiple `-p`s prepend in CLI order
    /// (`-p /a -p /b` → `/a:/b:<base>`).
    #[arg(short = 'p', long = "path-add", value_name = "DIR")]
    pub path_add: Vec<String>,
}

impl EnvOpts {
    /// Apply CLI env overrides on top of an existing [`EnvList`].
    ///
    /// Each `-e` is processed in CLI order, upserting into `list`.
    /// `-e VAR` (passthrough) with `VAR` unset on the host removes
    /// any existing entry with that name — the user's "use my
    /// host's value" override drops the baseline if there's nothing
    /// to forward.
    ///
    /// Note: `--path` is *not* applied here; it's a parameter of
    /// [`EnvList::default_baseline`] so the canonical `PATH` is set
    /// once and correctly even before any `-e` runs.
    pub fn apply(&self, list: &mut EnvList) {
        for spec in &self.env {
            match &spec.value {
                EnvSpecValue::Literal(v) => {
                    list.set(&spec.name, v.clone(), EnvSource::Cli);
                }
                EnvSpecValue::Passthrough => {
                    match std::env::var(&spec.name) {
                        Ok(value) => {
                            list.set(&spec.name, value, EnvSource::Cli);
                        }
                        Err(_) => {
                            // Unset OR non-UTF-8 — drop. Document at
                            // debug so users running with
                            // `RUST_LOG=redoubtful=debug` can see
                            // exactly which `-e VAR` requests went
                            // un-honored.
                            debug!(
                                name = spec.name.as_str(),
                                "passthrough -e var unset/non-UTF-8 on host; dropping"
                            );
                            list.unset(&spec.name);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> std::result::Result<EnvSpec, String> {
        s.parse()
    }

    /// A stable fake home for unit tests. Real value doesn't matter
    /// — these tests assert on what `default_baseline` writes given
    /// a path argument, not on whether the path exists.
    fn fake_home() -> &'static Path {
        Path::new("/home/test")
    }

    #[test]
    fn env_spec_literal_parses() {
        let spec = parse("FOO=bar").expect("parses");
        assert_eq!(spec.name, "FOO");
        match spec.value {
            EnvSpecValue::Literal(v) => assert_eq!(v, "bar"),
            EnvSpecValue::Passthrough => panic!("should be literal"),
        }
    }

    #[test]
    fn env_spec_literal_empty_value() {
        let spec = parse("FOO=").expect("parses");
        match spec.value {
            EnvSpecValue::Literal(v) => assert_eq!(v, ""),
            EnvSpecValue::Passthrough => panic!("`FOO=` is literal empty"),
        }
    }

    #[test]
    fn env_spec_passthrough_when_no_equals() {
        let spec = parse("FOO").expect("parses");
        match spec.value {
            EnvSpecValue::Passthrough => {}
            EnvSpecValue::Literal(_) => panic!("`FOO` should be passthrough"),
        }
    }

    #[test]
    fn env_spec_value_with_embedded_equals() {
        // `KEY=a=b=c` → literal value is `a=b=c` (only the first `=`
        // is the name/value separator). Common when users assign
        // URLs or `--flag=value`-shaped strings.
        let spec = parse("KEY=a=b=c").expect("parses");
        match spec.value {
            EnvSpecValue::Literal(v) => assert_eq!(v, "a=b=c"),
            EnvSpecValue::Passthrough => panic!("should be literal"),
        }
    }

    #[test]
    fn env_spec_rejects_empty_name() {
        assert!(parse("").is_err());
        assert!(parse("=value").is_err());
    }

    #[test]
    fn env_list_set_appends_then_upserts() {
        let mut list = EnvList::new();
        list.set("A", "1".to_owned(), EnvSource::Default);
        list.set("B", "2".to_owned(), EnvSource::Default);
        assert_eq!(list.len(), 2);

        // Upsert A — replaces, doesn't append.
        list.set("A", "1b".to_owned(), EnvSource::Cli);
        assert_eq!(list.len(), 2);
        let a = list.iter().find(|e| e.name == "A").expect("A present");
        assert_eq!(a.value, "1b");
        assert!(matches!(a.source, EnvSource::Cli));

        // Order is preserved: A first (its slot was reused), then B.
        let names: Vec<&str> = list.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn env_list_unset_removes_entry() {
        let mut list = EnvList::new();
        list.set("A", "1".to_owned(), EnvSource::Default);
        list.set("B", "2".to_owned(), EnvSource::Default);
        list.unset("A");
        assert_eq!(list.len(), 1);
        assert_eq!(list.iter().next().expect("B").name, "B");
        // Unsetting a missing name is a no-op.
        list.unset("Z");
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn default_baseline_sets_canonical_path_when_no_override() {
        let list = EnvList::default_baseline(fake_home(), None, &[]);
        let path = list
            .iter()
            .find(|e| e.name == "PATH")
            .expect("PATH baseline entry");
        assert_eq!(path.value, CANONICAL_PATH);
        assert!(matches!(path.source, EnvSource::Default));
    }

    #[test]
    fn default_baseline_respects_path_override() {
        let list = EnvList::default_baseline(
            fake_home(),
            Some("/only/this:/and/this"),
            &[],
        );
        let path = list
            .iter()
            .find(|e| e.name == "PATH")
            .expect("PATH baseline entry");
        assert_eq!(path.value, "/only/this:/and/this");
    }

    #[test]
    fn default_baseline_prepends_path_additions_to_canonical() {
        // No `--path`, two `-p` entries: prepend in CLI order in
        // front of the canonical baseline. Matches `fish_add_path`
        // and the `PATH=$DIR:$PATH` shell idiom — added dirs are
        // found first, canonical PATH still present behind them.
        let additions = vec![
            "/opt/agent/bin".to_owned(),
            "/home/me/.cargo/bin".to_owned(),
        ];
        let list = EnvList::default_baseline(fake_home(), None, &additions);
        let path = list
            .iter()
            .find(|e| e.name == "PATH")
            .expect("PATH baseline entry");
        assert_eq!(
            path.value,
            format!("/opt/agent/bin:/home/me/.cargo/bin:{CANONICAL_PATH}"),
        );
    }

    #[test]
    fn default_baseline_prepends_path_additions_to_override() {
        // `--path` plus `-p`: additions go in front of the override,
        // same prepend semantics as the canonical case.
        let additions = vec!["/extra".to_owned()];
        let list = EnvList::default_baseline(
            fake_home(),
            Some("/only/this"),
            &additions,
        );
        let path = list
            .iter()
            .find(|e| e.name == "PATH")
            .expect("PATH baseline entry");
        assert_eq!(path.value, "/extra:/only/this");
    }

    #[test]
    fn default_baseline_sets_home_from_path_arg() {
        // HOME comes from the `home` argument, not from the host env
        // — that's how env and the bind-mount layer stay in sync on
        // the same `PathBuf`.
        let list =
            EnvList::default_baseline(Path::new("/home/agent"), None, &[]);
        let home = list
            .iter()
            .find(|e| e.name == "HOME")
            .expect("HOME baseline entry");
        assert_eq!(home.value, "/home/agent");
        assert!(matches!(home.source, EnvSource::Default));
    }

    #[test]
    fn env_opts_apply_literal_upserts_baseline() {
        let mut list = EnvList::default_baseline(fake_home(), None, &[]);
        let opts = EnvOpts {
            env: vec![EnvSpec {
                name: "PATH".to_owned(),
                value: EnvSpecValue::Literal("/only/this".to_owned()),
            }],
            path: None,
            path_add: Vec::new(),
        };
        opts.apply(&mut list);
        let path = list
            .iter()
            .find(|e| e.name == "PATH")
            .expect("PATH still present");
        assert_eq!(path.value, "/only/this");
        assert!(matches!(path.source, EnvSource::Cli));
        // No duplicate entries.
        assert_eq!(
            list.iter().filter(|e| e.name == "PATH").count(),
            1,
            "upsert should keep PATH unique",
        );
    }
}

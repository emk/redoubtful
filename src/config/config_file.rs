//! Loading and parsing the on-disk `~/.config/redoubtful/config.toml`.
//!
//! [`ConfigFile`] is the top-level deserialized form: a map of named
//! [`ProfileDecl`] blocks and nothing else. `deny_unknown_fields`
//! catches typos at the file level so a stray top-level key is
//! rejected instead of silently landing in a catch-all.
//!
//! [`ConfigFile::load_or_init`] reads the file (or, on first run,
//! drops [`DEFAULT_CONFIG`] onto disk and re-reads it).
//! [`ConfigFile::finalize_config_with_cli`] runs the full pipeline
//! `cmd_run` and `cmd_show` share: load → normalize `~/`-prefixed
//! paths → resolve the `uses` chain → validate every profile (both
//! TOML and CLI) → resolve each into a [`Profile`] → push the CLI as
//! the last layer → fold-merge right-biased → finalize. The embedded
//! default asset is included via `include_str!` so the binary is
//! self-contained and the dumped file matches the asset
//! byte-for-byte (a `toml::ser` round-trip would strip the
//! explanatory header comments).
//!
//! [`resolve_uses`] walks the `uses` graph depth-first, returning
//! profiles in application order. Strict no-repeats: a profile
//! reached via two `uses` paths (or listed twice on the CLI) is an
//! error, not a silent merge — keeps the downstream merge fold
//! trivially well-defined since each profile contributes exactly
//! once.

use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::Path,
};

use serde::Deserialize;

use super::{
    Decl, Finalize, NormalizeConfigPaths,
    profile::{Profile, ProfileDecl},
};
use crate::{
    dirs::{config_path, home_dir},
    prelude::*,
};

/// Parsed `~/.config/redoubtful/config.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// The named profiles defined in `[profile.NAME]` blocks.
    /// Empty when the user hasn't declared any.
    #[serde(default, rename = "profile")]
    pub profile_decls: HashMap<String, ProfileDecl>,
}

/// The embedded default-config text, dropped onto disk byte-for-byte
/// the first time `redoubtful run` or `redoubtful show` finds the
/// user's config absent. `include_str!` pulls the file in at compile
/// time, so the binary is self-contained and the dumped file matches
/// the asset exactly (preserving the explanatory header comments
/// that a `toml::ser` round-trip would strip).
pub const DEFAULT_CONFIG: &str =
    include_str!("../../assets/config.toml.default");

impl ConfigFile {
    /// Load the user's config, auto-initializing the embedded default
    /// when the file is missing.
    ///
    /// On first run the file at `path` doesn't exist; we write the
    /// embedded asset and emit a one-line stderr notice naming the
    /// file. Subsequent runs hit the existing-file path and behave
    /// like a plain read-and-parse. An *empty* file (e.g. after the
    /// user manually `truncate -s 0`'d it) is honored as "no profiles
    /// defined" — we don't re-init over user-edited state.
    ///
    /// Permission-denied / read-only-home / any other I/O error besides
    /// `NotFound` still propagates as [`Error::CouldNotReadConfig`].
    /// Failures during the auto-init write (parent-dir creation, the
    /// write itself) propagate as [`Error::CouldNotWriteConfig`] so the
    /// user can tell apart "I can't read your config" from "I tried
    /// to install one and couldn't."
    pub fn load_or_init(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(source) => parse_config(&source, path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                init_default_config(path)?;
                // Re-parse the just-written file rather than the
                // embedded constant — keeps a single source of truth
                // (`fs::read_to_string`) for what the resolver sees,
                // and means the embedded-vs-on-disk byte mismatch (if
                // it ever existed) would surface as a parse divergence
                // here rather than silently.
                let source = fs::read_to_string(path).map_err(|e| {
                    Error::could_not_read_config(path.to_path_buf(), e)
                })?;
                parse_config(&source, path)
            }
            Err(e) => Err(Error::could_not_read_config(path.to_path_buf(), e)),
        }
    }

    /// Load the user's config, resolve the user's `uses` chain, fold
    /// in the CLI's [`ProfileDecl`] as the last layer, and finalize.
    /// Returns a fully-baked [`Profile`] ready for argv construction.
    ///
    /// Single source of truth for the pipeline `cmd_run` and `cmd_show`
    /// share: load (auto-init on first run) → normalize `~/`-prefixed
    /// paths in every profile → resolve the `-p` flags into an
    /// application-ordered list → validate every profile (TOML + CLI)
    /// up front → resolve each into a [`Profile`] → push the CLI as
    /// the last layer → fold-merge right-biased → finalize so the
    /// per-domain baselines (system mounts, canonical PATH, etc.)
    /// land underneath every user contribution.
    pub fn finalize_config_with_cli(cli: &ProfileDecl) -> Result<Profile> {
        let cfg_path = config_path()?;
        let mut config = Self::load_or_init(&cfg_path)?;

        // `~/` normalization. Takes HOME up-front; the sub-domain
        // `base_config`s read HOME again later from the same source.
        // Done here (not in `load_or_init`) so `load_or_init` stays a
        // pure parse-from-disk constructor that callers can drive
        // without pulling in a HOME requirement.
        let home = home_dir()?;
        for p in config.profile_decls.values_mut() {
            p.normalize_config_paths(&home)?;
        }

        // Resolve the uses-chain in topological order.
        let resolved = resolve_uses(&config, &cli.uses, &cfg_path)?;

        // Validate every profile (TOML + CLI) before resolving
        // anything — a malformed TOML profile that goes unused on
        // *this* invocation would otherwise slip through, but resolved
        // profiles are exactly the ones whose contributions reach the
        // sandbox, so a friendly diagnostic up front beats a
        // mid-pipeline failure.
        for (_name, decl) in &resolved {
            decl.validate()?;
        }
        cli.validate()?;

        // Resolve each into a `Profile`, push the CLI as the last
        // layer, fold-merge right-biased, then finalize. Capacity is
        // resolved-count + 1 (the CLI layer); use `saturating_add` so
        // a (theoretical) `usize::MAX`-sized resolved chain doesn't
        // panic on overflow — we'd OOM long before the +1 mattered,
        // but the lint wants overflow-safe arithmetic.
        let mut chain: Vec<Profile> =
            Vec::with_capacity(resolved.len().saturating_add(1));
        for (_name, decl) in &resolved {
            chain.push(decl.resolve()?);
        }
        chain.push(cli.resolve()?);
        Ok(Profile::merge_all_right_biased(&chain).finalize())
    }
}

/// Write [`DEFAULT_CONFIG`] to `path`, creating the parent dir
/// (including intermediate XDG layers) if needed. Emits a one-line
/// stderr notice naming the file so the user knows *something* just
/// happened in their home directory — a silent file creation would
/// be a usability bug.
fn init_default_config(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            Error::could_not_write_config(path.to_path_buf(), e)
        })?;
    }
    fs::write(path, DEFAULT_CONFIG)
        .map_err(|e| Error::could_not_write_config(path.to_path_buf(), e))?;
    // `eprintln!` (not `info!`) for the notice: tracing-subscriber
    // adds a level/timestamp prefix unsuitable for a one-shot
    // user-facing message about a side effect they didn't ask for.
    debug!("redoubtful: wrote default config to {}", path.display());
    Ok(())
}

/// Resolve `requested` profile names against `config` via
/// depth-first walk of `uses`, returning the profiles in
/// application order.
///
/// **Strict no-repeats.** If a profile is reached more than once
/// (whether via two `uses` paths or via the CLI listing it twice),
/// it's an error — not a silent skip. This forces the user to be
/// explicit about which path they meant; it also keeps the merge
/// fold trivially well-defined since each profile contributes
/// exactly once.
///
/// `config_path` is threaded through purely for diagnostics — the
/// "unknown profile" and "already included" messages name the file
/// the user should look in.
///
/// Returns `Vec<(name, &Profile)>` in **application order**: a
/// profile's `uses` deps come before the profile itself, and the
/// requested profiles are processed left-to-right. The caller
/// applies their contributions in this order; the merge fold's
/// right-biased `Option::or` then naturally yields last-wins
/// scalar semantics.
pub fn resolve_uses<'a>(
    config: &'a ConfigFile,
    requested: &[String],
    config_path: &Path,
) -> Result<Vec<(&'a str, &'a ProfileDecl)>> {
    let mut order: Vec<(&'a str, &'a ProfileDecl)> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for name in requested {
        resolve_uses_helper(config, name, &mut order, &mut seen, config_path)?;
    }
    Ok(order)
}

/// DFS helper for [`resolve_uses`]. Lookup happens against
/// `config.profiles`, which is a `HashMap<String, Profile>` —
/// indexing yields `&Profile`, and the lifetime of the returned
/// reference matches the `'a` on `config`. Recursion depth is
/// bounded by the number of `uses` edges, which is bounded by the
/// number of profiles (no cycles can form: strict no-repeats
/// rejects a back-edge before it closes a cycle).
fn resolve_uses_helper<'a>(
    config: &'a ConfigFile,
    name: &str,
    order: &mut Vec<(&'a str, &'a ProfileDecl)>,
    seen: &mut HashSet<&'a str>,
    config_path: &Path,
) -> Result<()> {
    let (key, profile) =
        config.profile_decls.get_key_value(name).ok_or_else(|| {
            Error::unknown_profile(name, config_path.to_path_buf())
        })?;
    if !seen.insert(key.as_str()) {
        return Err(Error::repeated_profile(name, config_path.to_path_buf()));
    }
    for dep in &profile.uses {
        resolve_uses_helper(config, dep, order, seen, config_path)?;
    }
    order.push((key.as_str(), profile));
    Ok(())
}

/// Parse `source` as a [`ConfigFile`], attaching `path` and the
/// source text to any error so miette can render the byte span as
/// an underline. Separated from [`load_or_init`] so unit tests can
/// exercise the parse-error surface without going through the
/// filesystem.
pub(super) fn parse_config(source: &str, path: &Path) -> Result<ConfigFile> {
    toml::from_str::<ConfigFile>(source).map_err(|e| {
        Error::config_parse(path.to_path_buf(), source.to_owned(), &e)
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::mount::MountAccess;

    /// Parse a TOML string with a fake path. Tests assert on the
    /// resulting `Error::ConfigParse` shape — message, path, and
    /// whether a span was produced. Span byte offsets are noisy to
    /// hardcode (whitespace shifts them), so tests instead check
    /// that the underlying source slice at the span lines up with
    /// what the user would see underlined.
    fn parse(source: &str) -> Result<ConfigFile> {
        parse_config(source, Path::new("test.toml"))
    }

    /// Pull the byte slice the miette span points at, or `None`
    /// when the error didn't pinpoint a location. Used to assert
    /// "the underline lands on this token" without hardcoding
    /// whitespace-sensitive offsets.
    fn span_slice<'a>(err: &Error, source: &'a str) -> Option<&'a str> {
        match err {
            Error::ConfigParse(inner) => {
                let span = inner.span.as_ref()?;
                let offset = span.offset();
                let end = offset.checked_add(span.len())?;
                source.get(offset..end)
            }
            other => panic!("expected ConfigParse, got {other:?}"),
        }
    }

    #[test]
    fn empty_file_parses_to_no_profiles() {
        let cfg = parse("").expect("empty file is a valid config");
        assert!(
            cfg.profile_decls.is_empty(),
            "no [profile.*] tables defined"
        );
    }

    #[test]
    fn whitespace_only_file_parses_to_no_profiles() {
        let cfg =
            parse("\n\n# just a comment\n").expect("comment-only is valid");
        assert!(cfg.profile_decls.is_empty());
    }

    #[test]
    fn empty_profile_table_round_trips() {
        let cfg = parse("[profile.rust]\n").expect("parses");
        assert_eq!(cfg.profile_decls.len(), 1);
        let rust = cfg.profile_decls.get("rust").expect("rust profile present");
        assert!(rust.uses.is_empty());
        assert!(rust.mount_decls.mounts.is_empty());
        assert!(rust.mount_decls.readonly.is_none());
        assert!(rust.forward_decls.forwards.is_empty());
        assert!(rust.env_decls.env.is_empty());
        assert!(rust.env_decls.path.is_none());
        assert!(rust.env_decls.path_add.is_empty());
    }

    #[test]
    fn uses_field_round_trips() {
        let cfg = parse("[profile.full]\nuses = [\"git-config\", \"rust\"]\n")
            .expect("parses");
        let full = cfg.profile_decls.get("full").expect("full profile present");
        assert_eq!(full.uses, vec!["git-config", "rust"]);
    }

    #[test]
    fn mount_with_host_only_defaults_sandbox_and_access() {
        // Single inline table with just `host` — sandbox should
        // default to host, access to ro. Mirrors CLI's
        // `-m HOST_PATH` single-arg behavior.
        let cfg = parse(
            r#"
[profile.x]
mounts = [{ host = "/etc/gitconfig" }]
"#,
        )
        .expect("parses");
        let x = cfg.profile_decls.get("x").expect("x");
        let m = x.mount_decls.mounts.first().expect("one mount");
        assert_eq!(m.host.get_ref(), &PathBuf::from("/etc/gitconfig"));
        assert!(m.sandbox.is_none());
        assert_eq!(m.sandbox_path(), Path::new("/etc/gitconfig"));
        assert_eq!(m.access_mode(), MountAccess::Ro);
    }

    #[test]
    fn mount_full_form_round_trips() {
        let cfg = parse(
            r#"
[profile.x]
mounts = [{ host = "/h", sandbox = "/s", access = "rw" }]
"#,
        )
        .expect("parses");
        let m = cfg
            .profile_decls
            .get("x")
            .expect("x")
            .mount_decls
            .mounts
            .first()
            .expect("one mount");
        assert_eq!(m.host.get_ref(), &PathBuf::from("/h"));
        assert_eq!(m.sandbox_path(), Path::new("/s"));
        assert_eq!(m.access_mode(), MountAccess::Rw);
    }

    #[test]
    fn mount_unknown_field_reports_span() {
        // `MountDecl` derives `Deserialize` with
        // `deny_unknown_fields`, so a typo like `host_path` instead
        // of `host` surfaces as a span at the bad key.
        let source = "[profile.x]\nmounts = [{ host_path = \"/x\" }]\n";
        let err = parse(source).expect_err("bad field must error");
        let slice =
            span_slice(&err, source).expect("toml pinpoints unknown field");
        assert!(
            slice.contains("host_path"),
            "expected span at `host_path`; got {slice:?} from {err:?}",
        );
    }

    #[test]
    fn forward_short_form_defaults_sandbox_port() {
        let cfg = parse("[profile.x]\nforwards = [{ host_port = 8080 }]\n")
            .expect("parses");
        let f = cfg
            .profile_decls
            .get("x")
            .expect("x")
            .forward_decls
            .forwards
            .first()
            .expect("one forward");
        assert_eq!(*f.host_port.get_ref(), 8080);
        assert!(f.sandbox_port.is_none());
        assert_eq!(f.sandbox_port(), 8080);
    }

    #[test]
    fn env_passthrough_omits_value() {
        let cfg = parse("[profile.x]\nenv = [{ name = \"MY_VAR\" }]\n")
            .expect("parses");
        let e = cfg
            .profile_decls
            .get("x")
            .expect("x")
            .env_decls
            .env
            .first()
            .expect("one env");
        assert_eq!(e.name.get_ref(), "MY_VAR");
        assert!(e.value.is_none(), "passthrough has no value");
    }

    #[test]
    fn env_literal_includes_value() {
        let cfg =
            parse("[profile.x]\nenv = [{ name = \"FOO\", value = \"bar\" }]\n")
                .expect("parses");
        let e = cfg
            .profile_decls
            .get("x")
            .expect("x")
            .env_decls
            .env
            .first()
            .expect("one env");
        assert_eq!(e.name.get_ref(), "FOO");
        assert_eq!(e.value.as_deref(), Some("bar"));
    }

    #[test]
    fn path_add_round_trips() {
        let cfg = parse(
            "[profile.x]\npath_add = [\"~/.opencode/bin\", \"/opt/x/bin\"]\n",
        )
        .expect("parses");
        let path_add =
            &cfg.profile_decls.get("x").expect("x").env_decls.path_add;
        assert_eq!(
            path_add,
            &vec![
                std::ffi::OsString::from("~/.opencode/bin"),
                std::ffi::OsString::from("/opt/x/bin"),
            ],
        );
    }

    #[test]
    fn malformed_toml_renders_with_span() {
        let source = "[profile.rust\nuses = []\n";
        let err = parse(source).expect_err("malformed TOML must error");
        assert!(matches!(err, Error::ConfigParse { .. }));
        let slice = span_slice(&err, source);
        assert!(slice.is_some(), "expected a span, got {err:?}");
    }

    #[test]
    fn unknown_top_level_field_renders_with_span_at_field() {
        let source = "something_else = 1\n";
        let err = parse(source).expect_err("unknown field must error");
        let slice =
            span_slice(&err, source).expect("toml pinpoints unknown field");
        assert!(
            slice.contains("something_else"),
            "expected span at `something_else`; got {slice:?} from {err:?}",
        );
    }

    #[test]
    fn unknown_profile_field_renders_with_span_at_field() {
        // `deny_unknown_fields` on `Profile` catches typos like
        // `use` instead of `uses`. The user gets a span on the bad
        // key, not silent acceptance.
        let source = "[profile.rust]\nuse = [\"x\"]\n";
        let err = parse(source).expect_err("unknown field must error");
        let slice =
            span_slice(&err, source).expect("toml pinpoints unknown field");
        assert!(
            slice.contains("use"),
            "expected span at `use`; got {slice:?} from {err:?}",
        );
    }

    #[test]
    fn type_error_renders_with_span() {
        let source = "[profile.rust]\nuses = \"not-a-list\"\n";
        let err = parse(source).expect_err("type error must error");
        let slice =
            span_slice(&err, source).expect("toml pinpoints type errors");
        assert!(
            slice.contains("not-a-list"),
            "expected span at value; got {slice:?} from {err:?}",
        );
    }

    #[test]
    fn mount_spec_in_toml_captures_real_span_for_host() {
        // Confirms the `Spanned<PathBuf>` round-trip — TOML's
        // `Deserialize` for `Spanned` populates the byte range, so
        // a downstream validation error can render with miette
        // pointing at the offending line.
        let source = r#"[profile.x]
mounts = [{ host = "/etc/gitconfig" }]
"#;
        let cfg = parse(source).expect("parses");
        let m = cfg
            .profile_decls
            .get("x")
            .expect("x")
            .mount_decls
            .mounts
            .first()
            .expect("one mount");
        let span = m.host.span();
        assert!(
            span.end > span.start,
            "host span must be non-empty for TOML inputs: {span:?}",
        );
        // The span underlines the quoted host string itself, so
        // the byte slice should contain the literal path.
        let slice = &source[span.start..span.end];
        assert!(
            slice.contains("/etc/gitconfig"),
            "expected span at host string; got {slice:?}",
        );
    }

    #[test]
    fn deny_unknown_fields_catches_top_level_typo_through_flatten() {
        // The flattened `MountDecls`/`ForwardDecls`/`EnvVarDecls` would
        // otherwise allow unrelated TOML keys to silently land in
        // the catch-all that flatten implies. `deny_unknown_fields`
        // on the container *does* propagate (we verified
        // experimentally) — a typo at the top level of a profile
        // is rejected with miette pointing at the bad key.
        let source = "[profile.x]\nmont = [\"/etc/x\"]\n";
        let err = parse(source).expect_err("typo must error");
        let slice =
            span_slice(&err, source).expect("toml pinpoints unknown field");
        assert!(
            slice.contains("mont"),
            "expected span at `mont`; got {slice:?} from {err:?}",
        );
    }

    // ===== Resolution =====

    /// Build a `ConfigFile` from TOML for the resolution tests.
    /// Skips path normalization since these fixtures don't exercise
    /// paths.
    fn cfg(source: &str) -> ConfigFile {
        parse(source).expect("fixture parses")
    }

    /// The names returned by `resolve_uses`, in order. Tests
    /// assert on this — `&ProfileDecl` references are awkward to
    /// `assert_eq!`, but the order alone proves the DFS is correct.
    fn resolved_names(config: &ConfigFile, requested: &[&str]) -> Vec<String> {
        let owned: Vec<String> =
            requested.iter().map(|s| (*s).to_string()).collect();
        let order = resolve_uses(config, &owned, Path::new("test.toml"))
            .expect("resolves");
        order.into_iter().map(|(n, _)| n.to_string()).collect()
    }

    #[test]
    fn resolve_single_profile_with_no_uses() {
        let c = cfg("[profile.rust]\n");
        assert_eq!(resolved_names(&c, &["rust"]), vec!["rust"]);
    }

    #[test]
    fn resolve_walks_uses_depth_first_deps_before_self() {
        // `full` uses [a, b]; `a` uses [c]. Order: c, a, b, full.
        // DFS finishes a subtree before moving to the next sibling.
        let c = cfg(r#"
[profile.full]
uses = ["a", "b"]
[profile.a]
uses = ["c"]
[profile.b]
[profile.c]
"#);
        assert_eq!(resolved_names(&c, &["full"]), vec!["c", "a", "b", "full"],);
    }

    #[test]
    fn resolve_unknown_profile_errors() {
        let c = cfg("[profile.x]\n");
        let err = resolve_uses(
            &c,
            &["does-not-exist".to_string()],
            Path::new("test.toml"),
        )
        .expect_err("unknown name must error");
        assert!(matches!(err, Error::UnknownProfile { .. }));
    }

    #[test]
    fn resolve_unknown_uses_dep_errors() {
        // `[profile.bad]` references a missing `uses` dep.
        let c = cfg(r#"
[profile.bad]
uses = ["nope"]
"#);
        let err =
            resolve_uses(&c, &["bad".to_string()], Path::new("test.toml"))
                .expect_err("missing uses dep must error");
        assert!(matches!(err, Error::UnknownProfile { .. }));
    }

    #[test]
    fn resolve_repeated_via_cli_errors() {
        let c = cfg("[profile.x]\n");
        let err = resolve_uses(
            &c,
            &["x".to_string(), "x".to_string()],
            Path::new("test.toml"),
        )
        .expect_err("repeated name must error");
        assert!(matches!(err, Error::RepeatedProfile { .. }));
    }

    #[test]
    fn resolve_repeated_via_diamond_errors() {
        // a->c, b->c. Resolving [a, b] would visit c twice. Strict
        // no-repeats rejects this rather than silently dedup'ing.
        let c = cfg(r#"
[profile.a]
uses = ["c"]
[profile.b]
uses = ["c"]
[profile.c]
"#);
        let err = resolve_uses(
            &c,
            &["a".to_string(), "b".to_string()],
            Path::new("test.toml"),
        )
        .expect_err("diamond must error");
        assert!(matches!(err, Error::RepeatedProfile { .. }));
    }

    #[test]
    fn resolve_self_cycle_is_repeated_error() {
        // `a` uses itself. The first visit inserts "a"; the
        // recursive descent into `uses=["a"]` hits the seen check
        // and errors as "already included" — same family of
        // problem, same handling.
        let c = cfg(r#"
[profile.a]
uses = ["a"]
"#);
        let err = resolve_uses(&c, &["a".to_string()], Path::new("test.toml"))
            .expect_err("self-cycle must error");
        assert!(matches!(err, Error::RepeatedProfile { .. }));
    }

    #[test]
    fn resolve_empty_request_is_empty_order() {
        let c = cfg("[profile.x]\n");
        assert!(resolved_names(&c, &[]).is_empty());
    }

    // ===== load_or_init + embedded default =====

    #[test]
    fn load_or_init_writes_default_when_missing() {
        // No file at the path → load_or_init writes the embedded
        // default and returns the parsed Config. The on-disk
        // content must match `DEFAULT_CONFIG` byte-for-byte.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("redoubtful").join("config.toml");
        let cfg = ConfigFile::load_or_init(&path).expect("auto-init succeeds");
        // The shipped default declares the `opencode` profile —
        // that's the v1 contract documented in `plans/CONFIG.md`.
        assert!(
            cfg.profile_decls.contains_key("opencode"),
            "default config must define [profile.opencode]; got {:?}",
            cfg.profile_decls.keys().collect::<Vec<_>>(),
        );
        // Byte-for-byte: the dump path must not re-serialize
        // through `toml::ser` (which would strip our explanatory
        // header comments).
        let on_disk =
            std::fs::read_to_string(&path).expect("written file readable");
        assert_eq!(on_disk, DEFAULT_CONFIG);
    }

    #[test]
    fn load_or_init_does_not_overwrite_existing_file() {
        // An empty file is honored as "no profiles defined" — the
        // user may have deliberately truncated it. We must NOT
        // re-init over their state.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").expect("write empty fixture");
        let cfg = ConfigFile::load_or_init(&path).expect("empty file parses");
        assert!(cfg.profile_decls.is_empty(), "empty file = no profiles");
        let on_disk = std::fs::read_to_string(&path).expect("read");
        assert_eq!(on_disk, "", "load_or_init must not overwrite");
    }

    #[test]
    fn load_or_init_parses_present_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[profile.x]\n").expect("write fixture");
        let cfg = ConfigFile::load_or_init(&path).expect("present file parses");
        assert!(cfg.profile_decls.contains_key("x"));
    }

    #[test]
    fn load_or_init_propagates_parse_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "= 1\n").expect("write fixture");
        let err = ConfigFile::load_or_init(&path)
            .expect_err("parse error must propagate");
        assert!(matches!(err, Error::ConfigParse(_)));
    }

    #[test]
    fn embedded_default_config_parses_cleanly() {
        // Compile-time-adjacent guard: a typo in the shipped
        // `assets/config.toml.default` would let us release a
        // binary that breaks every user's first run. This test
        // catches that before it ships.
        let cfg =
            parse_config(DEFAULT_CONFIG, Path::new("config.toml.default"))
                .expect("embedded default must parse");
        assert!(cfg.profile_decls.contains_key("opencode"));
    }
}

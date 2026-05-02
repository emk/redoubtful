//! `[profile.NAME]` aggregate: the `Decl` form a TOML block or CLI
//! invocation produces, the `Resolved` [`Profile`] aggregate the
//! sandbox runtime consumes, and the path-normalization step that
//! glues them together.
//!
//! [`ProfileDecl`] stores the same [`MountDecls`] / [`ForwardDecls`]
//! / [`EnvVarDecls`] structs the CLI uses, so a `[profile.NAME]`
//! block and a CLI invocation share one runtime representation, one
//! validation surface, and one [`Decl::resolve`] path. The TOML
//! schema is reflected by a private `Raw` helper inside
//! `ProfileDecl`'s hand-written [`Deserialize`] impl rather than via
//! `#[serde(flatten)]`-ing the three sub-decl types — see the
//! `ProfileDecl` doc comment for why flatten doesn't compose with
//! toml's `Spanned`. `#[serde(deny_unknown_fields)]` on `Raw` catches
//! typos at TOML parse time (the "you typo'd a field name and your
//! profile silently does nothing" failure mode is exactly what we
//! don't want).
//!
//! Span attribution lives *inside* the per-element decl types, on
//! the value that can fail validation ([`MountDecl::host`] is a
//! `Spanned<PathBuf>`, [`ForwardDecl::host_port`] is a
//! `Spanned<u16>`, [`EnvVarDecl::name`] is a `Spanned<String>`).
//! CLI-sourced decls use a `0..0` sentinel; TOML captures real byte
//! ranges via toml's [`Deserialize`] impl for `Spanned`. Downstream
//! validation errors can therefore render with miette pointing at
//! the offending line of the config that introduced them.
//!
//! Composition is `Decl::resolve` per profile (TOML uses-chain in
//! topological order, plus the CLI as the last layer), then
//! [`Finalize::merge_all_right_biased`] across the resulting
//! [`Profile`]s, then [`Finalize::finalize`] to bake the per-domain
//! baseline (system mounts, canonical PATH, etc.) underneath. Each
//! domain owns its own merge rule (mounts/forwards: left-then-right
//! `Vec::extend`; env: `BTreeMap` upsert with right-biased
//! `Option::or` for the scalar extras). The full pipeline lives in
//! [`crate::config::config_file::ConfigFile::finalize_config_with_cli`].
//!
//! Path normalization handles only a leading `~/`, only on TOML
//! inputs. CLI paths bypass this — the shell already expanded `~/`.
//! Anything else (`~user/`, `$VAR`, relative paths) is rejected
//! with [`Error::ConfigInvalidPath`] so the user's mental model
//! stays "config paths look like `~/x` or `/x`, period."

use std::{ffi::OsString, path::Path};

use serde::Deserialize;

use super::{
    env_var::EnvVarDecl,
    env_vars::{EnvVarDecls, EnvVars},
    forward::ForwardDecl,
    forwards::{ForwardDecls, Forwards},
    mount::MountDecl,
    mounts::{MountDecls, Mounts},
};
use crate::{
    config::{Decl, Finalize, NormalizeConfigPaths},
    prelude::*,
};

/// One named profile: `[profile.NAME] uses = [...]; mount = [...]; ...`.
///
/// Stores the CLI's [`MountDecls`], [`ForwardDecls`], and
/// [`EnvVarDecls`] directly so a TOML profile and a CLI invocation
/// share one runtime representation — same fields, same defaults,
/// same validation, same [`Decl::resolve`] path. Span attribution
/// lives inside each per-element decl (e.g. [`MountDecl::host`] is a
/// `Spanned<PathBuf>`), not on `ProfileDecl`.
///
/// `ProfileDecl` has a hand-written [`Deserialize`] impl rather than
/// `#[serde(flatten)]`-ing the three sub-decl types. Reason: serde's
/// flatten machinery internalizes flattened fields through a
/// `Map<String, Content>` representation, which strips toml's
/// `Spanned` magic signaling — so a flattened TOML profile would
/// error with "expected a spanned value" on every span-bearing decl
/// field. The custom impl deserializes a flat `Raw` view and repacks
/// it into the three sub-decls, preserving spans without forking the
/// types per source.
#[derive(Debug, Default, Clone, clap::Args)]
pub struct ProfileDecl {
    /// Names of other profiles this one transitively pulls in.
    /// Resolution is strict no-repeats: a profile reached via two
    /// `uses` paths is a config error, not a diamond to merge.
    ///
    /// TODO: Strongly consider whether this should be `--uses`.
    #[arg(short = 'p', long = "profile", value_name = "NAME")]
    pub uses: Vec<String>,

    /// Mount entries (`mount = [...]`) and the `readonly` toggle.
    #[clap(flatten)]
    pub mount_decls: MountDecls,

    /// Forward entries (`forward = [...]`).
    #[clap(flatten)]
    pub forward_decls: ForwardDecls,

    /// Env entries (`env = [...]`), the `path` override, and
    /// `path_add` list.
    #[clap(flatten)]
    pub env_decls: EnvVarDecls,
}

impl<'de> Deserialize<'de> for ProfileDecl {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Flat view of every key a `[profile.NAME]` block can carry,
        // mirroring the union of [`MountDecls`], [`ForwardDecls`], and
        // [`EnvVarDecls`] field sets. This is the single place where the
        // TOML schema is enumerated — `MountDecls` etc. own the runtime
        // representation, but their `Deserialize` derives can't be
        // composed via `flatten` while keeping `Spanned` working
        // (toml's span signaling is lost through serde's intermediate
        // Map). A new field in any Decls must be added here too — the
        // duplication is small, local, and obvious.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            uses: Vec<String>,
            #[serde(default)]
            mount: Vec<MountDecl>,
            #[serde(default)]
            readonly: Option<bool>,
            #[serde(default)]
            forward: Vec<ForwardDecl>,
            #[serde(default)]
            env: Vec<EnvVarDecl>,
            #[serde(default)]
            path: Option<String>,
            #[serde(default)]
            path_add: Vec<String>,
        }
        let raw = Raw::deserialize(d)?;
        // TOML is UTF-8 only, but `EnvVarDecls.path` / `path_add` are
        // `OsString` so non-UTF-8 entries from the CLI side survive.
        // This is the one place where the TOML→`OsString` boundary
        // lives — `From<String> for OsString` is infallible (UTF-8
        // bytes are always valid `OsString` bytes on Unix).
        Ok(ProfileDecl {
            uses: raw.uses,
            mount_decls: MountDecls {
                mount: raw.mount,
                readonly: raw.readonly,
            },
            forward_decls: ForwardDecls {
                forward: raw.forward,
            },
            env_decls: EnvVarDecls {
                env: raw.env,
                path: raw.path.map(OsString::from),
                path_add: raw
                    .path_add
                    .into_iter()
                    .map(OsString::from)
                    .collect(),
            },
        })
    }
}

impl Decl for ProfileDecl {
    type Resolved = Profile;

    /// Validate every sub-domain's contribution. Surfaces obvious
    /// problems (empty/NUL env names, port-zero forwards, missing
    /// mount host paths, etc.) before we go further into sandbox
    /// setup, so the user gets a friendly diagnostic instead of a
    /// terser failure deep inside bwrap.
    fn validate(&self) -> Result<()> {
        self.mount_decls.validate()?;
        self.forward_decls.validate()?;
        self.env_decls.validate()
    }

    /// Resolve into a [`Profile`] by resolving each sub-domain in
    /// turn. Each sub-domain's `Decl::resolve` carries its own
    /// extras (`Mounts::readonly`, `EnvVars::path` / `path_add`)
    /// across the boundary; the [`Profile`] aggregate holds none of
    /// its own.
    fn resolve(&self) -> Result<Self::Resolved> {
        Ok(Profile {
            mounts: self.mount_decls.resolve()?,
            forwards: self.forward_decls.resolve()?,
            env: self.env_decls.resolve()?,
        })
    }
}

/// The resolved counterpart of [`ProfileDecl`].
///
/// Aggregates the three sub-domain inventories that a profile (or
/// CLI invocation) contributes: mounts, port forwards, and env vars.
/// Each field carries its own extras ([`Mounts`]'s `readonly`,
/// [`EnvVars`]'s `path` / `path_add`); [`Profile`] itself has none.
/// All [`Finalize`] methods are field-wise delegation to the three
/// sub-domains, which already know how to merge themselves and bake
/// their own baselines.
///
/// `cmd_run` and `cmd_show` get a fully-baked [`Profile`] back from
/// [`crate::config::config_file::ConfigFile::finalize_config_with_cli`]
/// and destructure it for argv construction.
#[derive(Debug, Default, Clone)]
pub struct Profile {
    /// Resolved mount inventory plus the `readonly` extra (cleared
    /// during `Finalize::finalize`).
    pub mounts: Mounts,

    /// Resolved port-forward inventory.
    pub forwards: Forwards,

    /// Resolved env inventory plus the `path` / `path_add` extras
    /// (cleared during `Finalize::finalize`).
    pub env: EnvVars,
}

impl Finalize for Profile {
    /// Merge each sub-domain field-wise. The sub-domain's own
    /// merge rules apply: mounts concat left-then-right (order is
    /// load-bearing for bwrap argv), forwards concat left-then-right,
    /// env vars upsert into a `BTreeMap` (right wins on key
    /// collision), and each sub-domain's extras (`readonly`,
    /// `path`, `path_add`) merge per their own
    /// `merge_right_biased` rule (right-biased `Option::or` for
    /// scalars, concat for `path_add`).
    fn merge_right_biased(&self, other: &Self) -> Self {
        Self {
            mounts: self.mounts.merge_right_biased(&other.mounts),
            forwards: self.forwards.merge_right_biased(&other.forwards),
            env: self.env.merge_right_biased(&other.env),
        }
    }

    /// Build each sub-domain's baseline. Each sub-domain reads its
    /// own host-env state ([`Mounts`] reads `$HOME` / `cwd` via
    /// `dirs::home_dir` / `dirs::current_dir`; [`EnvVars`] reads
    /// `$HOME`, the curated passthrough list, and `LC_*`) plus its
    /// own merged extras from `self`.
    fn base_config(&self) -> Self {
        Self {
            mounts: self.mounts.base_config(),
            forwards: self.forwards.base_config(),
            env: self.env.base_config(),
        }
    }

    /// Clear each sub-domain's extras. The trait's default
    /// `finalize()` calls this between `base_config` (which read
    /// the extras) and the right-biased merge (which would otherwise
    /// re-introduce them on top of the baseline).
    fn clear_extra_fields(&mut self) {
        self.mounts.clear_extra_fields();
        self.forwards.clear_extra_fields();
        self.env.clear_extra_fields();
    }
}

impl NormalizeConfigPaths for ProfileDecl {
    /// Delegate to each path-bearing child. `forward_decls` (port
    /// numbers) and `uses` (profile names) have no paths.
    fn normalize_config_paths(&mut self, home: &Path) -> Result<()> {
        self.mount_decls.normalize_config_paths(home)?;
        self.env_decls.normalize_config_paths(home)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::config_file::{DEFAULT_CONFIG, parse_config};

    #[test]
    fn embedded_default_config_normalizes_paths_against_a_fake_home() {
        // Every path in the shipped default must be either `~/...`
        // or an absolute path — `~user/`, relative paths, etc.
        // would error during normalization on a real run. Catching
        // it here prevents a "first run errors on a brand-new
        // install" regression. Also serves as integration coverage
        // that `ProfileDecl::normalize_config_paths` correctly
        // delegates to its `MountDecls` and `EnvVarDecls` children.
        let mut cfg =
            parse_config(DEFAULT_CONFIG, Path::new("config.toml.default"))
                .expect("parses");
        for profile in cfg.profile_decls.values_mut() {
            profile
                .normalize_config_paths(Path::new("/home/test"))
                .expect("default-config paths normalize cleanly");
        }
    }

    // ===== Profile (Decl + Finalize) =====
    //
    // These tests verify that the `Profile` aggregate correctly
    // *delegates* to its three sub-domains. Per-domain merge /
    // base_config / clear_extra_fields semantics are covered in
    // `mounts.rs`, `forwards.rs`, and `env_vars.rs`; we don't
    // re-test them here.

    use std::ffi::OsStr;

    use toml::Spanned;

    use crate::config::{
        env_var::EnvVarDecl,
        forward::ForwardDecl,
        mount::{MountAccess, MountKind},
    };

    #[test]
    fn profile_decl_resolve_yields_profile_with_each_subdomain() {
        // One decl per sub-domain — verify each landed in the right
        // slot of the resolved `Profile`. Mount validation would
        // require a real host path; resolve doesn't validate, so we
        // can use a synthetic path here.
        let decl = ProfileDecl {
            uses: Vec::new(),
            mount_decls: MountDecls {
                mount: vec![MountDecl {
                    host: Spanned::new(0..0, PathBuf::from("/etc/gitconfig")),
                    sandbox: None,
                    access: None,
                }],
                readonly: Some(true),
            },
            forward_decls: ForwardDecls {
                forward: vec![ForwardDecl {
                    host_port: Spanned::new(0..0, 8080),
                    sandbox_port: None,
                }],
            },
            env_decls: EnvVarDecls {
                env: vec![EnvVarDecl {
                    name: Spanned::new(0..0, "FOO".to_owned()),
                    value: Some("bar".to_owned()),
                }],
                path: Some(OsString::from("/only/this")),
                path_add: vec![OsString::from("/extra")],
            },
        };
        let resolved = decl.resolve().expect("resolves");

        // mounts: one entry, plus the readonly extra carried through.
        assert_eq!(resolved.mounts.iter().count(), 1);
        assert_eq!(
            resolved.mounts.iter().next().unwrap().sandbox,
            PathBuf::from("/etc/gitconfig"),
        );

        // forwards: one entry.
        assert_eq!(resolved.forwards.iter().count(), 1);

        // env: one entry, plus the path / path_add extras carried
        // through (visible via finalize emitting them into PATH).
        assert_eq!(resolved.env.iter().count(), 1);
        assert_eq!(resolved.env.iter().next().unwrap().name, "FOO");
    }

    #[test]
    fn profile_finalize_merge_right_biased_delegates_to_each_subdomain() {
        // Build two `Profile`s with overlapping contributions in each
        // sub-domain and confirm that the aggregate merge inherits
        // each sub-domain's own rules.
        let mut left_env = EnvVars::default();
        left_env.set("SHARED", "left-wins-when-alone");
        left_env.set("ONLY_LEFT", "L");
        let left = Profile {
            mounts: MountDecls {
                mount: vec![MountDecl {
                    host: Spanned::new(0..0, PathBuf::from("/left")),
                    sandbox: None,
                    access: None,
                }],
                readonly: Some(true),
            }
            .resolve()
            .expect("resolves"),
            forwards: ForwardDecls {
                forward: vec![ForwardDecl {
                    host_port: Spanned::new(0..0, 8080),
                    sandbox_port: None,
                }],
            }
            .resolve()
            .expect("resolves"),
            env: left_env,
        };

        let mut right_env = EnvVars::default();
        right_env.set("SHARED", "right-wins");
        right_env.set("ONLY_RIGHT", "R");
        let right = Profile {
            mounts: MountDecls {
                mount: vec![MountDecl {
                    host: Spanned::new(0..0, PathBuf::from("/right")),
                    sandbox: None,
                    access: None,
                }],
                readonly: Some(false),
            }
            .resolve()
            .expect("resolves"),
            forwards: ForwardDecls {
                forward: vec![ForwardDecl {
                    host_port: Spanned::new(0..0, 9090),
                    sandbox_port: None,
                }],
            }
            .resolve()
            .expect("resolves"),
            env: right_env,
        };

        let merged = left.merge_right_biased(&right);

        // Mounts: left then right (Vec::extend). User-mount ordering
        // is load-bearing.
        let sandboxes: Vec<&Path> =
            merged.mounts.iter().map(|m| m.sandbox.as_path()).collect();
        assert_eq!(sandboxes, vec![Path::new("/left"), Path::new("/right")]);

        // Forwards: left then right.
        assert_eq!(merged.forwards.format_for_pasta(), "8080,9090");

        // Env: BTreeMap upsert, right wins on collision.
        let shared = merged
            .env
            .iter()
            .find(|e| e.name == "SHARED")
            .expect("SHARED present");
        assert_eq!(shared.value, OsStr::new("right-wins"));
        assert!(merged.env.iter().any(|e| e.name == "ONLY_LEFT"));
        assert!(merged.env.iter().any(|e| e.name == "ONLY_RIGHT"));
    }

    #[test]
    fn profile_finalize_base_config_includes_subdomain_baselines() {
        // A default Profile's base_config should yield each
        // sub-domain's own baseline: Mounts with the system mounts,
        // empty Forwards, and EnvVars with the canonical PATH.
        let base = Profile::default().base_config();

        // Mounts: at minimum the system pieces (/usr ro-bind, the
        // four /bin /sbin /lib /lib64 symlinks, /dev, /proc, /tmp).
        // Stronger ordering claims live in `mounts.rs`.
        assert!(
            base.mounts.iter().any(|m| m.sandbox == Path::new("/usr")),
            "system /usr mount missing from base",
        );
        assert!(
            base.mounts
                .iter()
                .any(|m| matches!(m.kind, MountKind::Proc)),
            "/proc missing from base",
        );

        // Forwards: empty. (No automatic forwards today.)
        assert!(base.forwards.is_empty());

        // EnvVars: PATH baked in (canonical, since no path override
        // was set on the input Profile).
        let path_entry = base
            .env
            .iter()
            .find(|e| e.name == "PATH")
            .expect("PATH present in env baseline");
        assert!(
            path_entry.value.to_string_lossy().contains("/usr/bin"),
            "PATH baseline should include /usr/bin, got {:?}",
            path_entry.value,
        );
    }

    #[test]
    fn profile_finalize_clear_extra_fields_clears_each_subdomain() {
        // Build a Profile with extras populated in each sub-domain
        // that has them, call clear_extra_fields, and confirm each
        // is zeroed. (Forwards has no extras.)
        let mounts = MountDecls {
            mount: Vec::new(),
            readonly: Some(true),
        }
        .resolve()
        .expect("resolves");
        let env = EnvVarDecls {
            env: Vec::new(),
            path: Some(OsString::from("/only/this")),
            path_add: vec![OsString::from("/extra")],
        }
        .resolve()
        .expect("resolves");
        let mut profile = Profile {
            mounts,
            forwards: Forwards::default(),
            env,
        };

        profile.clear_extra_fields();

        // Round-trip through finalize on each sub-domain to confirm
        // the extras are gone — using public observables since the
        // extras themselves are private. After finalize, `mounts`
        // should ignore the cleared `readonly` (cwd bind defaults to
        // Rw), and `env`'s PATH should be canonical (no `/extra:`
        // prefix from the cleared `path_add`).
        let mounts_done = profile.mounts.clone().finalize();
        let cwd =
            std::env::current_dir().expect("test runner has a working cwd");
        if let Some(cwd_entry) = mounts_done.iter().find(|m| m.sandbox == cwd) {
            assert!(
                matches!(
                    cwd_entry.kind,
                    MountKind::Mount {
                        access: MountAccess::Rw,
                        ..
                    }
                ),
                "cleared readonly must yield Rw cwd bind, got {:?}",
                cwd_entry.kind,
            );
        }

        let env_done = profile.env.clone().finalize();
        let path_value = &env_done
            .iter()
            .find(|e| e.name == "PATH")
            .expect("PATH present")
            .value;
        assert!(
            !path_value.to_string_lossy().contains("/extra"),
            "cleared path_add must not appear in PATH, got {:?}",
            path_value,
        );
        assert!(
            !path_value.to_string_lossy().contains("/only/this"),
            "cleared path must not appear in PATH, got {:?}",
            path_value,
        );
    }

    #[test]
    fn profile_decl_resolve_then_finalize_layers_baseline_under_user() {
        // End-to-end: a `ProfileDecl` with one user mount + one user
        // env var goes through resolve().finalize(); the sub-domain
        // baselines appear under the user contributions.
        let decl = ProfileDecl {
            uses: Vec::new(),
            mount_decls: MountDecls {
                mount: vec![MountDecl {
                    host: Spanned::new(0..0, PathBuf::from("/etc/gitconfig")),
                    sandbox: None,
                    access: None,
                }],
                readonly: None,
            },
            forward_decls: ForwardDecls::default(),
            env_decls: EnvVarDecls {
                env: vec![EnvVarDecl {
                    name: Spanned::new(0..0, "MY_VAR".to_owned()),
                    value: Some("hello".to_owned()),
                }],
                path: None,
                path_add: Vec::new(),
            },
        };
        let final_ = decl.resolve().expect("resolves").finalize();

        // System mount baseline present, user mount appended after.
        let usr_idx = final_
            .mounts
            .iter()
            .position(|m| m.sandbox == Path::new("/usr"))
            .expect("/usr from baseline");
        let user_idx = final_
            .mounts
            .iter()
            .position(|m| m.sandbox == Path::new("/etc/gitconfig"))
            .expect("user mount survives finalize");
        assert!(
            usr_idx < user_idx,
            "user mount must land after the baseline (usr={usr_idx}, user={user_idx})",
        );

        // Env baseline present (PATH), user var on top.
        assert!(
            final_.env.iter().any(|e| e.name == "PATH"),
            "PATH baseline missing post-finalize",
        );
        let my_var = final_
            .env
            .iter()
            .find(|e| e.name == "MY_VAR")
            .expect("user env var survives finalize");
        assert_eq!(my_var.value, OsStr::new("hello"));
    }
}

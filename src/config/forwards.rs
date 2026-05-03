//! The list of TCP port forwards from host loopback into the sandbox.
//!
//! Pipeline: the user declares forwards via [`ForwardDecls`] (`-f`
//! from the CLI; the `forwards = [...]` key in a `[profile.NAME]`
//! block from TOML). [`Decl::resolve`] turns one `ForwardDecls` into
//! a [`Forwards`] (one [`Forward`] per declared spec). Multiple
//! `Forwards` from layered profiles + CLI merge with
//! [`Finalize::merge_right_biased`] (concatenation; pasta passes
//! every entry to its `-T` flag in order). [`Finalize::base_config`]
//! is empty — there are no automatic forwards (a fresh sandbox can't
//! reach the host until the user asks for a port).
//!
//! References:
//!
//!   pasta(1) `--tcp-ns` (`-T`) flag, which is what
//!   [`Forwards::format_for_pasta`] produces strings for:
//!     <https://passt.top/builds/latest/web/passt.1.html>

use serde::Deserialize;

use super::forward::{Forward, ForwardDecl};
use crate::{
    config::{Decl, Finalize},
    prelude::*,
};

/// Shared forward options.
///
/// Flattened with `#[command(flatten)]` into any subcommand that
/// builds a [`Forwards`] (`run`, `show`), and routed into the
/// matching slot of [`crate::config::profile::ProfileDecl`] so the
/// same struct describes both CLI flags and `[profile.NAME]` blocks.
#[derive(Debug, Clone, Default, clap::Args, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardDecls {
    /// Forward a TCP port from host loopback into the sandbox.
    /// Repeatable. Format: `HOST_PORT[:SANDBOX_PORT]`. If
    /// `:SANDBOX_PORT` is omitted, the two ports match.
    #[arg(
        short = 'f',
        long = "forward",
        value_name = "HOST_PORT[:SANDBOX_PORT]"
    )]
    pub forwards: Vec<ForwardDecl>,
}

impl Decl for ForwardDecls {
    type Resolved = Forwards;

    /// Validate every [`ForwardDecl`] (port-zero rejection).
    fn validate(&self) -> Result<()> {
        for spec in &self.forwards {
            spec.validate()?;
        }
        Ok(())
    }

    fn resolve(&self) -> Result<Self::Resolved> {
        let forwards = self
            .forwards
            .iter()
            .map(|d| d.resolve())
            .collect::<Result<Vec<_>>>()?;
        Ok(Forwards { forwards })
    }
}

/// The ordered list of forwards pasta should configure for this
/// sandbox.
///
/// A newtype around `Vec<Forward>` so the assembly site can call
/// `forwards.forward(...)` without re-constructing the field-level
/// boilerplate, and so `show --json` can `serde_json` the whole
/// thing transparently as an array of [`Forward`] objects.
///
/// No extra fields: `Finalize::base_config` is empty (no automatic
/// forwards), `merge_right_biased` is `Vec::extend` (left first then
/// right — pasta passes every entry to `-T` in order), and
/// `clear_extra_fields` is the trait default no-op.
#[derive(Debug, Default, Clone, serde::Serialize)]
#[serde(transparent)]
pub struct Forwards {
    forwards: Vec<Forward>,
}

impl Forwards {
    /// Append a single TCP port forward.
    pub fn forward(&mut self, host_port: u16, sandbox_port: u16) -> &mut Self {
        self.forwards.push(Forward {
            host_port,
            sandbox_port,
        });
        self
    }

    /// Iterate over the forwards in declaration order.
    pub fn iter(&self) -> std::slice::Iter<'_, Forward> {
        self.forwards.iter()
    }

    /// Whether the list is empty. Used by the pasta argv builder
    /// to choose `-T none` vs an explicit list.
    pub fn is_empty(&self) -> bool {
        self.forwards.is_empty()
    }

    /// Format the list as the comma-separated SPEC string pasta's
    /// `-T` flag expects: each item is `HOST_PORT` if the two ports
    /// match, else `HOST_PORT:SANDBOX_PORT`.
    ///
    /// Returns an empty string for an empty list — callers should
    /// branch on [`Self::is_empty`] and emit `-T none` instead.
    pub fn format_for_pasta(&self) -> String {
        let mut out = String::new();
        for (i, f) in self.forwards.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            if f.host_port == f.sandbox_port {
                out.push_str(&f.host_port.to_string());
            } else {
                out.push_str(&format!("{}:{}", f.host_port, f.sandbox_port));
            }
        }
        out
    }
}

impl Finalize for Forwards {
    fn merge_right_biased(&self, other: &Self) -> Self {
        let mut forwards = self.forwards.clone();
        forwards.extend(other.forwards.iter().cloned());
        Self { forwards }
    }

    fn base_config(&self) -> Self {
        Self::default()
    }
    // `clear_extra_fields` uses the trait default no-op: there are
    // no extra fields, so the resolved decls survive `finalize()`
    // unchanged.
}

#[cfg(test)]
mod tests {
    use toml::Spanned;

    use super::*;

    #[test]
    fn format_for_pasta_uses_short_form_when_ports_match() {
        let mut list = Forwards::default();
        list.forward(8080, 8080);
        list.forward(5432, 9999);
        assert_eq!(list.format_for_pasta(), "8080,5432:9999");
    }

    #[test]
    fn forwards_empty_formats_to_empty_string() {
        let list = Forwards::default();
        assert!(list.is_empty());
        assert_eq!(list.format_for_pasta(), "");
    }

    #[test]
    fn forwards_merge_right_biased_concatenates() {
        // Order matters: pasta's `-T` flag emits every entry in the
        // order it appears, and merge is "left first, then right" so
        // baseline forwards (when we add them) precede user ones.
        let mut left = Forwards::default();
        left.forward(8080, 8080);
        let mut right = Forwards::default();
        right.forward(5432, 9999);
        let merged = left.merge_right_biased(&right);
        assert_eq!(merged.format_for_pasta(), "8080,5432:9999");
    }

    #[test]
    fn base_config_returns_empty() {
        let mut populated = Forwards::default();
        populated.forward(8080, 8080);
        // base_config ignores `self`'s entries — they're "normal
        // fields" that flow through finalize via the right-biased
        // merge, not extras consumed here.
        assert!(populated.base_config().is_empty());
    }

    #[test]
    fn forward_decls_resolve_then_finalize_emits_user_forwards() {
        // resolve() builds the user's Forwards; finalize() merges
        // the (empty) baseline underneath, so the user's entries
        // survive in declaration order.
        let decls = ForwardDecls {
            forwards: vec![
                ForwardDecl {
                    host_port: Spanned::new(0..0, 8080),
                    sandbox_port: None,
                },
                ForwardDecl {
                    host_port: Spanned::new(0..0, 5432),
                    sandbox_port: Some(Spanned::new(0..0, 9999)),
                },
            ],
        };
        let forwards = decls.resolve().expect("resolves").finalize();
        assert_eq!(forwards.format_for_pasta(), "8080,5432:9999");
    }
}

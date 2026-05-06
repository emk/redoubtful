use std::{env, ffi::OsString, str::FromStr};

use serde::{Serialize, Serializer};
use toml::Spanned;

use crate::{config::resolve_context, prelude::*};

/// A single env override: a name plus an optional value.
///
/// Same type for CLI and TOML inputs. `value: None` means
/// passthrough (`-e FOO` or TOML's `{ name = "FOO" }`); `value:
/// Some(s)` means literal (`-e FOO=s` or TOML's `{ name = "FOO",
/// value = "s" }`, where `s` may be the empty string for "set FOO
/// to the empty string"). The variable name carries a span so a
/// TOML-sourced empty/NUL name renders with miette underline at the
/// offending line; CLI-sourced specs use a `0..0` sentinel.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvVarDecl {
    /// The variable name.
    pub name: Spanned<String>,
    /// `Some(v)` for a literal assignment (the `v` may be empty);
    /// `None` for a passthrough.
    #[serde(default)]
    pub value: Option<String>,
}

impl super::Decl for EnvVarDecl {
    type Resolved = Option<EnvVar>;

    /// Reject empty name and NUL-in-name. Bwrap would refuse these
    /// later (NUL in particular is an `execve` violation); we
    /// surface them up-front with a friendlier message and (for
    /// TOML inputs) a span pointing at the offending line.
    fn validate(&self) -> Result<()> {
        let name = self.name.get_ref();
        if name.is_empty() {
            return Err(Error::invalid_env_name(
                name.clone(),
                "name is empty".to_owned(),
            ));
        }
        if name.contains('\0') {
            return Err(Error::invalid_env_name(
                name.clone(),
                "name contains NUL".to_owned(),
            ));
        }
        Ok(())
    }

    fn resolve(
        &self,
        _ctx: &resolve_context::ResolveContext,
    ) -> Result<Self::Resolved> {
        // Determine what value to use for the env var. Literals come
        // in as UTF-8 `String` (CLI/TOML), passthroughs come in as
        // `OsString` from `var_os` so non-UTF-8 host bytes pass
        // through to bwrap byte-for-byte.
        let value: OsString = match self.value.as_deref() {
            Some(literal) => literal.into(),
            None => match env::var_os(self.name.get_ref()) {
                Some(v) => v,
                None => return Ok(None),
            },
        };

        Ok(Some(EnvVar {
            name: self.name.get_ref().to_owned(),
            value,
        }))
    }
}

impl FromStr for EnvVarDecl {
    type Err = Error;

    /// Parse `VAR` (passthrough) or `VAR=VALUE` (literal).
    ///
    /// Distinguishes by *presence of `=`*, not by whether the
    /// post-`=` string is empty: `-e FOO=` is a literal empty
    /// string, while `-e FOO` is a passthrough. This matches the
    /// docker `-e` convention coding-agent users are likely to
    /// already have a mental model for. Name validation (empty/NUL)
    /// happens at [`EnvVarDecl::validate`] time so CLI and TOML
    /// inputs share one check.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (name, value) = match s.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (s, None),
        };
        Ok(EnvVarDecl {
            name: Spanned::new(0..0, name.to_owned()),
            value,
        })
    }
}

/// One concrete environment-variable assignment that bwrap will see.
///
/// `value` is an `OsString` so non-UTF-8 host bytes (from a
/// `-e FOO` passthrough or a `LC_*` value the host happens to set
/// non-Unicode) pass through to bwrap byte-for-byte. CLI/TOML
/// literal values arrive as UTF-8 `String` and convert losslessly
/// into `OsString`. The single lossy hop is at the JSON-output
/// boundary in [`serialize_value_lossy`] — `show --json` emits a
/// best-effort UTF-8 string with U+FFFD substitutions, so the
/// JSON consumer always gets a string and not, say, a base64 byte
/// blob it would have to decode.
#[derive(Debug, Clone, Serialize)]
pub struct EnvVar {
    /// The variable name (e.g. `PATH`). No `=`-style encoding here;
    /// bwrap's `--setenv` takes name and value as separate argv
    /// tokens. Names stay `String` because POSIX env-var names are
    /// effectively required to be ASCII alphanumerics + underscore.
    pub name: String,

    /// The value to assign. May be empty (`-e FOO=` is a real use
    /// case: "set FOO to the empty string"), and may carry non-UTF-8
    /// bytes from the host env.
    #[serde(serialize_with = "serialize_value_lossy")]
    pub value: OsString,
}

/// JSON-output adapter for [`EnvVar::value`].
///
/// `OsString` doesn't have a single canonical string form — the
/// only honest choice for a JSON-string field is `to_string_lossy`,
/// which substitutes U+FFFD for any non-UTF-8 byte. This keeps
/// `show --json` consumable by anything that expects strings (and
/// the lossy substitution is documented + observable rather than
/// silently dropping the entry).
fn serialize_value_lossy<S: Serializer>(
    value: &OsString,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&value.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;
    use crate::config::Decl;

    fn parse(s: &str) -> Result<EnvVarDecl> {
        s.parse()
    }

    #[test]
    fn env_var_decl_literal_parses() {
        let decl = parse("FOO=bar").expect("parses");
        assert_eq!(decl.name.get_ref(), "FOO");
        assert_eq!(decl.value.as_deref(), Some("bar"));
    }

    #[test]
    fn env_var_decl_literal_empty_value() {
        let decl = parse("FOO=").expect("parses");
        // `FOO=` is literal empty string, NOT passthrough.
        assert_eq!(decl.value.as_deref(), Some(""));
    }

    #[test]
    fn env_var_decl_passthrough_when_no_equals() {
        let decl = parse("FOO").expect("parses");
        assert!(decl.value.is_none(), "`FOO` should be passthrough");
    }

    #[test]
    fn env_var_decl_value_with_embedded_equals() {
        // `KEY=a=b=c` → literal value is `a=b=c` (only the first `=`
        // is the name/value separator). Common when users assign
        // URLs or `--flag=value`-shaped strings.
        let decl = parse("KEY=a=b=c").expect("parses");
        assert_eq!(decl.value.as_deref(), Some("a=b=c"));
    }

    #[test]
    fn env_var_decl_validate_rejects_empty_name() {
        // FromStr accepts empty/NUL names syntactically; validate()
        // is what rejects them, mirroring the TOML path.
        let empty = parse("").expect("parses syntactically");
        assert!(empty.validate().is_err());
        let empty_eq = parse("=value").expect("parses syntactically");
        assert!(empty_eq.validate().is_err());
        // Sanity: well-formed names validate cleanly.
        assert!(parse("FOO").unwrap().validate().is_ok());
        assert!(parse("FOO=bar").unwrap().validate().is_ok());
    }

    #[test]
    fn env_var_decl_resolve_literal_yields_os_string_value() {
        // Literal CLI input is always UTF-8 String; resolve()
        // converts it losslessly into the EnvVar's OsString value.
        let decl = parse("FOO=bar").unwrap();
        let ctx = resolve_context::ResolveContext::empty();
        let resolved = decl.resolve(&ctx).unwrap().expect("literal resolves");
        assert_eq!(resolved.name, "FOO");
        assert_eq!(resolved.value, OsStr::new("bar"));
    }

    #[test]
    fn env_var_decl_resolve_passthrough_unset_yields_none() {
        // A passthrough whose name is (almost certainly) not set on
        // the host should resolve to None — the "drop the entry"
        // signal up to EnvVarDecls.
        let decl = parse("REDOUBTFUL_DEFINITELY_NOT_SET_4f7a8b").unwrap();
        let ctx = resolve_context::ResolveContext::empty();
        let resolved = decl.resolve(&ctx).unwrap();
        assert!(resolved.is_none(), "unset passthrough must resolve to None");
    }

    #[test]
    fn env_var_serialize_value_renders_lossy_for_non_utf8() {
        // Non-UTF-8 bytes survive in the OsString value but get
        // substituted with U+FFFD at the JSON-string boundary. The
        // lone lossy hop is the serializer; everything else is
        // byte-clean.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let var = EnvVar {
                name: "X".to_owned(),
                // 0xFF is not valid UTF-8.
                value: OsString::from_vec(vec![b'a', 0xFF, b'b']),
            };
            let json = serde_json::to_string(&var).expect("serializes");
            // U+FFFD encoded literally in JSON-string form.
            assert!(
                json.contains('\u{FFFD}'),
                "expected U+FFFD substitution in {json}",
            );
        }
    }
}

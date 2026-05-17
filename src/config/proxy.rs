//! A single proxy destination declaration.
//!
//! Pipeline: the user-facing [`ProxyDecl`] (CLI/TOML) resolves via
//! [`Decl::resolve`] into a runtime [`Proxy`]. During resolution,
//! Handlebars templates in `headers`, `params`, and `auth` fields
//! are rendered against secrets loaded from `~/.config/redoubtful/secrets.toml`.
//! The plural pieces (`ProxyDecls`, `Proxies`, `Finalize`) live in
//! [`crate::config::proxies`].
//!
//! The compact CLI syntax is `HOST[:PORT][=ACTION]` parsed by
//! [`FromStr`]. TOML supports the full form with headers, params,
//! and auth injection.

use std::{collections::BTreeMap, str::FromStr};

use serde::{Deserialize, Serialize};

use super::{Secret, Template};
use crate::{
    config::{Decl, resolve_context::ResolveContext},
    prelude::*,
};

/// Whether traffic to a destination is allowed or denied.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum ProxyAction {
    #[default]
    Allow,
    Deny,
}

impl FromStr for ProxyAction {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(Error::proxy_invalid_action(other.to_owned())),
        }
    }
}

/// Authentication credentials declared as Handlebars templates.
///
/// Stored in [`ProxyDecl`]. During [`Decl::resolve`], templates are
/// rendered against secrets and converted to [`ProxyAuth`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProxyAuthDecl {
    /// Basic authentication with username and password.
    Basic {
        username: Template,
        password: Template,
    },
    /// Bearer token authentication.
    Bearer { token: Template },
}

/// Resolved authentication credentials.
///
/// `Debug` on this enum delegates to the `Secret` variants which
/// redact their values. Consumed by the proxy server at runtime
/// (Stage 3) for credential injection.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ProxyAuth {
    /// Basic authentication with username and password.
    Basic { username: Secret, password: Secret },
    /// Bearer token authentication.
    Bearer { token: Secret },
}

/// A single proxy destination declared by the user.
///
/// Supports both CLI (`--proxy=example.net:80=deny`) and TOML
/// (`[[proxies]] host = "example.net"`) input. The `host` field
/// is mandatory; `port` defaults to 443, `action` defaults to
/// `Allow`, and `headers`/`params`/`auth` default to empty/none.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyDecl {
    /// The hostname or IP address to proxy.
    pub host: String,
    /// TCP port. Defaults to 443 (HTTPS).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Whether to allow or deny traffic to this destination.
    #[serde(default)]
    pub action: ProxyAction,
    /// Custom headers to inject, as Handlebars templates.
    #[serde(default)]
    pub headers: BTreeMap<String, Template>,
    /// URL query parameters to inject, as Handlebars templates.
    #[serde(default)]
    pub params: BTreeMap<String, Template>,
    /// Authentication credentials, as Handlebars templates.
    #[serde(default)]
    pub auth: Option<ProxyAuthDecl>,
}

/// Default port for proxy declarations (HTTPS).
fn default_port() -> u16 {
    443
}

impl FromStr for ProxyDecl {
    type Err = Error;

    /// Parse a compact `HOST[:PORT][=ACTION]` proxy specification.
    ///
    /// Supported forms:
    /// - `example.net` → host=example.net, port=443, action=Allow
    /// - `example.net:80` → host=example.net, port=80, action=Allow
    /// - `example.net=deny` → host=example.net, port=443, action=Deny
    /// - `example.net:80=deny` → all three fields explicit
    ///
    /// Errors on empty host, invalid port, invalid action, or
    /// multiple `=` separators.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Split on `=` (max 2 parts).
        let parts: Vec<&str> = s.splitn(3, '=').collect();
        let (host_port, action_str) = match parts.as_slice() {
            [single] => (*single, None),
            [host_port, action] => (*host_port, Some(*action)),
            _ => {
                return Err(Error::proxy_invalid_syntax(
                    s.to_owned(),
                    "multiple `=` separators are not supported".to_owned(),
                ));
            }
        };

        // Split host_port on `:` (max 2 parts).
        let hp_parts: Vec<&str> = host_port.splitn(3, ':').collect();
        let (host, port_str) = match hp_parts.as_slice() {
            [single] => (*single, None),
            [host, port] => (*host, Some(*port)),
            _ => {
                return Err(Error::proxy_invalid_syntax(
                    s.to_owned(),
                    "multiple `:` separators are not supported".to_owned(),
                ));
            }
        };

        // Validate host.
        if host.is_empty() {
            return Err(Error::ProxyEmptyHost);
        }

        // Parse port if provided.
        let port = match port_str {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| Error::proxy_invalid_port(p.to_owned()))?,
            None => 443,
        };

        // Parse action if provided.
        let action = match action_str {
            Some(a) => a.parse::<ProxyAction>()?,
            None => ProxyAction::Allow,
        };

        Ok(ProxyDecl {
            host: host.to_owned(),
            port,
            action,
            headers: BTreeMap::new(),
            params: BTreeMap::new(),
            auth: None,
        })
    }
}

impl Decl for ProxyDecl {
    type Resolved = Proxy;

    /// Validate the proxy declaration. Rejects empty hostnames.
    fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            return Err(Error::ProxyEmptyHost);
        }
        Ok(())
    }

    /// Resolve templates in headers, params, and auth against
    /// secrets via [`ResolveContext`].
    ///
    /// This is the first [`Decl`] type that actually uses the
    /// `ctx` parameter — all existing types pass `_ctx`.
    fn resolve(&self, ctx: &ResolveContext) -> Result<Self::Resolved> {
        let headers = self
            .headers
            .iter()
            .map(|(k, v)| Ok((k.clone(), Secret(ctx.render_template(&v.0)?))))
            .collect::<Result<BTreeMap<_, _>>>()?;

        let params = self
            .params
            .iter()
            .map(|(k, v)| Ok((k.clone(), Secret(ctx.render_template(&v.0)?))))
            .collect::<Result<BTreeMap<_, _>>>()?;

        let auth = self
            .auth
            .as_ref()
            .map(|a| resolve_auth(a, ctx))
            .transpose()?;

        Ok(Proxy {
            host: crate::hostname::normalize_hostname(&self.host),
            port: self.port,
            action: self.action,
            headers,
            params,
            auth,
        })
    }
}

/// Resolve a [`ProxyAuthDecl`] against secrets.
fn resolve_auth(
    auth: &ProxyAuthDecl,
    ctx: &ResolveContext,
) -> Result<ProxyAuth> {
    match auth {
        ProxyAuthDecl::Basic { username, password } => Ok(ProxyAuth::Basic {
            username: Secret(ctx.render_template(&username.0)?),
            password: Secret(ctx.render_template(&password.0)?),
        }),
        ProxyAuthDecl::Bearer { token } => Ok(ProxyAuth::Bearer {
            token: Secret(ctx.render_template(&token.0)?),
        }),
    }
}

/// A fully-resolved proxy destination.
///
/// All Handlebars templates have been rendered against secrets;
/// `headers`, `params`, and `auth` carry [`Secret`] values that
/// redact their contents in `Debug`, `Display`, and `Serialize`.
///
/// Consumed by the proxy server at runtime (Stage 3) for
/// destination routing and credential injection.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Proxy {
    /// The hostname or IP address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Whether to allow or deny traffic.
    pub action: ProxyAction,
    /// Resolved custom headers.
    pub headers: BTreeMap<String, Secret>,
    /// Resolved URL query parameters.
    pub params: BTreeMap<String, Secret>,
    /// Resolved authentication credentials.
    pub auth: Option<ProxyAuth>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> std::result::Result<ProxyDecl, Error> {
        s.parse()
    }

    // ===== FromStr =====

    #[test]
    fn proxy_decl_fromstr_host_only() {
        let decl = parse("example.net").expect("parses");
        assert_eq!(decl.host, "example.net");
        assert_eq!(decl.port, 443);
        assert_eq!(decl.action, ProxyAction::Allow);
        assert!(decl.headers.is_empty());
        assert!(decl.params.is_empty());
        assert!(decl.auth.is_none());
    }

    #[test]
    fn proxy_decl_fromstr_host_port() {
        let decl = parse("example.net:80").expect("parses");
        assert_eq!(decl.host, "example.net");
        assert_eq!(decl.port, 80);
        assert_eq!(decl.action, ProxyAction::Allow);
    }

    #[test]
    fn proxy_decl_fromstr_host_action() {
        let decl = parse("example.net=deny").expect("parses");
        assert_eq!(decl.host, "example.net");
        assert_eq!(decl.port, 443);
        assert_eq!(decl.action, ProxyAction::Deny);
    }

    #[test]
    fn proxy_decl_fromstr_full() {
        let decl = parse("example.net:80=deny").expect("parses");
        assert_eq!(decl.host, "example.net");
        assert_eq!(decl.port, 80);
        assert_eq!(decl.action, ProxyAction::Deny);
    }

    #[test]
    fn proxy_decl_fromstr_action_case_insensitive() {
        assert_eq!(
            parse("example.net=ALLOW").expect("parses").action,
            ProxyAction::Allow,
        );
        assert_eq!(
            parse("example.net=Deny").expect("parses").action,
            ProxyAction::Deny,
        );
        assert_eq!(
            parse("example.net=Allow").expect("parses").action,
            ProxyAction::Allow,
        );
    }

    #[test]
    fn proxy_decl_fromstr_rejects_empty_host() {
        let err = parse(":80").expect_err("empty host must error");
        assert!(matches!(err, Error::ProxyEmptyHost));
    }

    #[test]
    fn proxy_decl_fromstr_rejects_bad_port() {
        let err = parse("example.net:abc").expect_err("bad port must error");
        assert!(matches!(err, Error::ProxyInvalidPort { .. }));
    }

    #[test]
    fn proxy_decl_fromstr_rejects_bad_action() {
        let err = parse("example.net=wat").expect_err("bad action must error");
        assert!(matches!(err, Error::ProxyInvalidAction { .. }));
    }

    #[test]
    fn proxy_decl_fromstr_rejects_multiple_equals() {
        let err = parse("a=b=c").expect_err("multiple = must error");
        assert!(matches!(err, Error::ProxyInvalidSyntax { .. }));
    }

    #[test]
    fn proxy_decl_fromstr_rejects_multiple_colons() {
        let err = parse("a:b:c").expect_err("multiple : must error");
        assert!(matches!(err, Error::ProxyInvalidSyntax { .. }));
    }

    // ===== Decl::resolve =====

    #[test]
    fn proxy_decl_resolve_no_templates() {
        // Plain proxy with no templates — resolves without ctx usage.
        let decl = ProxyDecl {
            host: "example.net".to_owned(),
            port: 443,
            action: ProxyAction::Allow,
            headers: BTreeMap::new(),
            params: BTreeMap::new(),
            auth: None,
        };
        let ctx = ResolveContext::empty();
        let proxy = decl.resolve(&ctx).expect("resolves");
        assert_eq!(proxy.host, "example.net");
        assert_eq!(proxy.port, 443);
        assert_eq!(proxy.action, ProxyAction::Allow);
        assert!(proxy.headers.is_empty());
        assert!(proxy.params.is_empty());
        assert!(proxy.auth.is_none());
    }

    #[test]
    fn proxy_decl_resolve_renders_header_templates() {
        let mut headers = BTreeMap::new();
        headers.insert(
            "X-Api-Key".to_owned(),
            Template("{{secrets.example.api-key}}".to_owned()),
        );
        let decl = ProxyDecl {
            host: "example.net".to_owned(),
            port: 443,
            action: ProxyAction::Allow,
            headers,
            params: BTreeMap::new(),
            auth: None,
        };
        let ctx = ResolveContext::empty();
        // With empty secrets, template rendering should fail
        // (strict mode). This confirms the rendering path is hit.
        let err = decl.resolve(&ctx).expect_err("missing secret must error");
        assert!(matches!(err, Error::TemplateRender { .. }));
    }

    #[test]
    fn proxy_decl_resolve_renders_auth_basic() {
        let decl = ProxyDecl {
            host: "example.net".to_owned(),
            port: 443,
            action: ProxyAction::Allow,
            headers: BTreeMap::new(),
            params: BTreeMap::new(),
            auth: Some(ProxyAuthDecl::Basic {
                username: Template("{{secrets.example.username}}".to_owned()),
                password: Template("{{secrets.example.password}}".to_owned()),
            }),
        };
        let ctx = ResolveContext::empty();
        let err = decl.resolve(&ctx).expect_err("missing secret must error");
        assert!(matches!(err, Error::TemplateRender { .. }));
    }

    #[test]
    fn proxy_decl_resolve_renders_auth_bearer() {
        let decl = ProxyDecl {
            host: "example.net".to_owned(),
            port: 443,
            action: ProxyAction::Allow,
            headers: BTreeMap::new(),
            params: BTreeMap::new(),
            auth: Some(ProxyAuthDecl::Bearer {
                token: Template("{{secrets.example.token}}".to_owned()),
            }),
        };
        let ctx = ResolveContext::empty();
        let err = decl.resolve(&ctx).expect_err("missing secret must error");
        assert!(matches!(err, Error::TemplateRender { .. }));
    }

    #[test]
    fn proxy_decl_resolve_missing_secret_errors() {
        // Any template referencing a non-existent secret path
        // should fail with TemplateRender (strict mode).
        let mut params = BTreeMap::new();
        params.insert(
            "api_key".to_owned(),
            Template("{{secrets.nonexistent.key}}".to_owned()),
        );
        let decl = ProxyDecl {
            host: "example.net".to_owned(),
            port: 443,
            action: ProxyAction::Allow,
            headers: BTreeMap::new(),
            params,
            auth: None,
        };
        let ctx = ResolveContext::empty();
        let err = decl.resolve(&ctx).expect_err("missing secret must error");
        assert!(matches!(err, Error::TemplateRender { .. }));
    }

    #[test]
    fn proxy_decl_resolve_normalizes_host_case() {
        let decl = ProxyDecl {
            host: "Example.Net".to_owned(),
            port: 443,
            action: ProxyAction::Allow,
            headers: BTreeMap::new(),
            params: BTreeMap::new(),
            auth: None,
        };
        let ctx = ResolveContext::empty();
        let proxy = decl.resolve(&ctx).expect("resolves");
        assert_eq!(proxy.host, "example.net");
    }

    // ===== Secret redaction =====

    #[test]
    fn secret_debug_redacts() {
        let s = Secret("my-secret-value".to_owned());
        let debug = format!("{s:?}");
        assert!(
            !debug.contains("my-secret-value"),
            "Debug must not leak secret value: {debug}",
        );
        assert!(debug.contains("***"), "Debug should show '***': {debug}");
    }

    #[test]
    fn secret_display_redacts() {
        let s = Secret("my-secret-value".to_owned());
        let display = format!("{s}");
        assert!(
            !display.contains("my-secret-value"),
            "Display must not leak secret value: {display}",
        );
        assert_eq!(display, "***");
    }

    #[test]
    fn secret_serialize_redacts() {
        let s = Secret("my-secret-value".to_owned());
        let json = serde_json::to_string(&s).expect("serializes");
        assert!(
            !json.contains("my-secret-value"),
            "JSON must not leak secret value: {json}",
        );
        assert_eq!(json, "\"***\"");
    }
}

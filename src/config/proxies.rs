//! Proxy destination inventory.
//!
//! Pipeline: the user declares proxies via [`ProxyDecls`] (`--proxy`
//! from the CLI; `[[proxies]]` in a `[profile.NAME]` block from TOML,
//! plus the top-level `public_web` toggle). [`Decl::resolve`] turns
//! one `ProxyDecls` into a [`Proxies`] (one [`Proxy`] per declared
//! spec, with templates rendered against secrets).
//!
//! Multiple `Proxies` from layered profiles + CLI merge with
//! [`Finalize::merge_right_biased`] (right wins on host collision
//! via `BTreeMap` upsert). [`Finalize::base_config`] sets
//! `public_web = ProxyAction::Allow` and empty proxies.
//!
//! The [`Proxies::is_proxy_server_needed`] method is a global check
//! that controls whether we spawn a proxy server process at all.

use std::collections::BTreeMap;

use clap::Args;
use serde::Deserialize;

use super::{
    Decl, Finalize,
    proxy::{Proxy, ProxyAction, ProxyDecl},
    resolve_context,
};
use crate::prelude::*;

/// Shared proxy options.
///
/// Flattened with `#[command(flatten)]` into any subcommand that
/// builds a [`Proxies`] (`run`, `show`), and routed into the
/// matching slot of [`crate::config::profile::ProfileDecl`] so
/// the same struct describes both CLI flags and `[profile.NAME]`
/// blocks.
#[derive(Debug, Clone, Default, Args, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyDecls {
    /// Allow or deny public web access.
    #[arg(long = "public-web", num_args = 0..=1, default_missing_value = "allow")]
    #[serde(default)]
    pub public_web: Option<ProxyAction>,

    /// Proxy a specific host. Repeatable. Format:
    /// `HOST[:PORT][=ACTION]`.
    #[arg(short = 'p', long = "proxy", value_name = "HOST[:PORT][=ACTION]")]
    #[serde(default, rename = "proxies")]
    pub proxies: Vec<ProxyDecl>,
}

impl Decl for ProxyDecls {
    type Resolved = Proxies;

    /// Validate every [`ProxyDecl`].
    fn validate(&self) -> Result<()> {
        for spec in &self.proxies {
            spec.validate()?;
        }
        Ok(())
    }

    fn resolve(
        &self,
        ctx: &resolve_context::ResolveContext,
    ) -> Result<Self::Resolved> {
        let mut proxies = BTreeMap::new();
        for decl in &self.proxies {
            let proxy = decl.resolve(ctx)?;
            proxies.insert(proxy.host.clone(), proxy);
        }
        Ok(Proxies {
            public_web: self.public_web,
            proxies,
        })
    }
}

/// The resolved proxy inventory.
///
/// `proxies` is a `BTreeMap` keyed by hostname for deterministic
/// ordering and natural key-based dedup in [`merge_right_biased`].
/// `public_web` is always set after resolution (the `Allow` default
/// is baked in during [`Decl::resolve`]).
#[derive(Debug, Default, Clone)]
pub struct Proxies {
    /// Whether public web access is allowed. After [`Finalize::finalize`], this
    /// should always be `Some`, thanks to [`Self::base_config`]. But this needs
    /// to be an option here so that [`Finalize::merge_right_biased`] is a monoid
    /// with a proper zero value (i.e. `None`).
    public_web: Option<ProxyAction>,
    /// Proxy entries keyed by hostname.
    proxies: BTreeMap<String, Proxy>,
}

impl Proxies {
    /// Iterate over the proxy entries.
    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = &Proxy> {
        self.proxies.values()
    }

    /// Whether the proxy list is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Returns the number of proxy entries.
    #[allow(dead_code)]
    pub fn public_web(&self) -> Result<ProxyAction> {
        self.public_web.ok_or_else(|| {
            todo!("should be set by base_config; needs new error type")
        })
    }

    /// Whether a proxy server process is needed at all.
    ///
    /// Returns `true` when any outbound traffic would pass through
    /// the proxy:
    /// - `public_web == Allow` → proxy needed for public web traffic
    /// - `public_web == Deny` + any `Allow` proxy → proxy needed
    ///   for those explicit destinations
    /// - `public_web == Deny` + all proxies `Deny` → no proxy needed
    #[allow(dead_code)]
    pub fn is_proxy_server_needed(&self) -> Result<bool> {
        if self.public_web()? == ProxyAction::Allow {
            return Ok(true);
        }
        Ok(self
            .proxies
            .values()
            .any(|p| p.action == ProxyAction::Allow))
    }
}

impl Finalize for Proxies {
    /// Merge two proxy inventories: `public_web` is direct
    /// replacement (right wins), `proxies` `BTreeMap` upserts
    /// by hostname (right wins on collision, different hosts
    /// concatenate).
    fn merge_right_biased(&self, other: &Self) -> Self {
        let mut proxies = self.proxies.clone();
        for (host, proxy) in &other.proxies {
            proxies.insert(host.clone(), proxy.clone());
        }
        Self {
            public_web: other.public_web,
            proxies,
        }
    }

    /// Base configuration: `public_web = Allow`, empty proxies.
    fn base_config(&self) -> Self {
        Self {
            public_web: Some(ProxyAction::Allow),
            proxies: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== ProxyDecls =====

    #[test]
    fn proxy_decls_default_is_empty() {
        let decls = ProxyDecls::default();
        assert!(decls.public_web.is_none());
        assert!(decls.proxies.is_empty());
    }

    #[test]
    fn proxy_decls_resolve_yields_proxies() {
        let decls = ProxyDecls {
            public_web: Some(ProxyAction::Deny),
            proxies: vec![ProxyDecl {
                host: "example.net".to_owned(),
                port: 443,
                action: ProxyAction::Allow,
                headers: BTreeMap::new(),
                params: BTreeMap::new(),
                auth: None,
            }],
        };
        let ctx = resolve_context::ResolveContext::empty();
        let proxies = decls.resolve(&ctx).expect("resolves");
        assert_eq!(proxies.public_web().unwrap(), ProxyAction::Deny);
        assert!(!proxies.is_empty());
        let proxy = proxies.iter().next().unwrap();
        assert_eq!(proxy.host, "example.net");
    }

    // ===== Finalize =====

    #[test]
    fn proxies_base_config_defaults_public_web_allow() {
        let proxies = Proxies::default();
        let base = proxies.base_config();
        assert_eq!(base.public_web().unwrap(), ProxyAction::Allow);
        assert!(base.is_empty());
    }

    #[test]
    fn proxies_merge_right_biased_deduplicates_by_host() {
        let mut left = Proxies::default();
        let left_proxy = Proxy {
            host: "example.net".to_owned(),
            port: 443,
            action: ProxyAction::Allow,
            headers: BTreeMap::new(),
            params: BTreeMap::new(),
            auth: None,
        };
        left.proxies.insert("example.net".to_owned(), left_proxy);

        let right_proxy = Proxy {
            host: "example.net".to_owned(),
            port: 80,
            action: ProxyAction::Deny,
            headers: BTreeMap::new(),
            params: BTreeMap::new(),
            auth: None,
        };
        let right = Proxies {
            public_web: Some(ProxyAction::Deny),
            proxies: {
                let mut m = BTreeMap::new();
                m.insert("example.net".to_owned(), right_proxy);
                m
            },
        };

        let merged = left.merge_right_biased(&right);
        assert_eq!(merged.public_web().unwrap(), ProxyAction::Deny);
        assert_eq!(merged.proxies.len(), 1);
        let proxy = merged.proxies.get("example.net").unwrap();
        assert_eq!(proxy.action, ProxyAction::Deny);
        assert_eq!(proxy.port, 80);
    }

    #[test]
    fn proxies_merge_right_biased_concatenates_different_hosts() {
        let mut left = Proxies::default();
        left.proxies.insert(
            "left.net".to_owned(),
            Proxy {
                host: "left.net".to_owned(),
                port: 443,
                action: ProxyAction::Allow,
                headers: BTreeMap::new(),
                params: BTreeMap::new(),
                auth: None,
            },
        );

        let mut right = Proxies::default();
        right.proxies.insert(
            "right.net".to_owned(),
            Proxy {
                host: "right.net".to_owned(),
                port: 443,
                action: ProxyAction::Allow,
                headers: BTreeMap::new(),
                params: BTreeMap::new(),
                auth: None,
            },
        );

        let merged = left.merge_right_biased(&right);
        assert_eq!(merged.proxies.len(), 2);
        assert!(merged.proxies.contains_key("left.net"));
        assert!(merged.proxies.contains_key("right.net"));
    }

    // ===== is_proxy_server_needed =====

    #[test]
    fn is_proxy_server_needed_public_web_allow_returns_true() {
        let proxies = Proxies {
            public_web: Some(ProxyAction::Allow),
            proxies: BTreeMap::new(),
        };
        assert!(proxies.is_proxy_server_needed().unwrap());
    }

    #[test]
    fn is_proxy_server_needed_public_web_deny_no_proxies_returns_false() {
        let proxies = Proxies {
            public_web: Some(ProxyAction::Deny),
            proxies: BTreeMap::new(),
        };
        assert!(!proxies.is_proxy_server_needed().unwrap());
    }

    #[test]
    fn is_proxy_server_needed_public_web_deny_with_allowed_proxy_returns_true()
    {
        let mut proxies = Proxies {
            public_web: Some(ProxyAction::Deny),
            proxies: BTreeMap::new(),
        };
        proxies.proxies.insert(
            "allowed.net".to_owned(),
            Proxy {
                host: "allowed.net".to_owned(),
                port: 443,
                action: ProxyAction::Allow,
                headers: BTreeMap::new(),
                params: BTreeMap::new(),
                auth: None,
            },
        );
        assert!(proxies.is_proxy_server_needed().unwrap());
    }

    #[test]
    fn is_proxy_server_needed_public_web_deny_all_deny_returns_false() {
        let mut proxies = Proxies {
            public_web: Some(ProxyAction::Deny),
            proxies: BTreeMap::new(),
        };
        proxies.proxies.insert(
            "denied.net".to_owned(),
            Proxy {
                host: "denied.net".to_owned(),
                port: 443,
                action: ProxyAction::Deny,
                headers: BTreeMap::new(),
                params: BTreeMap::new(),
                auth: None,
            },
        );
        assert!(!proxies.is_proxy_server_needed().unwrap());
    }
}

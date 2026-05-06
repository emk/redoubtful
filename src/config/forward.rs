//! A single TCP port forward from host loopback into the sandbox.
//!
//! The agent connects to `127.0.0.1:sandbox_port` inside the netns,
//! pasta pipes that through to `127.0.0.1:host_port` on the host.
//!
//! v0 scope is intentionally small: TCP only, host loopback only,
//! one port per [`Forward`]. Pasta natively supports ranges, IPv6
//! addresses, and per-address bindings — when we need any of those
//! we widen [`Forward`] / [`ForwardDecl`] without changing the
//! surface of [`crate::config::forwards::Forwards`].
//!
//! Pipeline: the user-facing [`ForwardDecl`] (CLI/TOML) resolves via
//! [`Decl::resolve`] into a runtime [`Forward`]. The plural pieces
//! (`ForwardDecls`, `Forwards`, `Finalize`) live in
//! [`crate::config::forwards`].
//!
//! References:
//!
//!   pasta(1) `--tcp-ns` (`-T`) flag:
//!     <https://passt.top/builds/latest/web/passt.1.html>
//!   Project architecture spec:
//!     `specs/ARCHITECTURE.md`

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use toml::Spanned;

use crate::{
    config::{Decl, resolve_context},
    prelude::*,
};

/// A single port-forward specification: the host port and an
/// optional sandbox port.
///
/// Same type for CLI and TOML inputs. Ports carry `Spanned` wrappers
/// so a TOML-sourced `host_port = 0` renders with miette underline
/// at the offending line; CLI-sourced specs use a `0..0` sentinel.
/// `sandbox_port` defaults to `host_port` when absent — see
/// [`Self::sandbox_port`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardDecl {
    /// TCP port on host loopback to forward from.
    pub host_port: Spanned<u16>,

    /// TCP port inside the sandbox netns to forward to. `None`
    /// means "same as `host_port`".
    #[serde(default)]
    pub sandbox_port: Option<Spanned<u16>>,
}

impl ForwardDecl {
    /// Effective sandbox port, falling back to `host_port` when
    /// no explicit sandbox port was given.
    pub fn sandbox_port(&self) -> u16 {
        self.sandbox_port
            .as_ref()
            .map(|p| *p.get_ref())
            .unwrap_or_else(|| *self.host_port.get_ref())
    }
}

impl FromStr for ForwardDecl {
    type Err = String;

    /// Parse a `HOST_PORT[:SANDBOX_PORT]` forward specification.
    ///
    /// If only one port is given, sandbox_port is left absent (and
    /// callers fall back to host_port). Multi-colon syntax is
    /// reserved for future extensions (per-address binding, ranges,
    /// etc.). Ports must parse as a `u16`; the port-zero check
    /// runs separately at [`Decl::validate`] time.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        let (host, sandbox) = match parts.as_slice() {
            [single] => (*single, None),
            [host, sandbox] => (*host, Some(*sandbox)),
            _ => {
                return Err(format!(
                    "forward spec {s:?} contains more than one `:`; \
                     multi-colon syntax is reserved for future use"
                ));
            }
        };
        let host_port: u16 = host.parse().map_err(|_| {
            format!("forward host port {host:?} is not a valid TCP port number")
        })?;
        let sandbox_port = match sandbox {
            Some(s) => Some(s.parse::<u16>().map_err(|_| {
                format!(
                    "forward sandbox port {s:?} is not a valid TCP port number"
                )
            })?),
            None => None,
        };
        Ok(ForwardDecl {
            host_port: Spanned::new(0..0, host_port),
            sandbox_port: sandbox_port.map(|p| Spanned::new(0..0, p)),
        })
    }
}

impl Decl for ForwardDecl {
    type Resolved = Forward;

    /// Reject port 0 on either side. Port 0 is "any port" in TCP
    /// land and not a useful forward target. Validation runs after
    /// parsing so the same check applies to CLI and TOML inputs.
    fn validate(&self) -> Result<()> {
        if *self.host_port.get_ref() == 0 {
            return Err(Error::invalid_forward_port("host_port".to_owned(), 0));
        }
        if let Some(sandbox) = &self.sandbox_port
            && *sandbox.get_ref() == 0
        {
            return Err(Error::invalid_forward_port(
                "sandbox_port".to_owned(),
                0,
            ));
        }
        Ok(())
    }

    fn resolve(
        &self,
        _ctx: &resolve_context::ResolveContext,
    ) -> Result<Self::Resolved> {
        Ok(Forward {
            host_port: *self.host_port.get_ref(),
            sandbox_port: self.sandbox_port(),
        })
    }
}

/// A single host-loopback port forwarded into the sandbox netns.
///
/// `host_port` is what the agent's TCP connect request *targets*
/// in the sandbox (since pasta defaults to same-port forwarding,
/// and we currently only support same-port-on-both-sides or an
/// explicit remap). `sandbox_port` is the port number the agent
/// actually sees inside the netns — these can differ when the
/// user passes `-f HOST_PORT:SANDBOX_PORT`.
#[derive(Debug, Clone, Serialize)]
pub struct Forward {
    /// TCP port on host loopback to forward from.
    pub host_port: u16,

    /// TCP port inside the sandbox netns to forward to.
    pub sandbox_port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> std::result::Result<ForwardDecl, String> {
        s.parse()
    }

    #[test]
    fn forward_decl_accepts_single_port() {
        let spec = parse("8080").expect("parses");
        assert_eq!(*spec.host_port.get_ref(), 8080);
        assert!(spec.sandbox_port.is_none());
        assert_eq!(spec.sandbox_port(), 8080);
    }

    #[test]
    fn forward_decl_accepts_host_colon_sandbox() {
        let spec = parse("8080:9090").expect("parses");
        assert_eq!(*spec.host_port.get_ref(), 8080);
        assert_eq!(spec.sandbox_port(), 9090);
    }

    #[test]
    fn forward_decl_rejects_multiple_colons() {
        let err = parse("127.0.0.1:8080:9090")
            .expect_err("multi-colon should be rejected");
        assert!(err.contains("more than one `:`"), "{err}");
    }

    #[test]
    fn forward_decl_validate_rejects_zero_port() {
        // Port 0 parses successfully — it's a valid u16. The
        // rejection happens at validate() time, alongside the TOML
        // path's identical check.
        let host_zero = parse("0").expect("parses port 0 syntactically");
        assert!(host_zero.validate().is_err());
        let sandbox_zero =
            parse("8080:0").expect("parses sandbox 0 syntactically");
        assert!(sandbox_zero.validate().is_err());
        // Non-zero ports validate cleanly.
        assert!(parse("8080").unwrap().validate().is_ok());
        assert!(parse("8080:9090").unwrap().validate().is_ok());
    }

    #[test]
    fn forward_decl_rejects_out_of_range() {
        assert!(parse("65536").is_err());
        assert!(parse("notanumber").is_err());
    }

    #[test]
    fn forward_decl_resolve_yields_forward() {
        let ctx = resolve_context::ResolveContext::empty();
        // Single-port spec: sandbox defaults to host.
        let single = parse("8080").unwrap().resolve(&ctx).expect("resolves");
        assert_eq!(single.host_port, 8080);
        assert_eq!(single.sandbox_port, 8080);

        // Explicit remap: each side carries its own port.
        let remap =
            parse("8080:9090").unwrap().resolve(&ctx).expect("resolves");
        assert_eq!(remap.host_port, 8080);
        assert_eq!(remap.sandbox_port, 9090);
    }
}

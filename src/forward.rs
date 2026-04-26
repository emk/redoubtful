//! The list of TCP port forwards from host loopback into the sandbox.
//!
//! Each [`Forward`] describes one port that pasta should make
//! available to the sandboxed process: the agent connects to
//! `127.0.0.1:sandbox_port` inside the netns, pasta pipes that
//! through to `127.0.0.1:host_port` on the host.
//!
//! v0 scope is intentionally small: TCP only, host loopback only,
//! one port per [`Forward`]. Pasta natively supports ranges, IPv6
//! addresses, and per-address bindings — when we need any of those
//! we widen [`Forward`]/[`ForwardSpec`] without changing the surface
//! of [`ForwardList`].
//!
//! References:
//!
//!   pasta(1) `--tcp-ns` (`-T`) flag, which is what the
//!   per-forward strings produced here are passed through:
//!     <https://passt.top/builds/latest/web/passt.1.html>
//!   Project architecture spec:
//!     `specs/ARCHITECTURE.md`

use std::str::FromStr;

use serde::Serialize;

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

    /// Where this forward came from. Lets `redoubtful forwards
    /// --jsonl` distinguish CLI-supplied forwards from any future
    /// automatic ones (e.g. the credential proxy port).
    pub source: ForwardSource,
}

/// Provenance of a forward — extensible.
///
/// Only one variant today; the credential proxy will add a `Proxy`
/// variant once it lands. Don't add speculative variants — the type
/// has to stay aligned with what actually constructs forwards.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForwardSource {
    /// Added via a `-f`/`--forward` CLI flag.
    Cli,
}

/// The ordered list of forwards pasta should configure for this
/// sandbox.
///
/// A newtype around `Vec<Forward>` so the assembly site can call
/// `forwards.forward(...)` without re-constructing the field-level
/// boilerplate, and so the JSONL emitter can just `serde_json` the
/// whole thing transparently.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(transparent)]
pub struct ForwardList(Vec<Forward>);

impl ForwardList {
    /// An empty forward list — the default.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Append a single TCP port forward.
    pub fn forward(
        &mut self,
        host_port: u16,
        sandbox_port: u16,
        source: ForwardSource,
    ) -> &mut Self {
        self.0.push(Forward {
            host_port,
            sandbox_port,
            source,
        });
        self
    }

    /// Iterate over the forwards in declaration order.
    pub fn iter(&self) -> std::slice::Iter<'_, Forward> {
        self.0.iter()
    }

    /// Whether the list is empty. Used by the pasta argv builder
    /// to choose `-T none` vs an explicit list.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Format the list as the comma-separated SPEC string pasta's
    /// `-T` flag expects: each item is `HOST_PORT` if the two ports
    /// match, else `HOST_PORT:SANDBOX_PORT`.
    ///
    /// Returns an empty string for an empty list — callers should
    /// branch on [`Self::is_empty`] and emit `-T none` instead.
    pub fn format_for_pasta(&self) -> String {
        let mut out = String::new();
        for (i, f) in self.0.iter().enumerate() {
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

/// A single CLI-supplied port forward specification.
///
/// Parses from `HOST_PORT[:SANDBOX_PORT]` via [`FromStr`], which
/// clap picks up automatically — no `value_parser` plumbing
/// required on the option struct.
#[derive(Debug, Clone)]
pub struct ForwardSpec {
    /// TCP port on host loopback to forward from.
    pub host_port: u16,

    /// TCP port inside the sandbox netns to forward to.
    pub sandbox_port: u16,
}

impl FromStr for ForwardSpec {
    type Err = String;

    /// Parse a `HOST_PORT[:SANDBOX_PORT]` forward specification.
    ///
    /// If only one port is given, both sides use the same port (the
    /// common case for `-f 8080`). Multi-colon syntax is reserved
    /// for future extensions (per-address binding, ranges, etc.).
    /// Ports must parse as a non-zero `u16`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        let (host, sandbox) = match parts.as_slice() {
            [single] => (*single, *single),
            [host, sandbox] => (*host, *sandbox),
            _ => {
                return Err(format!(
                    "forward spec {s:?} contains more than one `:`; \
                     multi-colon syntax is reserved for future use"
                ));
            }
        };
        let host_port = parse_port(host).map_err(|e| {
            format!("forward host port {host:?} is invalid: {e}")
        })?;
        let sandbox_port = parse_port(sandbox).map_err(|e| {
            format!("forward sandbox port {sandbox:?} is invalid: {e}")
        })?;
        Ok(ForwardSpec {
            host_port,
            sandbox_port,
        })
    }
}

fn parse_port(s: &str) -> std::result::Result<u16, String> {
    let n: u16 = s.parse().map_err(|_| "not a TCP port number".to_string())?;
    if n == 0 {
        return Err("port 0 is not a valid forward target".to_string());
    }
    Ok(n)
}

/// Shared CLI options for forward flags.
///
/// Flattened with `#[command(flatten)]` into any subcommand that
/// builds a [`ForwardList`] (`run`, `forwards`).
#[derive(Debug, Clone, Default, clap::Args)]
pub struct ForwardOpts {
    /// Forward a TCP port from host loopback into the sandbox.
    /// Repeatable. Format: `HOST_PORT[:SANDBOX_PORT]`. If
    /// `:SANDBOX_PORT` is omitted, the two ports match.
    #[arg(
        short = 'f',
        long = "forward",
        value_name = "HOST_PORT[:SANDBOX_PORT]"
    )]
    pub forward: Vec<ForwardSpec>,
}

impl ForwardOpts {
    /// Append CLI forwards to a [`ForwardList`].
    pub fn apply(&self, list: &mut ForwardList) {
        for spec in &self.forward {
            list.forward(spec.host_port, spec.sandbox_port, ForwardSource::Cli);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> std::result::Result<ForwardSpec, String> {
        s.parse()
    }

    #[test]
    fn forward_spec_accepts_single_port() {
        let spec = parse("8080").expect("parses");
        assert_eq!(spec.host_port, 8080);
        assert_eq!(spec.sandbox_port, 8080);
    }

    #[test]
    fn forward_spec_accepts_host_colon_sandbox() {
        let spec = parse("8080:9090").expect("parses");
        assert_eq!(spec.host_port, 8080);
        assert_eq!(spec.sandbox_port, 9090);
    }

    #[test]
    fn forward_spec_rejects_multiple_colons() {
        let err = parse("127.0.0.1:8080:9090")
            .expect_err("multi-colon should be rejected");
        assert!(err.contains("more than one `:`"), "{err}");
    }

    #[test]
    fn forward_spec_rejects_zero_port() {
        assert!(parse("0").is_err());
        assert!(parse("8080:0").is_err());
    }

    #[test]
    fn forward_spec_rejects_out_of_range() {
        assert!(parse("65536").is_err());
        assert!(parse("notanumber").is_err());
    }

    #[test]
    fn format_for_pasta_uses_short_form_when_ports_match() {
        let mut list = ForwardList::new();
        list.forward(8080, 8080, ForwardSource::Cli);
        list.forward(5432, 9999, ForwardSource::Cli);
        assert_eq!(list.format_for_pasta(), "8080,5432:9999");
    }

    #[test]
    fn empty_forward_list_formats_to_empty_string() {
        let list = ForwardList::new();
        assert!(list.is_empty());
        assert_eq!(list.format_for_pasta(), "");
    }
}

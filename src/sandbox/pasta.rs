//! Build the pasta command line for `redoubtful run`.
//!
//! Pasta sits between `redoubtful` and `bwrap` in the process tree:
//!
//! ```text
//! redoubtful → pasta → bwrap → user command
//! ```
//!
//! Pasta creates a private network namespace (and joins a per-pasta
//! user namespace), connects the netns to the host with a tap-mode
//! virtual link that has *no route* to the Internet or to host
//! loopback, and forwards a small allowlist of host-loopback ports
//! through to the netns. Bwrap, running inside, inherits the netns
//! (via `--share-net`).
//!
//! The flag block here is small but security-critical:
//!
//! - `--config-net` — actually configure the tap interface (without
//!   this, pasta sets up the netns but leaves it unrouted).
//! - `--no-map-gw` — don't map pasta's host-side address as a
//!   reachable gateway from inside the netns. Without this, the
//!   sandbox could DNS or HTTP over loopback to whatever pasta
//!   exposes on its host side.
//! - `--no-dhcp --no-dhcpv6 --no-ra` — skip the dynamic-config
//!   protocols pasta would otherwise serve into the netns. We do
//!   our own static plumbing.
//! - `--foreground` — pasta defaults to *daemonizing* when started
//!   from a TTY, which would break our exit-code propagation
//!   (`Command::wait` would return immediately on the dropped
//!   parent). `--foreground` keeps pasta as our direct child until
//!   the inner command exits.
//! - `-t none` — disable the *namespace-to-host* TCP forwarding
//!   default (`-t auto`), which would otherwise expose any port
//!   the agent binds in the netns back to the host. We never want
//!   that.
//! - `-T <list-or-none>` — explicit allowlist for *host-to-namespace*
//!   forwarding, which is the direction the user actually wants
//!   (`-T auto`, the default, would forward every port currently
//!   bound on the host into the netns — a massive leak).
//!
//! References:
//!
//!   pasta(1) manpage:
//!     <https://passt.top/builds/latest/web/passt.1.html>
//!   Project architecture spec:
//!     `specs/ARCHITECTURE.md`
//!
//! This file contains security configuration, so we favor comment
//! overkill and links to supporting documentation for audit.

use std::ffi::OsString;

use crate::{
    config::forwards::Forwards, prelude::*, sandbox::argv::ArgvBuilder,
};

/// Build the full argv for `pasta` (not including `pasta` itself),
/// ending with `-- <child argv...>` (typically the bwrap command).
#[instrument(level = "debug", skip_all, fields(n_forwards = forwards.iter().count()))]
pub fn pasta_argv(
    forwards: &Forwards,
    child_argv: Vec<OsString>,
) -> Vec<OsString> {
    let mut a = ArgvBuilder::default();

    // ===== Network configuration =====
    a.flag("--config-net");
    a.flag("--no-map-gw");
    a.flag("--no-dhcp");
    a.flag("--no-dhcpv6");
    a.flag("--no-ra");

    // ===== Lifecycle =====
    //
    // Pasta defaults to daemonizing when started from a TTY. We need
    // it to stay our direct child so `Child::wait` actually waits
    // for the sandbox to exit and propagates its status.
    a.flag("--foreground");

    // ===== TCP forwarding policy =====
    //
    // -t (--tcp-ports) controls *namespace → host* forwarding;
    // default `auto` would forward every port the agent binds in
    // the netns back to the host. Force off.
    a.pair_str("-t", "none");

    // -T (--tcp-ns) controls *host → namespace* forwarding; default
    // `auto` would forward every port currently bound on the host
    // into the netns. Replace with an explicit list (or `none`).
    let tcp_ns = if forwards.is_empty() {
        "none".to_string()
    } else {
        forwards.format_for_pasta()
    };
    a.pair_str("-T", &tcp_ns);

    // ===== Inner command =====
    a.flag("--");
    a.extend_os(child_argv);
    let argv = a.into_vec();

    // Per spec: log the exact pasta argv at DEBUG so users can
    // reproduce failures by hand.
    debug!(?argv, "pasta argv");
    argv
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn position(argv: &[OsString], token: &str) -> Option<usize> {
        argv.iter().position(|a| a.as_os_str() == OsStr::new(token))
    }

    #[test]
    fn argv_includes_required_network_flags() {
        let forwards = Forwards::default();
        let argv = pasta_argv(&forwards, vec![]);
        assert!(argv.contains(&os("--config-net")));
        assert!(argv.contains(&os("--no-map-gw")));
        assert!(argv.contains(&os("--no-dhcp")));
        assert!(argv.contains(&os("--no-dhcpv6")));
        assert!(argv.contains(&os("--no-ra")));
        assert!(argv.contains(&os("--foreground")));
    }

    #[test]
    fn argv_disables_namespace_to_host_forwarding() {
        let forwards = Forwards::default();
        let argv = pasta_argv(&forwards, vec![]);
        let t_pos = position(&argv, "-t").expect("-t flag present");
        assert_eq!(argv.get(t_pos + 1), Some(&os("none")));
    }

    #[test]
    fn argv_uses_t_capital_none_when_no_forwards() {
        let forwards = Forwards::default();
        let argv = pasta_argv(&forwards, vec![]);
        let t_pos = position(&argv, "-T").expect("-T flag present");
        assert_eq!(argv.get(t_pos + 1), Some(&os("none")));
    }

    #[test]
    fn argv_uses_t_capital_list_when_forwards_present() {
        let mut forwards = Forwards::default();
        forwards.forward(8080, 8080);
        forwards.forward(5432, 9999);
        let argv = pasta_argv(&forwards, vec![]);
        let t_pos = position(&argv, "-T").expect("-T flag present");
        assert_eq!(argv.get(t_pos + 1), Some(&os("8080,5432:9999")));
    }

    #[test]
    fn argv_includes_proxy_port_as_a_forward() {
        // The proxy port is now just another forward entry with no
        // special treatment — `proxy_profile` adds it via
        // `forwards.forward(port, port)`.
        let mut forwards = Forwards::default();
        forwards.forward(43210, 43210);
        forwards.forward(8080, 8080);
        forwards.forward(5432, 9999);
        let argv = pasta_argv(&forwards, vec![]);
        let t_pos = position(&argv, "-T").expect("-T flag present");
        assert_eq!(argv.get(t_pos + 1), Some(&os("43210,8080,5432:9999")));
    }

    #[test]
    fn child_argv_appears_after_double_dash() {
        let forwards = Forwards::default();
        let argv = pasta_argv(&forwards, vec![os("bwrap"), os("--share-net")]);
        let dash = position(&argv, "--").expect("-- separator present");
        assert_eq!(argv.get(dash + 1), Some(&os("bwrap")));
        assert_eq!(argv.get(dash + 2), Some(&os("--share-net")));
    }
}

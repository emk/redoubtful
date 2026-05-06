# Security Philosophy (as understood by Qwen)

> **Status:** Qwen3 27B's draft understanding based on a discussion. Subject to refinement.

## Core Philosophy

`redoubtful` implements a sandbox for running coding agents (Claude Code, OpenCode, etc.) that prioritizes **security through OS-level isolation** rather than application-level permission dialogs.

The guiding insight is that standard agent permission systems are fundamentally flawed: they interrupt the agent's work, require human judgment calls mid-task, and rely on users who are tired or overwhelmed to make security decisions. The result is either excessive friction or rubber-stamped approvals.

Instead, redoubtful establishes **tight security boundaries at the OS level** using Linux namespaces (mount, pid, user, net, ipc, uts, cgroup) and then allows the agent to operate freely within those boundaries. This is the Unix approach: least privilege at the perimeter, autonomy inside.

## The Security-Ergonomics Trade-off

The goal is not maximum security against sophisticated adversaries, but **practical security that people actually use**. High-friction tools don't get used. The design philosophy is "a lot of security in a highly ergonomic package" — enough isolation to make `--dangerously-skip-permissions` safe by construction, without requiring constant human intervention.

## The Lethal Trifecta

The sandbox addresses three risk factors:

1. **Access to private data** — Aggressively restricted via filesystem isolation, phantom home directory, and credential injection (no real credentials inside the sandbox)
2. **Exposure to untrusted content** — Controlled via network policies and the `public_web` toggle
3. **Ability to externally communicate** — Controlled via the same network policies

The sandbox restricts (1) aggressively. The user controls (2) and (3) with a single switch (`public_web = "allow"` / `"deny"`).

## The Agent-as-Contractor Model

The agent is treated like an external human contractor:

- Issued specific access on an as-needed basis
- Given workspace (project directory) and tools (sandboxed environment)
- Provided with scoped credentials via the proxy
- Not trusted with dangerous abilities that should be managed via process controls

Organizational controls (branch protection, CI checks, merge queues) are the right layers for preventing damage, not permission dialogs.

## Collaboration Surface

The sandbox is designed for human-agent collaboration on the same machine. The human works outside the sandbox with full access; the agent works inside with restricted access. They meet at the **shared project directory**, which is bind-mounted read-write.

This differs from remote VM approaches (which make sense for unattended tasks) by enabling immediate collaboration without requiring the agent to have access beyond the project.

## The Credential Proxy

The proxy runs in-process on the host, never inside the sandbox. It serves two purposes:

1. **Credential injection** — The sandbox contains fake/placeholder credentials. The proxy intercepts requests and injects real ones.
2. **Network policy enforcement** — The proxy controls what network destinations are reachable.

### Policy Chain

1. **Explicit route** — Specific rule for this site? Apply it (MITM with injection, tunnel, or explicit deny) and stop.
2. **Public web check** — Is this a public web site (standard port, non-private IP)? Apply the `public_web` policy (defaults to allow, user can set deny).
3. **Default deny** — Everything else is blocked.

### Modes

- **MITM mode** — Proxy intercepts TLS, decrypts HTTP, injects/swap credentials, re-encrypts to real destination. Used for sites that need credential injection.
- **Tunnel mode** — Proxy just pipes bytes bidirectionally. Client does real TLS to real destination. Used for allowlisted hosts that don't need credential injection.

### Certificate Authority

- Fresh CA keypair per sandbox session via `rcgen`
- Leaf certs generated on-the-fly per hostname, cached for session
- Trusted only inside sandbox via environment variables; never installed on host
- Destroyed on teardown

### DNS

DNS resolution happens in the proxy, not in the sandbox. The sandbox has no DNS access, so it can only reach hosts the proxy is configured to handle (or that pass the public web check).

## Security Properties

1. No real credentials appear inside the sandbox (not as env vars, files, or disk)
2. No host files outside the project directory and configured read-only list are accessible
3. No TCP destinations reachable except forwarded host-loopback ports and allowed public destinations
4. No DNS resolution to arbitrary hosts (proxy handles resolution)
5. Fresh namespaces isolate the sandbox from host processes and authority
6. Configuration files (`.bashrc`, `.gitconfig`, etc.) are write-protected

## Design Principles

- **OS-enforced boundaries > application-enforced permissions** — Use mount namespaces, network isolation, and capability dropping rather than permission dialogs
- **Simple controls for common cases** — One toggle (`public_web`) controls broad policy; explicit routes add granularity when needed
- **Credentials outside the sandbox** — The proxy is the single point where real credentials exist
- **Fail-closed** — Default deny for network, explicit allow for filesystem access
- **Auditability** — Small, legible proxy code handling credentials; structured logging

## What This Means

Inside the sandbox, the agent can run with `--dangerously-skip-permissions` because the sandbox already established the dangerous part: restricting what's accessible. The flag is only "dangerous" relative to an unrestricted shell — relative to the sandbox's boundaries, it's the rational default.

The sandbox doesn't try to prevent all possible harm (like exfiltration of project code via public endpoints). Instead, it establishes a strong baseline: the agent has no credentials, limited host data, and controlled network access. The user then adjusts the `public_web` toggle based on their risk tolerance and the agent's task.

# Hardening: layered defense for the redoubtful sandbox

> **Status:** Design notes from Claude. None of these layers are
> implemented in `redoubtful run` yet beyond what bwrap and pasta do
> by default. This doc captures the layered model we want to build
> toward; see [APPARMOR_USERNS.md](APPARMOR_USERNS.md) for the
> userns-specific Ubuntu/AppArmor piece, which slots in as one layer
> of the stack described here.
>
> Note that this is Claude-authored in multiple passes, and may not
> be 100% self-consistent, or guaranteed to be in line with the
> final security posture and tradeoffs.

## Scope

The irreducible goal is **don't make redoubtful a userns
attack-surface delta**. On a host that blocks unprivileged userns
creation (the Ubuntu 24.04+ default), shipping a way for the
redoubtful binary to bypass that restriction means we own the
consequences: the agent inside our sandbox can reach kernel attack
surface that wasn't reachable from the same shell without us. The
whole document is structured around closing that gap.

Beyond that, we want graceful defense-in-depth, but we're not
building a bullet-proof sandbox. The coding agents redoubtful is
designed for don't generally try complex kernel exploits — future
agents might (Mythos being the named hypothetical), so the layers
below are worth sketching, but treat anything past "block userns
recursion + use bwrap correctly" as nice-to-have rather than blocker.

Practical implication: Tier A below is the first shipping milestone
and is sufficient for the current threat model. Tier B is sketched
so we know what the next investment looks like, not because we're
committing to build it now.

## Containers vs. sandboxes

The Linux kernel collapsed two distinct use cases into a single set of
namespace primitives:

- **Containers** want a private little world where the calling process
  is "fake root" with capabilities it didn't have before, and where
  nested containers (DinD, nested Flatpak, etc.) compose recursively.
  User namespaces deliver exactly this: creating a userns grants the
  creator the full namespaced capability set, by design.
- **Sandboxes** want strictly less privilege than the calling process,
  with no syscall path that lets the sandboxed code un-do that
  smallness. Recursion is suspicious — a sandbox that can spawn a
  child sandbox with broader powers is a sandbox that can be escaped.

User namespaces are fundamentally a *container* primitive being
repurposed as a *sandbox* primitive. Most of the mitigations in this
document are, at heart, attempts to make the userns machinery stop
handing out container powers when we only wanted isolation.

The kernel community is gradually adding sandbox-shaped primitives
that don't have this conflation — Landlock, `no_new_privs`, seccomp —
but none of them replace the namespace machinery for filesystem and
process isolation. So redoubtful needs both: namespaces for the
isolation, sandbox-shaped primitives layered on top to clamp the
escape paths.

## Recursion as a policy violation (in the default posture)

In redoubtful's default operating posture, any successful
`unshare(CLONE_NEWUSER)` from inside the sandbox is a policy
violation. Not "interesting telemetry," not "something to defang"
— forbidden outright. The typical agent legitimately should never
need a nested userns; agent tooling that wants one is doing
something the default threat model already treats as suspect.

Three layers enforce this independently:

1. **seccomp** filter inside the sandbox blocks the `unshare`/`clone`
   syscall variants that take `CLONE_NEWUSER`.
2. **Per-userns `max_user_namespaces=0`** means the kernel refuses
   to allocate a nested userns even if seccomp is bypassed.
3. **AppArmor recursive `pix` cap-deny** (Ubuntu/Debian only) means
   if a nested userns is somehow created anyway, the capabilities
   that creation grants are denied at the LSM layer.

Belt, suspenders, and a second pair of suspenders.

But this is a posture choice, not a categorical rule. Users
developing sandbox tooling — the obvious example being redoubtful
working on itself — legitimately need nesting, and they accept a
weaker security posture in exchange. The "Self-hosting" subsection
below covers that operating point; the short version is fish or
cut bait. The policy violation framing applies to the default
posture, not to every conceivable use of the tool.

## The layered model

| # | Layer | Mechanism | Coverage |
|---|---|---|---|
| 1 | Namespace isolation | bwrap + pasta | Agent gets a clean filesystem view, fresh PID/UTS/IPC/cgroup namespaces, isolated networking |
| 2 | Privilege descent | `prctl(PR_SET_NO_NEW_PRIVS, 1)` | Closes setuid / file-cap escape paths; prerequisite for unprivileged seccomp |
| 3 | Syscall denial | seccomp BPF filter | Blocks userns recursion + the obvious kernel-exploit primitives |
| 4 | Userns recursion limit | `/proc/sys/user/max_user_namespaces=0` | Kernel refuses nested userns even if seccomp is bypassed |
| 5 | Cap mediation in nested userns | AppArmor recursive `pix` (Ubuntu/Debian) | Caps inside any nested userns are denied at the LSM layer |
| 6 | Filesystem/network path denial | Landlock | Tightens the FS view bwrap already established |
| 7 | Memory inspection | `prctl(PR_SET_DUMPABLE, 0)` | Same-UID processes can't ptrace or read `/proc/pid/mem` |

Layers 1–4 and 7 are portable across Linux distros and are mandatory.
Layer 5 is the Ubuntu/Debian AppArmor work documented in
[APPARMOR_USERNS.md](APPARMOR_USERNS.md). Layer 6 is phase-2 hardening.

On non-Ubuntu systems the AppArmor layer is unavailable, but the
seccomp + sysctl + namespace combination still keeps recursive userns
shut. Equivalent SELinux confinement on Fedora/RHEL is plausible but
unexplored; for now those distros run on the portable layers alone.

## Two implementation tiers

The layers above split into two implementation tiers, and the second
tier is materially more complex than the first.

**Tier A — parent-side.** Everything redoubtful's parent process and
the bwrap invocation can do without a helper inside the sandbox:

- AppArmor profile (loaded into the kernel, attached to the
  redoubtful binary path).
- `--seccomp <fd>` filter handed to bwrap on the command line.
- bwrap's own flags: namespace creation, mount setup, UID mapping,
  argv handling.
- `no_new_privs` (bwrap sets this when any `--unshare-*` flag is
  in use; we should still verify rather than assume).

This is mostly "configure bwrap correctly" — no new process to
write, no init responsibilities. Tier A should land first; it gets
us most of the layered model on a cleanly portable basis.

**Tier B — inside-sandbox shim.** Some hardening can only be applied
from inside the userns, after bwrap finishes its setup but before
the agent runs:

- Writing `/proc/sys/user/max_user_namespaces=0`. Needs the
  namespace-owner caps that bwrap has but the agent shouldn't, so
  it has to happen between bwrap's setup and the agent's exec.
- `PR_SET_DUMPABLE 0`. The flag is reset to 1 by execve unless set
  by the immediate pre-exec process; only a shim that exec's the
  agent can pin it.
- Landlock rule application. Process-self-restriction; survives
  exec, but has to be applied by something already inside the
  sandbox.
- A tighter second-tier seccomp filter just before exec'ing the
  agent. The bwrap-applied filter covers shim and agent equally;
  a shim can install something stricter for the agent alone.

The natural shape is `bwrap ... -- redoubtful sandbox-init --
<agent-cmd>`: bwrap execs a `redoubtful` subcommand, which applies
the Tier B hardening and then exec's the agent. Keeping the shim
inside redoubtful's own binary avoids a separate dependency.

If the agent forks children (likely for any non-trivial coding
agent), the shim should also act as a real PID-1 init inside the
PID namespace: install signal handlers that forward to the agent's
process group, reap orphan zombies, and propagate the agent's exit
status. This is ~50–100 lines of careful Rust, or a dependency on a
tini-equivalent crate. Skipping it leads to the classic "container
that ignores SIGTERM" and "zombie pile" bugs.

Tier B brings real complexity — its own seccomp filter to think
about, init duties, signal semantics, exit-code propagation. But
Tier A alone leaves a meaningful gap: the agent can recurse via
userns if the seccomp filter ever has a hole, Landlock isn't
reachable without inside-sandbox application, and `PR_SET_DUMPABLE`
needs the pre-exec slot. So Tier B is likely the long-term shape,
with Tier A as the first shipping milestone.

## Layer details

### `no_new_privs`

Single bit set via `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Once set,
propagates to all children and can never be cleared. Required as a
precondition for unprivileged seccomp filters; also closes setuid
binary escape paths.

bwrap appears to set this whenever any `--unshare-*` flag is in play,
but we shouldn't rely on assumption when the cost of a
`prctl(PR_GET_NO_NEW_PRIVS)` check is one syscall. Verify at runtime,
either inside `redoubtful check` or as a startup assertion in `run`.

Available since Linux 3.5 (2012).

### seccomp filter

bwrap accepts `--seccomp <fd>` for an explicit BPF filter, but
installs nothing by default.

**Required (blocks userns recursion):**

- `unshare(2)` when `flags & CLONE_NEWUSER`.
- `clone(2)` when `flags & CLONE_NEWUSER`.
- `clone3(2)` outright. The syscall takes a struct pointer, so
  seccomp can't inspect its flag arg; the standard play is "deny
  `clone3` and force fallback to `clone`." Modern glibc may have
  switched some paths to `clone3`, so this needs a test pass on
  common agent runtimes (Python, Node, common shells) to confirm
  legitimate workloads still work.

This is the part directly tied to the userns scope concern — it's
what stops redoubtful from being a userns attack-surface delta even
if AppArmor isn't available or the per-userns sysctl write fails.

**Nice-to-have (broader kernel-attack-surface reduction):**

The obvious additional deny candidates: `kexec_load`, `init_module`,
`finit_module`, `delete_module`, `bpf` (or scope tightly), `keyctl`,
`userfaultfd`, `perf_event_open`, `quotactl`, `swapon`, `swapoff`.
The Chrome and Firefox sandbox baselines are good references for
fuller deny lists. None of this is on the critical path for the
userns scope concern; it's defense against agents that go looking
for kernel CVEs, which today's agents generally don't.

On the Rust side, `seccompiler` or `libseccomp-rs` will compile the
filter; we pass the resulting fd to bwrap via `--seccomp`.

Available since Linux 3.17 (2014). Requires `no_new_privs` for
unprivileged use.

### Per-userns `max_user_namespaces=0`

`/proc/sys/user/max_user_namespaces` is a per-userns sysctl: the
kernel keeps a separate copy in each `user_namespace` struct, and
processes inside the namespace can *lower* (never raise) it. Setting
it to 0 inside the agent's bwrap-created userns prevents any further
nested userns from being allocated.

Writing the sysctl requires `CAP_SYS_RESOURCE` in the userns. The
bwrap process is the owner of its userns and has all caps there, so
it can do the write — the open question is *when* in bwrap's setup
sequence we get the chance. Options: lobby for a bwrap flag, use a
shim that runs after bwrap finishes setup but before exec'ing the
agent, or do the write ourselves from a tiny binary launched by
bwrap's `--exec-label`/`--cap-add`/etc. machinery.

Available since Linux 4.9 (2016).

### `PR_SET_DUMPABLE 0`

Cheap one-liner. Prevents same-UID processes from `ptrace`-ing the
agent or reading `/proc/<agent-pid>/mem`. Defense against an attacker
who already has same-UID code execution *outside* the sandbox; not
the primary threat for redoubtful, but trivially worth doing.

### Landlock (phase 2)

Linux 5.13+ kernel feature for self-imposed filesystem and network
access control. ABI v6 (Linux 6.12+) covers filesystem path access,
TCP socket bind/connect, abstract Unix sockets, signal scoping, and
IOCTL restrictions on devices.

Landlock complements bwrap rather than replacing it. Landlock denies
access on the filesystem view you already have; bwrap gives you a
*different* (smaller) view. For sandboxing, "the path doesn't exist"
beats "the path exists but `EACCES`" because the latter leaks
structure to a curious agent.

Reasonable phase-2 use: apply Landlock immediately before exec'ing
the agent inside bwrap to further pin down filesystem and network
access on top of the bwrap mounts. The Rust `landlock` crate (from
the upstream maintainer) is straightforward.

## Self-hosting (redoubtful inside redoubtful)

Running redoubtful inside its own sandbox — e.g., letting an agent
work on the redoubtful codebase and test changes — requires the
**Tier 2** operating point throughout: a `flags=(unconfined) {
userns, }` profile, with none of the recursion-blocking mitigations
installed. Inner bwrap then creates its userns through the same
kernel-sysctl gate the outer one used; the inner agent ends up
with the same namespaced caps as the outer.

There is no halfway option. A "Tier 1 with nesting allowed" mode
would have to disable the seccomp `CLONE_NEWUSER` deny, skip the
`max_user_namespaces=0` write, and either weaken
`redoubtful_unpriv`'s cap-deny or accept that inner bwrap fails at
mount/pivot_root. At that point Tier 2 has been reconstructed with
extra ceremony.

So self-hosting is fish or cut bait: accept the reduced security
posture (Tier 2 throughout, by definition), or don't nest. The case
for accepting it is reasonable in this specific context — the agent
doing redoubtful development is one you already trust enough to
hand userns and namespaced caps to — but it's a deliberate choice,
not a free lunch.

## Implications for `redoubtful check`

Some of these layers need their own check entries beyond the
AppArmor probe documented in `plans/CHECK_SUBCOMMAND.md`:

- Kernel version sufficient for the syscalls/sysctls we depend on.
- seccomp available (probe via `prctl(PR_GET_SECCOMP)` or a small
  filter install + remove).
- `no_new_privs` works (universal on any kernel from the past
  decade, but cheap to verify).
- Per-userns `max_user_namespaces` writable from inside a probe
  bwrap (this is the layer most likely to surprise us in practice).
- Landlock available, if we adopt it.

Failures split between "we can fix this for you" (the AppArmor
remediation paths in `APPARMOR_USERNS.md`) and "your kernel literally
can't sandbox this way" (very old kernel, seccomp disabled at boot,
etc.). The check output should distinguish the two so the user knows
whether they're looking at a config tweak or a host change.

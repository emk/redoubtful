# AppArmor user-namespace restriction on Ubuntu 24.04+

> **Status:** Research by Claude, with empirical verification on a
> single Ubuntu 24.04 box (kernel 6.17, AppArmor 4.0.1). Check
> sources before relying on any specific claim.
>
> **See also:** [HARDENING.md](HARDENING.md) for the broader
> defense-in-depth model this AppArmor work fits into. The AppArmor
> layer is one of seven; the others are portable across distros.

Ubuntu 24.04 (Noble) and later ship with AppArmor's
"unprivileged userns restriction" turned on by default. With this
restriction in place, `bwrap` cannot create a user namespace and fails
immediately:

```
$ bwrap --unshare-all --share-net -- true
bwrap: setting up uid map: Permission denied
```

Confirm with:

```
$ cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
1
```

The unrelated sysctl `kernel.unprivileged_userns_clone` is *not* the
blocker — it has been `1` (allowed) for years and remains so on
24.04. Bubblewrap ships
`/usr/lib/sysctl.d/50-bubblewrap.conf` solely to keep that legacy knob
on, but that file does not address the AppArmor restriction.

## Why the restriction exists

Unprivileged user namespaces are not a privilege-escalation primitive
on their own — the kernel's `ns_capable()` check confines capability
bits to the namespace as designed. The problem is **kernel
attack-surface expansion**: creating a userns lets an unprivileged
process reach syscall paths gated on `CAP_SYS_ADMIN` /
`CAP_NET_ADMIN` / `CAP_NET_RAW` that the kernel community had
implicitly assumed only real root would ever drive. [Edera measured
the expansion empirically][edera] at ~2.6× more "privileged" syscall
paths reachable on a current 6.18 kernel (8/40 sampled operations
without userns vs. 27/40 with).

The CVE history is the receipt. Examples Ubuntu's
[23.10 spec][ubuntu-23.10] explicitly cites:

- [CVE-2022-0185][cve-2022-0185] — fs_context, `CAP_SYS_ADMIN`-via-mount
- [CVE-2022-1015][cve-2022-1015] / [-25636][cve-2022-25636] /
  [-2078][cve-2022-2078] — nftables, `CAP_NET_ADMIN`
- [CVE-2022-24122][cve-2022-24122] — ucounts refcount, exploited
  inside userns
- [CVE-2020-14386][cve-2020-14386] — AF_PACKET, `CAP_NET_RAW`

And the headline post-restriction case:

- [CVE-2024-1086][cve-2024-1086] — nf_tables double-free, ~99%
  reliable LPE on stock Ubuntu/Debian, requires unprivileged userns
  plus nftables to trigger.

nftables alone accounts for ~18 of the ~40 catalogued userns-enabled
kernel CVEs since 2020; eBPF, overlayfs, and the namespace machinery
itself contribute most of the rest. The bridge from "fake root in
namespace" to "host compromise" is always: namespaced capability
check passes → unscoped buggy kernel code runs in ring 0.

So the restriction is prophylaxis with a long history and a strong
prior that the next bug of this shape is coming.

[edera]: https://edera.dev/stories/user-namespaces-are-not-a-security-boundary
[ubuntu-23.10]: https://discourse.ubuntu.com/t/spec-unprivileged-user-namespace-restrictions-via-apparmor-in-ubuntu-23-10/37626
[cve-2022-0185]: https://nvd.nist.gov/vuln/detail/CVE-2022-0185
[cve-2022-1015]: https://nvd.nist.gov/vuln/detail/CVE-2022-1015
[cve-2022-25636]: https://nvd.nist.gov/vuln/detail/CVE-2022-25636
[cve-2022-2078]: https://nvd.nist.gov/vuln/detail/CVE-2022-2078
[cve-2022-24122]: https://nvd.nist.gov/vuln/detail/CVE-2022-24122
[cve-2020-14386]: https://nvd.nist.gov/vuln/detail/CVE-2020-14386
[cve-2024-1086]: https://nvd.nist.gov/vuln/detail/CVE-2024-1086

## How nested user namespaces compound the risk

The kernel-attack-surface story has a second layer that's easy to
miss. From `user_namespaces(7)`:

> The child process created by clone(2) with the CLONE_NEWUSER flag
> starts out with a complete set of capabilities in the new user
> namespace. Likewise, a process that creates a new user namespace
> using unshare(2) ... gains a full set of capabilities in that
> namespace.

Translation: **whoever creates a user namespace becomes its owner
and gets the full namespaced capability set inside it, regardless
of UID or capabilities held before.** This is the deliberate
mechanism by which unprivileged users gain `CAP_SYS_ADMIN` etc. for
legitimate container-style use.

The direct consequence for sandboxing is unpleasant: an agent
process that starts inside our bwrap sandbox with no useful caps
can still call `unshare -U -m` to spawn a *child* user namespace
where it is the owner, and therefore has full namespaced caps. The
kernel attack surface that motivates the original AppArmor
restriction is reachable from inside our sandbox via one syscall —
unless we close that path.

The Tier 1 profile addresses this with the recursive `pix /** ->
&redoubtful_unpriv` rule: any further userns the agent creates
inherits `audit deny capability,` from `redoubtful_unpriv`, so the
caps the kernel grants are stripped at the LSM layer before they
can reach a privileged syscall. That recursion-handling is the
*specific* reason the Tier 1 chain looks the way it does, and is
the main thing Tier 2's `flags=(unconfined)` profile gives up: the
agent inside Tier 2 *can* recurse into a fresh userns and reach the
full kernel attack surface there.

Independent of AppArmor, redoubtful should also block userns
recursion at the seccomp and per-userns-sysctl layers as
defense-in-depth — those mechanisms apply on non-Ubuntu hosts where
AppArmor isn't available. See [HARDENING.md](HARDENING.md) for the
broader layering.

## Why no default bwrap profile

Ubuntu does **not** ship an AppArmor profile attached to `/usr/bin/bwrap`
by default, and Canonical has explicitly said the naive form (just
`flags=(unconfined) { userns, }`) won't be added: bwrap is a generic
launcher and whitelisting it that way would defeat the entire
restriction. Any unprivileged process can shell out to bwrap to get
userns, so the protection collapses to "trust everyone with a
shell." John Johansen (AppArmor maintainer) framed this on Launchpad
#2046844 as needing real per-binary scoping, not blanket grants.

The same shape *is* shipped for many specific tools — see
`/etc/apparmor.d/{firefox,chrome,code,flatpak,buildah,crun}` —
because each of those is a specific named binary, not a generic
launcher. **redoubtful is in that category.** A profile attached to
`/usr/bin/redoubtful` (or wherever it's installed) is appropriate
exactly the way Firefox's profile is.

The upstream AppArmor project also ships a more careful profile
called `bwrap-userns-restrict` (in
`apparmor/profiles/extras/`) that uses **profile stacking** to allow
bwrap itself to create a userns while denying capabilities to
processes *inside* that namespace — neutralizing most of the exploit
shape (CVE-2024-1086 and the netfilter family). Ubuntu briefly
shipped this profile in mid-2024 and rolled it back within weeks
([LP #2072811][lp-2072811]) because it broke Flatpak apps' file
saving. It now lives only upstream as an opt-in, with a release-notes
caveat that the Flatpak interaction still isn't fixed.

## Three options for letting redoubtful create user namespaces

There is no truly clean answer. Each option trades against the next.
Empirically tested on this box; see "What we confirmed" below.

### Tier 1 — surgical: chained per-binary profile + `change_profile` lockdown

A four-profile chain (`redoubtful` → `redoubtful_pasta` →
`redoubtful_bwrap`, plus `redoubtful_unpriv` as the cap-stacking
partner), paired with the system-wide `change_profile` gate. See
`plans/apparmor-test-redoubtful.profile` for the working profile.

The chain mirrors the upstream `bwrap-userns-restrict` shape:

- `redoubtful` is attached to the redoubtful binary path. Px-transitions
  into `redoubtful_pasta` when it execs `/usr/bin/pasta`.
- `redoubtful_pasta` allows pasta to create its userns + TAP. ix on
  pasta's AVX2 self-dispatch. Px-transitions into `redoubtful_bwrap`
  when pasta execs `/usr/bin/bwrap`.
- `redoubtful_bwrap` allows bwrap to do its setup (mount, pivot_root,
  etc.). Uses `pix /** -> &redoubtful_bwrap//&redoubtful_unpriv` to
  stack `redoubtful_unpriv` onto bwrap's children — the agent and
  anything it spawns.
- `redoubtful_unpriv` is the stacking partner. It allows userns
  recursively (so agent tools that legitimately need a nested userns
  still work) but `audit deny capability,`. The intersection of
  allow-sets removes capabilities inside the namespace.

Pair with:

```
sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=1
echo "kernel.apparmor_restrict_unprivileged_unconfined=1" \
  | sudo tee /etc/sysctl.d/60-apparmor-hardening.conf
```

This sysctl prevents an arbitrary unprivileged shell from using
`aa-exec` to enter `redoubtful_bwrap` (or similar) and bypass the
binary attachment. With it on, only execve of the redoubtful binary
itself reaches the userns grant. Ubuntu plans to enable this sysctl
by default in 25.04+.

Result: bwrap creates a user namespace inside redoubtful's chain,
but the agent inside has no usable capabilities. CVE-2024-1086 and
similar nftables/netfilter exploits return EPERM at the LSM cap check.

**Cost:** ~80 lines of profile to maintain. AppArmor ABI/syntax may
shift between versions. Custom rather than off-the-shelf.

**Doesn't break Flatpak.** The Flatpak profile is unchanged; bwrap
running outside redoubtful still hits the kernel sysctl deny.

### Tier 2 — short: Flatpak-style label-only profile

A 5-line profile attached to redoubtful, identical in shape to the
ones Ubuntu ships for Firefox/Chrome/VSCode/Flatpak. See
`plans/apparmor-test-redoubtful-short.profile`.

```
profile redoubtful /path/to/redoubtful flags=(unconfined) {
  userns,
  include if exists <local/redoubtful>
}
```

`flags=(unconfined)` means the profile is labeling-only — AppArmor
doesn't enforce restrictions, it just grants `userns,` to satisfy
the kernel sysctl. pasta and bwrap and the agent all inherit the
unconfined `redoubtful` label. The agent has full namespaced
capabilities — same as a process inside Firefox's renderer.

**Cost:** trivial to maintain; matches a well-known pattern.

**Trade-off:** the agent in the sandbox has the same kernel attack
surface as a Firefox renderer. CVE-2024-1086 is reachable from inside
the sandbox. Acceptable if you trust your sandbox bound — bwrap
mounts, pasta networking — to contain a compromised agent that has
namespaced caps. Not acceptable if your threat model assumes the
agent is the primary attacker.

**Doesn't break Flatpak.**

### Tier 3 — fallback: lift the kernel restriction system-wide

```
echo 'kernel.apparmor_restrict_unprivileged_userns=0' \
  | sudo tee /etc/sysctl.d/60-apparmor-namespace.conf
sudo sysctl --system
```

Or non-persistently:

```
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

Lifts the userns restriction for *every* unprivileged process on the
box. Acceptable on a single-user developer machine; not great on
shared or multi-user systems. Reasonable choice if installing
AppArmor profiles is impractical.

**Doesn't break Flatpak.** Flatpak's existing profile machinery is
unaffected.

## What we confirmed empirically

On this Ubuntu 24.04 box with kernel 6.17 and AppArmor 4.0.1, with
test profiles attached to a wrapper binary at a known path:

1. **The kernel sysctl `apparmor_restrict_unprivileged_userns=1`
   blocks userns creation by unconfined processes.** Direct `bwrap
   --unshare-all -- true` from a regular shell fails at
   `setting up uid map: Permission denied`. Audit log shows AppArmor
   transitioning the unconfined task into a built-in
   `unprivileged_userns` profile that denies the followup uid_map
   write.
2. **A binary-attached profile that grants `userns,` lets the named
   binary create user namespaces.** Both the chained Tier 1 form and
   the Flatpak-style Tier 2 form work — the kernel mediates userns
   based on the profile attached at execve time.
3. **`Px -> name` resolves to top-level profiles by name.** This is
   the safe form for cross-profile transitions. `Cx -> name` in our
   experiments resolved with naming quirks for nested profiles
   (target was `parent_leaf//child` rather than the full
   `top//mid//child`); we abandoned Cx and used Px.
4. **`flags=(unconfined)` profiles do not enforce transition rules.**
   We tried `flags=(unconfined) { /usr/bin/pasta Px -> ..., }` and
   the Px did not fire — pasta stayed in the parent profile. Once we
   moved to enforced profiles (`flags=(attach_disconnected,
   mediate_deleted)` plus explicit allow lists), Px transitions worked.
5. **Profile stacking via `pix /** -> &A//&B` takes the intersection
   of allow-sets** — `audit deny capability,` in B denies caps in
   the stacked label even though A allows them. Confirmed by running
   `mount -t tmpfs none /mnt` inside the agent and getting
   `permission refusée`, and `ip link add … type dummy` getting
   `Operation not permitted`.
6. **The kernel `CapEff` mask is unchanged by AppArmor's `audit deny
   capability,`.** `cat /proc/self/status` from inside the agent
   showed `CapEff: 1ffffffffff` (all caps set), but actual cap-using
   syscalls failed. AppArmor denies at the LSM `cap_capable` hook;
   the kernel mask is just metadata.
7. **`aa-exec -p NAME -- cmd` calls `aa_change_onexec(NAME)` and
   `execve(cmd)`.** From an unprivileged unconfined shell, this
   attempts to land `cmd` in `NAME`'s profile.
8. **`apparmor_restrict_unprivileged_unconfined=1` doesn't outright
   EPERM the change_onexec — it converts it to stacking.** Audit log
   shows `change_profile unprivileged unconfined converted to
   stacking`. The resulting label is `unconfined//&NAME`, and that
   stacked label retains "unconfined-ish" properties that effectively
   prevent a useful userns setup (uid_map write fails after creation).
9. **Cap-stacking via the `pix` rule applies regardless of how bwrap
   got into its profile.** Even at sysctl=0 (where the aa-exec bypass
   succeeds), the bypass-er's bwrap children still landed in
   `redoubtful_bwrap//&redoubtful_unpriv` — the stacked deny is
   independent of the change_profile gate. Defense in depth holds.
10. **Ubuntu's per-binary userns-granting pattern
    (`flags=(unconfined) { userns, }`) is shipped for many specific
    tools — firefox, chrome, vscode, buildah, crun, flatpak — but
    deliberately not for `/usr/bin/bwrap`** because bwrap is a
    generic launcher.

## Hypotheses we observed but didn't fully verify

These were consistent with the audit logs and observed behavior but
we didn't trace the kernel source or test exhaustively.

### What `flags=(unconfined)` short-circuits

The Flatpak/Firefox/Chrome pattern reads
`profile NAME /path flags=(unconfined) { userns, }` — and the
question is why the explicit `userns,` is necessary at all when
"unconfined" already sounds like "everything is allowed."

The model that fits our observations: `flags=(unconfined)` is
"label-only, skip the *old* AppArmor mediation hooks." The
traditional LSM hooks for file access, capability, network, ptrace,
signal, mount, pivot_root, dbus, etc., get short-circuited for
processes attached to the profile. The profile exists primarily so
audit/`ps -eZ` can surface a name (`firefox (unconfined)` instead
of bare `unconfined`) and so other things have a hook to ask
"does this profile allow X?"

Transition rules (`Px`/`Cx`) are also short-circuited under
`flags=(unconfined)` — that's why our Tier 1 chain experiment
broke when we tried to use unconfined on the parent profile and
only worked once we moved to enforced profiles. **Confirmed
empirically.**

The `userns,` mediation, by contrast, is *new* — added in 2024
specifically to plug the userns kernel-attack-surface hole. It's
keyed off the `apparmor_restrict_unprivileged_userns=1` sysctl, and
it asks every profile (confined or unconfined) "do you have an
explicit `userns,` allow rule?" The check fires regardless of the
unconfined flag, because if it didn't, every default-attached
unconfined process would silently keep userns access and the
restriction would do nothing. **Consistent with empirical behavior
and Canonical's design intent in the
[23.10 spec][ubuntu-23.10]; not confirmed by reading the parser
source.**

What this implies (but isn't fully verified):

- The set of rules short-circuited by `flags=(unconfined)` is
  approximately "the old AppArmor model" — file/cap/network/exec/
  transition rules. Newer mediation classes that opted in via
  separate kernel sysctls (currently just `userns` that we're
  certain of, possibly others) stay enforced.
- We don't know exactly where AppArmor decides to elide rules for
  unconfined profiles. Likely candidates are the parser
  (`parser/parser_main.c` or `parser_policy.c`) compiling the
  policy DFA differently, or the kernel-side label evaluator
  treating the unconfined flag as an early-out for most rule
  classes.
- We also haven't tested whether other modern mediation classes
  (e.g., `mount` rules, `dbus` rules, signal/ptrace rules) are
  enforced or short-circuited under `flags=(unconfined)`. Worth
  knowing if we ever try to mix unconfined with other newer rules.

This matters for any Tier 1 trimming work: if we knew exactly which
rule classes are enforced under unconfined profiles, we could
potentially simplify our chain by combining unconfined + a small
explicit allow list per profile rather than enumerating every old-
model permission class.

### Other open questions

- **Why uid_map write fails specifically after the
  unconfined→stacking conversion at sysctl=1.** The userns is
  created (audit shows `userns_create` succeeded), but the kernel
  then transitions the calling task into `unprivileged_userns`
  (the built-in restricted profile) which denies subsequent
  cap-requiring ops including `uid_map`. We assume this transition
  applies to stacked-with-unconfined labels because of the
  unconfined component, but didn't trace the exact decision in
  `aa_userns_create`.
- **Why mount inside the bypass-er's namespace at sysctl=0 fails
  with `seul le superutilisateur peut utiliser mount`** rather than
  AppArmor's `permission refusée`. The legitimate-chain mount
  produces the AppArmor error; the bypass produces the userspace
  getuid()==0 check error. We hypothesize that bwrap's uid mapping
  setup behaves differently when bwrap runs directly under
  `redoubtful_bwrap` (via the bypass) vs. when it inherits an
  already-established userns from pasta — but we didn't trace
  bwrap's setup logic to confirm.
- **Whether the agent can do anything dangerous after `unshare -U`
  inside the sandbox.** Tier 1's `redoubtful_unpriv` allows userns
  recursively (so legitimate agent tooling works) and recursively
  pix-stacks itself onto further children. We tested that `unshare
  -U /bin/echo` works (echo prints) but did not test cap-requiring
  syscalls *inside* a nested userns the agent created. The expected
  behavior is that AppArmor's recursive stack keeps the cap-deny
  applied to all descendants, but we didn't verify with a probe.

## Don't: setuid bwrap

The legacy Debian setuid path (`README.Debian.gz`) disables some bwrap
features and has had privilege-escalation CVEs (CVE-2020-5291,
CVE-2016-8659). Upstream does not recommend it.

## Implications for `redoubtful check`

The `redoubtful check` subcommand should:

1. Read `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`. If
   `0` or absent, the userns restriction isn't in effect — fine.
2. If `1`, attempt a probe `bwrap`/`pasta` invocation. If it
   succeeds, a profile is in place — fine.
3. If the probe fails, print the three-tier remediation. Default
   recommendation: Tier 1 with the path-substituted profile emitted
   inline so the user can `sudo tee /etc/apparmor.d/redoubtful`
   directly. Tier 2 and Tier 3 mentioned as alternatives with their
   trade-offs spelled out.

`redoubtful run` runs the same probe before launching the sandbox so
that a misconfigured host gets the friendly diagnostic instead of
bwrap's `setting up uid map: Permission denied`.

## Sources

### The restriction itself

- [containers/bubblewrap#632 — bwrap broke on Ubuntu 24.04](https://github.com/containers/bubblewrap/issues/632)
- [Ubuntu Launchpad #2046477 — enable userns restrictions by default](https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/2046477)
- [Ubuntu Launchpad #2046844 — userns restrictions cause bubblewrap regressions (Johansen on per-binary requirement)](https://bugs.launchpad.net/ubuntu/+source/bubblewrap/+bug/2046844)
- [Ubuntu Discourse: Understanding AppArmor User Namespace Restriction](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007)
- [Ubuntu 23.10 spec — unprivileged userns restrictions via AppArmor](https://discourse.ubuntu.com/t/spec-unprivileged-user-namespace-restrictions-via-apparmor-in-ubuntu-23-10/37626)

### Threat model

- [Edera — Linux User Namespaces: 262% More Kernel Attack Surface](https://edera.dev/stories/user-namespaces-are-not-a-security-boundary)
- [CVE-2024-1086 PoC (nftables LPE requiring userns)](https://github.com/Notselwyn/CVE-2024-1086)
- [Russell Coker — Ubuntu 24.04 and Bubblewrap](https://etbe.coker.com.au/2024/04/24/ubuntu-24-04-bubblewrap/)

### The upstream `bwrap-userns-restrict` profile

- [Profile source (apparmor/profiles/extras/bwrap-userns-restrict)](https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor/profiles/extras/bwrap-userns-restrict)
- [AppArmor MR !1205 — adding the profile](https://gitlab.com/apparmor/apparmor/-/merge_requests/1205)
- [AppArmor 4.0.2 release notes — Flatpak interaction not addressed](https://apparmor.net/news/release-4.0.2/)
- [Launchpad #2072811 — Ubuntu rolled the profile back over Flatpak breakage][lp-2072811]
- [flatpak/flatpak#5462 — Flatpak apps no longer run on Ubuntu](https://github.com/flatpak/flatpak/issues/5462)

[lp-2072811]: https://bugs.launchpad.net/bugs/2072811

### change_profile / aa-exec / unconfined sysctl

- [DEVCORE — The Journey of Bypassing Ubuntu's Unprivileged Namespace Restriction](https://u1f383.github.io/linux/2025/06/26/the-journey-of-bypassing-ubuntus-unprivileged-namespace-restriction.html)
- [Qualys — Three bypasses of Ubuntu's unprivileged user namespace restrictions](https://www.qualys.com/2025/three-bypasses-of-Ubuntu-unprivileged-user-namespace-restrictions.txt)
- [aa_change_profile(2) man page](https://manpages.ubuntu.com/manpages/bionic/man2/aa_change_profile.2.html)
- [apparmor.d(5)](https://manpages.debian.org/unstable/apparmor/apparmor.d.5.en.html)

### Other background

- [AppArmor](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/container-security/protections/apparmor.html): More background on "(unconfied)".

### Reference profiles on Ubuntu

- `/etc/apparmor.d/firefox`, `/etc/apparmor.d/chrome`,
  `/etc/apparmor.d/code`, `/etc/apparmor.d/flatpak`,
  `/etc/apparmor.d/buildah`, `/etc/apparmor.d/crun` — all use the
  same `flags=(unconfined) { userns, }` pattern attached to a
  specific binary path.

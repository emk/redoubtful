# AppArmor user-namespace restriction on Ubuntu 24.04+

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

## Why no default bwrap profile

Ubuntu does **not** ship an AppArmor profile that whitelists `bwrap`,
and Canonical has explicitly said one won't be added: bwrap is a
generic launcher and whitelisting `/usr/bin/bwrap` by name would defeat
the entire restriction (any unprivileged process can just shell out to
bwrap to get userns). The name `bwrap-userns-restrict` you may see in
older docs is a red herring — that was a profile shipped briefly for
Flatpak's *internal* bwrap, not the standalone binary.

## The two options for a developer workstation

Either is fine for a single-user dev box. Pick once.

### Option A — sysctl escape hatch (system-wide)

```
echo 'kernel.apparmor_restrict_unprivileged_userns=0' \
  | sudo tee /etc/sysctl.d/60-apparmor-namespace.conf
sudo sysctl --system
```

Or non-persistently:

```
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

Lifts the restriction for *every* unprivileged process on the box.
Acceptable on a single-user developer machine; not great on shared or
multi-user systems.

### Option B — per-binary AppArmor profile (more surgical)

Create `/etc/apparmor.d/bwrap`:

```
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
```

Then reload AppArmor:

```
sudo systemctl reload apparmor
```

Only `/usr/bin/bwrap` (and processes it spawns) gain `userns`;
everything else on the system stays under the default-deny landing
profile. Caveat: anything you run *through* bwrap inherits the
unrestricted view, so this is essentially equivalent to "trust bwrap
users."

### Don't: setuid bwrap

The legacy Debian setuid path (`README.Debian.gz`) disables some bwrap
features and has had privilege-escalation CVEs (CVE-2020-5291,
CVE-2016-8659). Upstream does not recommend it.

## Implications for `redoubtful check`

`specs/ARCHITECTURE.md` already calls this out as something `redoubtful
check` should detect and explain. When that subcommand lands it
should:

- Read `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`. If
  `0`, fine. If absent, fine (kernel/distro doesn't have the knob).
- If `1`, attempt a probe `bwrap`/`unshare` invocation. If it
  succeeds, a profile is in place — fine. If it fails, print the
  two-option fix above with both commands.

## Sources

- [containers/bubblewrap#632 — bwrap broke on Ubuntu 24.04](https://github.com/containers/bubblewrap/issues/632)
- [Ubuntu Launchpad #2046477 — enable userns restrictions by default](https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/2046477)
- [Ubuntu Launchpad #2046844 — userns restrictions cause bubblewrap regressions](https://bugs.launchpad.net/ubuntu/+source/bubblewrap/+bug/2046844)
- [Ubuntu Discourse: Understanding AppArmor User Namespace Restriction](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007)
- [Russell Coker — Ubuntu 24.04 and Bubblewrap](https://etbe.coker.com.au/2024/04/24/ubuntu-24-04-bubblewrap/) (source of the per-binary profile snippet)
- [chainguard-dev/melange#1508](https://github.com/chainguard-dev/melange/issues/1508)

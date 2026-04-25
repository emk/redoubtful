# Tier 2 — short profile for redoubtful, Flatpak-style.
#
# Same shape Ubuntu ships for /etc/apparmor.d/{firefox,chrome,vscode,
# flatpak,buildah,crun,...}: a labeling-only profile attached to a
# specific binary path. `flags=(unconfined)` means AppArmor doesn't
# enforce most rules — the profile exists only to grant `userns,`
# to the named binary so the kernel sysctl
# `apparmor_restrict_unprivileged_userns=1` allows the binary to
# create a user namespace.
#
# Trade-off vs the chained Tier 1 profile (apparmor-test-redoubtful.profile):
#   + 5 lines instead of ~80
#   + matches the well-known Ubuntu pattern, easy to audit
#   - the agent inside the sandbox inherits the unconfined label
#     and has full namespaced capabilities. The kernel attack
#     surface that motivated the userns restriction is reachable
#     from inside our sandbox. Same security model as Firefox.
#
# Launch with:
#   target/debug/examples/wrapper pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / -- /bin/echo hi

abi <abi/4.0>,
include <tunables/global>

profile redoubtful /home/emk/w/src/redoubtful/target/debug/examples/wrapper flags=(unconfined) {
  userns,
  include if exists <local/redoubtful>
}

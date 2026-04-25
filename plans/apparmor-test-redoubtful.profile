# Tier-1 test profile for redoubtful — Px chain + cap-stacking.
#
# `flags=(unconfined)` profiles are labeling-only — they don't
# enforce rules, including transitions. So we can't trim to the
# 5-line shape; we need enforced profiles with explicit allow
# lists. This mirrors the shape upstream `bwrap-userns-restrict`
# uses.
#
#   redoubtful           attached to wrapper. Px -> redoubtful_pasta
#                        on /usr/bin/pasta.
#   redoubtful_pasta     pasta runs here. ix on AVX2 self-dispatch.
#                        Px -> redoubtful_bwrap on /usr/bin/bwrap.
#   redoubtful_bwrap     bwrap runs here. pix-stacks redoubtful_unpriv
#                        onto bwrap's children.
#   redoubtful_unpriv    stacking partner that denies capability.
#                        Recursive pix so anything the agent spawns
#                        also lands here.
#
# Pair with kernel.apparmor_restrict_unprivileged_unconfined=1 to
# block aa-exec entry from arbitrary unprivileged shells.
#
# Launch with:
#   target/debug/examples/wrapper pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / -- /bin/echo hi

abi <abi/4.0>,
include <tunables/global>

profile redoubtful /home/emk/w/src/redoubtful/target/debug/examples/wrapper flags=(attach_disconnected,mediate_deleted) {
  allow capability,
  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow ptrace,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,

  /usr/bin/pasta Px -> redoubtful_pasta,
}

profile redoubtful_pasta flags=(attach_disconnected,mediate_deleted) {
  allow capability,
  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow ptrace,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,

  /usr/bin/pasta{,.avx2} ix,
  /usr/bin/bwrap Px -> redoubtful_bwrap,
}

profile redoubtful_bwrap flags=(attach_disconnected,mediate_deleted) {
  allow capability,
  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow ptrace,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,

  allow pix /** -> &redoubtful_bwrap//&redoubtful_unpriv,
}

profile redoubtful_unpriv flags=(attach_disconnected,mediate_deleted) {
  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow ptrace,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,

  allow pix /** -> &redoubtful_unpriv,
  audit deny capability,
}

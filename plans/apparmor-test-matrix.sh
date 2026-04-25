#!/usr/bin/env bash
# Test matrix for the chained AppArmor profile in
# `plans/apparmor-test-redoubtful.profile`.
#
# Designed to be run twice:
#   1. With kernel.apparmor_restrict_unprivileged_unconfined=1 — the
#      "Tier 1 surgical" configuration. Tests 8/9/10 (aa-exec
#      bypasses) should fail.
#   2. With kernel.apparmor_restrict_unprivileged_unconfined=0 —
#      tests 8/9/10 should succeed for echo (the bypass works), but
#      cap-stacking in the bwrap-children pix rule still applies, so
#      mount/ip-link inside still get denied.
#
# Toggle with:
#   sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=1
#   sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
#
# Prereqs: profile loaded via
#   sudo cp plans/apparmor-test-redoubtful.profile /etc/apparmor.d/redoubtful-test
#   sudo apparmor_parser -r /etc/apparmor.d/redoubtful-test
# and the wrapper binary built via `cargo build --example wrapper`.
#
# Don't `set -e` — several tests are expected to fail; we want to see
# every result.

WRAPPER="${WRAPPER:-$(dirname "$0")/../target/debug/examples/wrapper}"
WRAPPER="$(realpath "$WRAPPER")"

if [[ ! -x "$WRAPPER" ]]; then
  echo "wrapper binary not found at $WRAPPER" >&2
  echo "build it with: cargo build --example wrapper" >&2
  exit 2
fi

echo "=== sysctl state ==="
echo "userns=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns) unconfined=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined)"
echo "wrapper=$WRAPPER"
echo

echo "=== Test 1: baseline, no profile (should FAIL — kernel sysctl deny) ==="
pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / -- /bin/echo hi 2>&1
echo "exit=$?"
echo

echo "=== Test 2: wrapper -> pasta -> bwrap -> echo (should SUCCEED) ==="
"$WRAPPER" pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / -- /bin/echo hi 2>&1
echo "exit=$?"
echo

echo "=== Test 3: profile context inside agent (expect: redoubtful_bwrap//&redoubtful_unpriv) ==="
"$WRAPPER" pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / -- /bin/cat /proc/self/attr/current 2>&1
echo "exit=$?"
echo

echo "=== Test 4: agent's CapEff/CapBnd (kernel mask — unchanged by AppArmor; expect 1ffffffffff) ==="
"$WRAPPER" pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / -- /usr/bin/grep -E 'CapEff|CapBnd' /proc/self/status 2>&1
echo "exit=$?"
echo

echo "=== Test 5 (KEY): agent calls mount (needs CAP_SYS_ADMIN) — should be DENIED by stacking ==="
"$WRAPPER" pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / --tmpfs /mnt -- /bin/mount -t tmpfs none /mnt 2>&1
echo "exit=$?"
echo

echo "=== Test 6: agent calls ip link add (needs CAP_NET_ADMIN) — should be DENIED by stacking ==="
"$WRAPPER" pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / -- /usr/sbin/ip link add dev tdummy type dummy 2>&1
echo "exit=$?"
echo

echo "=== Test 7: agent calls unshare -U (userns allowed by redoubtful_unpriv; should SUCCEED) ==="
"$WRAPPER" pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / -- /usr/bin/unshare -U /bin/echo nested-userns-worked 2>&1
echo "exit=$?"
echo

echo "=== Test 8 (BYPASS): aa-exec into redoubtful_bwrap ==="
echo "    With unconfined=1: should fail (bwrap can't write uid_map)."
echo "    With unconfined=0: should print 'bypass-bwrap' (bypass succeeds for the echo)."
aa-exec -p redoubtful_bwrap -- bwrap --unshare-all --share-net --ro-bind / / -- /bin/echo bypass-bwrap 2>&1
echo "exit=$?"
echo

echo "=== Test 9 (BYPASS): aa-exec into redoubtful directly ==="
echo "    With unconfined=1: should fail (chain doesn't transition into pasta)."
echo "    With unconfined=0: pasta runs in 'redoubtful' but lacks exec rule for /usr/bin/pasta.avx2."
aa-exec -p redoubtful -- pasta --quiet -- bwrap --unshare-all --share-net --ro-bind / / -- /bin/echo bypass-redoubtful 2>&1
echo "exit=$?"
echo

echo "=== Test 10 (BYPASS): aa-exec into redoubtful_pasta ==="
echo "    With unconfined=1: should fail."
echo "    With unconfined=0: bwrap runs in redoubtful_pasta which lacks general exec rules."
aa-exec -p redoubtful_pasta -- bwrap --unshare-all --share-net --ro-bind / / -- /bin/echo bypass-pasta 2>&1
echo "exit=$?"
echo

echo "=== Bonus: bypass-er's profile context (does pix-stacking still apply?) ==="
aa-exec -p redoubtful_bwrap -- bwrap --unshare-all --share-net --ro-bind / / -- /bin/cat /proc/self/attr/current 2>&1
echo "exit=$?"
echo

echo "=== Bonus: bypass-er can mount inside the namespace? ==="
echo "    With unconfined=0, expect 'seul le superutilisateur'/superuser-only because"
echo "    bypass-er's userns uid_map ends up unconfigured. AppArmor cap-deny would also"
echo "    block this even if uid_map were set. See APPARMOR_USERNS.md hypothesis section."
aa-exec -p redoubtful_bwrap -- bwrap --unshare-all --share-net --ro-bind / / --tmpfs /mnt -- /bin/mount -t tmpfs none /mnt 2>&1
echo "exit=$?"
echo

echo "=== Recent AppArmor denials in dmesg (last 2 minutes) ==="
journalctl -k --since "2 minutes ago" --no-pager 2>&1 | grep -i 'apparmor.*\(DENIED\|AUDIT\)' | tail -20

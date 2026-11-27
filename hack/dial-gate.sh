#!/bin/sh
# Pinned dialing gate (PLAN.md milestone row 7-8, issues #20 and #145; ARCHITECTURE.md §6.1, §6.2 step 3, §6.3,
# Appendix B) on the local arm64 QEMU VM.
#   hack/dial-gate.sh [uefi|bios] [install] [release] [checks]   default: install checks
# uefi (default) is the arm64 VM, bios the amd64 one (hack/gate.sh's boot modes); only install uses it.
# install  hack/gate.sh none: make release, an unattended install and firstboot, so rootd and its resolver reach the
#          box by the real path (install.sh). Then boots the VM.
# release  installs this checkout as a new release version on the running VM with that release's own install.sh (for
#          iterating on a box that `install` made).
# checks   builds hack/dial-gate/probe (a broker stand-in on internal/dial) and hack/gate-dns for the guest, copies
#          them and hack/dial-gate/checks.sh to /run/dg, then runs checks.sh setup, main and cleanup. Covers, through
#          the release's rootd and resolved: an allowlisted name is refused when it answers with the box's own address
#          (on the default interface, on another one, its SLAAC IPv6, one still in DAD), a LAN host's global IPv6 (on
#          link, or under a prefix the router announces off-link), 192.168.x, NAT64-wrapped 192.168.x, the box's own or
#          an on-link IPv4 inside a NAT64 address, 240.0.0.1, when only /etc/hosts names it, and when a systemd 259
#          resolve hook answers it; rootd reads the box's addresses at each resolution. A broker uid under the broker
#          units' sandbox dials only rootd's addresses, in order, within one 10 s budget, with SNI, the certificate check
#          and Host on the name; never the /etc/hosts answer, no lookup (the keys drop counters stay still), no redirect.
# The test network is inside the VM (a veth LAN and a netns that holds the upstreams), so the host needs no internet
# for the checks. Checks print PASS/FAIL to .vm/dial-gate.txt; exit 1 on any FAIL. AGENTBOX_VM_ID and AGENTBOX_ISO_DIR
# pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
mkdir -p "$VM"
BOOT=uefi; case ${1:-} in uefi|bios) BOOT=$1; shift ;; esac
[ $# -gt 0 ] || set -- install checks
OUT="$VM/dial-gate.txt" LOG="$VM/dial-gate.log"
die() { echo "dial-gate.sh: $*" >&2; exit 1; }
vssh() { hack/vm.sh ssh "$@"; }
vmroot() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s'; }
running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }
bootid() { vssh cat /proc/sys/kernel/random/boot_id 2>/dev/null || :; }
wait_boot() { end=$(( $(date +%s) + $2 ))
  while :; do b=$(bootid); [ -n "$b" ] && [ "$b" != "$1" ] && return 0; [ "$(date +%s)" -lt $end ] || return 1; sleep 5; done; }
up() { running || { hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"
  echo '[ "$(timeout 600 systemctl is-system-running --wait)" = running ] || systemctl --failed --no-pager' | vmroot >>"$LOG" 2>&1 || :; }
# tovm FILE DST: copy a host file into the VM as root
tovm() { { echo x; cat "$1"; } | vssh "sudo -S -p '' sh -c 'mkdir -p /run/dg && cat > $2 && chmod 0755 $2'"; }
phase() { echo "sh /run/dg/checks.sh $1" | vmroot | tee -a "$OUT"; }

: > "$OUT"
for stage; do
  case $stage in
  install)
    hack/gate.sh none "$BOOT"
    up
    ;;
  release)
    running || up
    V=0.0.2-dev$(date +%s)
    R=$(mktemp -d "$VM/rel.XXXXXX")
    make -s release VERSION="$V" MINISIGN_KEY="$VM/keys/minisign.key" DIST="$R" >/dev/null
    vssh 'rm -rf /tmp/rel && mkdir /tmp/rel && tar -xz -C /tmp/rel' < "$R/agentbox-$V.tgz"
    # install.sh only enables: start the sockets here (a boot would). systemd refuses to start a new socket while its
    # service runs, so rootd stops first.
    echo 'sh /tmp/rel/install.sh --from-firstboot && systemctl stop agentbox-rootd.service && systemctl start agentbox-rootd-admin.socket agentbox-rootd-gate.socket agentbox-audit-seal.socket agentbox-rootd-resolve-proxy.socket agentbox-rootd-resolve-keys.socket agentbox-rootd-resolve-git.socket agentbox-rootd.service' | vmroot >>"$LOG" 2>&1 || die "install.sh $V failed; see $LOG"
    rm -rf "$R"
    echo "installed release $V"
    ;;
  checks)
    running || up
    case $(cat "$VM/arch") in arm64) GA=arm64 ;; amd64) GA=amd64 ;; esac
    for p in gate-dns dial-gate/probe; do CGO_ENABLED=0 GOOS=linux GOARCH=$GA go build -o "$VM/${p##*/}" "./hack/$p"; done
    tovm hack/dial-gate/checks.sh /run/dg/checks.sh
    tovm "$VM/gate-dns" /run/dg/gate-dns
    tovm "$VM/probe" /run/dg/probe
    rm -f "$VM/gate-dns" "$VM/probe"
    CHECKED=1
    phase setup
    phase main
    echo 'cat /run/dg/check.log; cat /run/dg/output-chain.txt; journalctl -b -u agentbox-rootd.service -u dg-dns.service -u dg-up.service -o short-precise --no-pager' | vmroot > "$VM/dial-gate-journal.txt" 2>&1 || :
    phase cleanup
    ;;
  *) die "unknown stage $stage (install, release, checks)" ;;
  esac
done
[ -n "${CHECKED:-}" ] || exit 0
! grep -q '^FAIL' "$OUT" || die "dial gate failed; see $OUT, $VM/dial-gate-journal.txt and $LOG"
[ "$(grep -c '^fails=0$' "$OUT")" -eq 3 ] || die "dial gate did not finish its three phases; see $OUT"
echo "dial gate: all checks passed"

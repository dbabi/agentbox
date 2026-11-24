#!/bin/sh
# rootd gates (PLAN.md milestone row 3: rootd skeleton, resolver, log sealing; ARCHITECTURE.md §2, §2.1, §6.1, §6.3, §9,
# Appendix B) on the local arm64 QEMU VM.
#   hack/rootd-gate.sh [uefi|bios] [install] [release] [checks]   default: install checks
# uefi (default) is the arm64 VM, bios the amd64 one (hack/gate.sh's boot modes); only install uses it.
# install  hack/gate.sh none: make release, an unattended install and firstboot, so rootd's units, sysusers.d and
#          tmpfiles.d files reach the box by the real path (install.sh). Then boots the VM.
# release  installs this checkout as a new release version on the running VM with that release's own install.sh (for
#          iterating on a box that `install` made).
# checks   copies the fixtures in hack/rootd-gate/ (and gate-dns, built for the guest) to /run/rg, then runs
#          checks.sh setup and main, reboots, runs after-reboot and cleanup. Covers: the units and their sandbox, the
#          sockets' owners and SO_PEERCRED checks, SCM_RIGHTS refusal, the approve-in-admin start refusal; the resolver
#          refusing private, special-purpose, NAT64-wrapped, own, on-link and off-interface answers; a broker reaching
#          only what rootd resolved; READY=1 after the sets match rootd.db, timer and notify refills, a reboot refill; a
#          keys-like flow surviving element expiry and cut by removing its entry; audit segment creation and sealing.
# FLOW=host:port (default example.com:80) is the public HTTP server the flow check holds a connection to; the VM reaches
# it through slirp, so the host needs internet. The firewall is the release's own agentbox-firewall.service. Checks
# print PASS/FAIL to .vm/rootd-gate.txt; exit 1 on any FAIL. AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
mkdir -p "$VM"
BOOT=uefi; case ${1:-} in uefi|bios) BOOT=$1; shift ;; esac
[ $# -gt 0 ] || set -- install checks
OUT="$VM/rootd-gate.txt" LOG="$VM/rootd-gate.log"
FLOW=${FLOW:-example.com:80}
die() { echo "rootd-gate.sh: $*" >&2; exit 1; }
vssh() { hack/vm.sh ssh "$@"; }
vmroot() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s'; }
running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }
bootid() { vssh cat /proc/sys/kernel/random/boot_id 2>/dev/null || :; }
wait_boot() { end=$(( $(date +%s) + $2 ))
  while :; do b=$(bootid); [ -n "$b" ] && [ "$b" != "$1" ] && return 0; [ "$(date +%s)" -lt $end ] || return 1; sleep 5; done; }
up() { running || { hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"
  echo '[ "$(timeout 600 systemctl is-system-running --wait)" = running ] || systemctl --failed --no-pager' | vmroot >>"$LOG" 2>&1 || :; }
# tovm FILE DST: copy a host file into the VM as root
tovm() { { echo x; cat "$1"; } | vssh "sudo -S -p '' sh -c 'mkdir -p /run/rg && cat > $2 && chmod 0755 $2'"; }
phase() { { printf 'FLOW=%s\n' "$FLOW"; echo "export FLOW"; echo "sh /run/rg/checks.sh $1"; } | vmroot | tee -a "$OUT"; }

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
    CGO_ENABLED=0 GOOS=linux GOARCH=$GA go build -o "$VM/gate-dns" ./hack/gate-dns
    for f in rg.py checks.sh; do tovm "hack/rootd-gate/$f" /run/rg/$f; done
    tovm "$VM/gate-dns" /run/rg/gate-dns
    CHECKED=1
    rm -f "$VM/gate-dns"
    phase setup
    phase main
    echo 'cat /run/rg/flow-kept.log; echo; cat /run/rg/check.log' | vmroot > "$VM/rootd-gate-flow.txt" 2>&1 || :
    old=$(bootid)
    echo 'systemctl reboot' | vmroot >/dev/null 2>&1 || :
    wait_boot "$old" 900 || die "no SSH after the reboot"
    echo '[ "$(timeout 600 systemctl is-system-running --wait)" = running ] || :' | vmroot >>"$LOG" 2>&1 || :
    for f in rg.py checks.sh; do tovm "hack/rootd-gate/$f" /run/rg/$f; done
    phase after-reboot
    phase cleanup
    echo 'journalctl -b -1 -u agentbox-rootd.service -o short-precise --no-pager; journalctl -b -u agentbox-rootd.service -o short-precise --no-pager' | vmroot > "$VM/rootd-gate-journal.txt" 2>&1 || :
    ;;
  *) die "unknown stage $stage (install, release, checks)" ;;
  esac
done
[ -n "${CHECKED:-}" ] || exit 0
! grep -q '^FAIL' "$OUT" || die "rootd gate failed; see $OUT and $LOG"
[ "$(grep -c '^fails=0$' "$OUT")" -eq 4 ] || die "rootd gate did not finish its four phases; see $OUT"
echo "rootd gate: all checks passed"

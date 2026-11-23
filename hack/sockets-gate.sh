#!/bin/sh
# Week 4 gate for the socket inventory as code (PLAN.md row 4, ARCHITECTURE.md §2.1, A-arch-runtime-network-07) on
# the local arm64 QEMU VM, none mode.
#   hack/sockets-gate.sh [uefi|bios] [install] [check]   default: both, in order
# uefi (default) is the arm64 VM, bios the amd64 one (hack/gate.sh's boot modes); only install uses it.
# install  hack/gate.sh none: the unattended install and the release pipeline, so the generated tmpfiles.d and
#          .socket units reach the box by the real path (install.sh).
# check    the installed box matches internal/sockets exactly (`agentbox sockets check`), before and after a reboot;
#          the installed tmpfiles.d is the generated one; a socket with a wrong mode or owner, a dir with a wrong
#          mode, a per-task dir without setgid and a stray file are each reported, and the box matches again once
#          they are undone.
# PASS/FAIL lines go to .vm/sockets-gate.txt, command output to .vm/sockets-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
BOOT=uefi; case ${1:-} in uefi|bios) BOOT=$1; shift ;; esac
G=none; [ "$BOOT" = uefi ] || G=none-bios # gate.sh writes .vm/gate-$G.txt
[ $# -gt 0 ] || set -- install check
OUT="$VM/sockets-gate.txt" LOG="$VM/sockets-gate.log"
mkdir -p "$VM"
: > "$OUT"
! command -v caffeinate >/dev/null || { caffeinate -i -w $$ & }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT"; }
die() { log "ABORT $*"; exit 1; }
root() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s'; } # stdin: a script run as root on the VM
bootid() { hack/vm.sh ssh cat /proc/sys/kernel/random/boot_id 2>/dev/null || :; }
running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }
wait_boot() {
  end=$(( $(date +%s) + $2 ))
  while :; do b=$(bootid); [ -n "$b" ] && [ "$b" != "$1" ] && return 0; [ "$(date +%s)" -lt $end ] || return 1; sleep 5; done
}
up() { running || { hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"; }
reboot_vm() { old=$(bootid); echo 'systemctl reboot' | root >/dev/null 2>&1 || :; wait_boot "$old" 900 || die "no SSH after reboot"; }
guest() {
  root >"$VM/guest.out" 2>>"$LOG" || :
  while IFS= read -r l; do case $l in PASS*|FAIL*) log "$l" ;; *) echo "$l" >>"$LOG" ;; esac; done <"$VM/guest.out"
  grep -q '^fails=' "$VM/guest.out" || log "FAIL the check block on the VM did not finish (see $LOG)"
}
PRELUDE='fails=0
check() { if (eval "$2") >>/tmp/gate-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
A=/var/lib/agentbox/current/bin/agentbox
booted() { [ "$(timeout 600 systemctl is-system-running --wait)" = running ] || systemctl --failed --no-pager; }
# reports WANT: sockets check fails and prints the line WANT
reports() { ! $A sockets check >/tmp/sc.out 2>&1; cat /tmp/sc.out; grep -qxF "$1" /tmp/sc.out; }
'
# the checks that hold after install and after every boot
MATCH='booted
check "agentbox sockets check: the box matches the inventory" "$A sockets check"
check "the installed tmpfiles.d is the generated one" "cmp /usr/lib/tmpfiles.d/agentbox.conf /var/lib/agentbox/current/tmpfiles.d/agentbox.conf && grep -qx \"# Generated from internal/sockets: go test ./internal/sockets -update\" /usr/lib/tmpfiles.d/agentbox.conf"
for d in /run/agentbox /run/agentbox-rootd-approve /run/agentbox-llm /run/agentbox-llm-decide /run/agentbox-apps /run/agentbox-gate/t /run/agentbox-proxy/t /run/agentbox-keys/t /run/agentbox-git/t /run/agentbox-witness/t; do
  check "tmpfiles made $d" "[ -d $d ]"; done
check "the live sockets are there and were checked: rootd, auditd, ntfy" "for s in /run/agentbox-rootd/rootd-admin.sock /run/agentbox-rootd/audit-seal.sock /run/agentbox-rootd/resolve-git.sock /run/agentbox-audit/rootd.sock /run/agentbox-audit/git.sock /run/ntfy/ntfy.sock; do [ -S \$s ] || exit 1; done"
'

for s; do case $s in
install)
  hack/gate.sh none "$BOOT" >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-$G.txt"
  log "PASS install: hack/gate.sh none (install, release pipeline, firstboot, reconcile, no failed units)" ;;
check)
  up
  { echo "$PRELUDE"; echo "$MATCH"; cat <<'EOF'; } | guest
S=/run/agentbox-audit/rootd.sock
chmod 0666 $S
check "a socket with mode 0666 is reported" 'reports "$S: mode 0666, want 0660"'
chmod 0660 $S
chown nobody $S
check "a socket owned by nobody is reported" 'reports "$S: owner nobody:root, want agentbox-audit:root"'
chown agentbox-audit $S
chgrp agentbox /run/agentbox-rootd/resolve-git.sock
check "a socket with the wrong group is reported" 'reports "/run/agentbox-rootd/resolve-git.sock: owner root:agentbox, want root:agentbox-git"'
chgrp agentbox-git /run/agentbox-rootd/resolve-git.sock
chmod 0755 /run/agentbox-witness/t
check "a runtime dir with mode 0755 is reported" 'reports "/run/agentbox-witness/t: mode 0755, want 0711"'
check "  ... and systemd-tmpfiles --create puts it back" 'systemd-tmpfiles --create /usr/lib/tmpfiles.d/agentbox.conf && [ "$(stat -c %a /run/agentbox-witness/t)" = 711 ]'
touch /run/agentbox-rootd/stray
check "a file the inventory doesn't name is reported" 'reports "/run/agentbox-rootd/stray: not in the inventory"'
rm /run/agentbox-rootd/stray
# a per-task broker dir as rootd makes it (§2.1): agentbox-proxy:ag-<agent> 2750
groupadd -r ag-gatetest
T=/run/agentbox-proxy/t/T1; mkdir $T && chown agentbox-proxy:ag-gatetest $T && chmod 2750 $T
check "a per-task dir agentbox-proxy:ag-<agent> 2750 matches the template" '$A sockets check'
chmod g-s $T # GNU chmod keeps a dir's setgid bit for a numeric mode
check "  ... without setgid it is reported" 'reports "$T: mode 0750, want 2750"'
chmod 2750 $T; chown root $T
check "  ... owned by root it is reported" 'reports "$T: owner root:ag-gatetest, want agentbox-proxy:ag-<agent>"'
rmdir $T; groupdel ag-gatetest
check "every change undone: the box matches again" '$A sockets check'
check "no failed units" '[ -z "$(systemctl --failed --no-legend --plain)" ]'
echo "fails=$fails"
EOF
  reboot_vm
  { echo "$PRELUDE"; echo "$MATCH"; echo 'echo "fails=$fails"'; } | sed 's/check "/check "after reboot: /' | guest
  ;;
*) die "unknown scenario $s (install or check)" ;;
esac; done
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "sockets gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "sockets gate: all checks passed"

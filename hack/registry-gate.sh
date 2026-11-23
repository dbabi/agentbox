#!/bin/sh
# Week 4 op registry gate (PLAN.md row 4, ARCHITECTURE.md §5.1) on the local QEMU VM, arm64 UEFI, none mode.
#   hack/registry-gate.sh [uefi|bios] [install|checks ...]   default: both, in order
# uefi (default) is the arm64 VM, bios the amd64 one (hack/gate.sh's boot modes); only install uses it.
# install  hack/gate.sh none: the unattended install and the release pipeline, so the release's gen/ files reach the
#          box by the real path (make release, install.sh).
# checks   rootd starts on the shipped gen/ and logs the match. Then, one at a time: one byte appended to
#          gen/cedar.schema, an MCP tool renamed, an op added to the JSON schemas, gen/ops.schema.json deleted, and an extra
#          file in gen/: each time rootd refuses to start (no READY=1, the unit is not active) and the journal names the
#          mismatch. With the files restored, rootd starts again and no unit is failed.
# PASS/FAIL lines go to .vm/registry-gate.txt, command output to .vm/registry-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
BOOT=uefi; case ${1:-} in uefi|bios) BOOT=$1; shift ;; esac
G=none; [ "$BOOT" = uefi ] || G=none-bios # gate.sh writes .vm/gate-$G.txt
[ $# -gt 0 ] || set -- install checks
OUT="$VM/registry-gate.txt" LOG="$VM/registry-gate.log"
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
up() { running || { hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"
  echo '[ "$(timeout 600 systemctl is-system-running --wait)" = running ] || systemctl --failed --no-pager' | root >>"$LOG" 2>&1 || :; }
guest() {
  root >"$VM/guest.out" 2>>"$LOG" || :
  while IFS= read -r l; do case $l in PASS*|FAIL*) log "$l" ;; *) echo "$l" >>"$LOG" ;; esac; done <"$VM/guest.out"
  grep -q '^fails=' "$VM/guest.out" || log "FAIL the check block on the VM did not finish (see $LOG)"
}

for s; do case $s in
install)
  hack/gate.sh none "$BOOT" >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-$G.txt"
  log "PASS install: hack/gate.sh none (install, release pipeline, firstboot, no failed units)" ;;
checks)
  up
  guest <<'EOF'
fails=0
check() { if (eval "$2") >>/tmp/gate-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
G=$(readlink -f /var/lib/agentbox/current)/gen
U=agentbox-rootd.service
B=/run/registry-gate-gen
rm -rf $B && cp -a "$G" $B
# refused MSG: rootd's restart fails, it never gets active, and its journal since the restart has MSG
refused() { t=$(date +%s); sleep 1; ! systemctl restart $U && sleep 3 && ! systemctl is-active -q $U &&
  journalctl -u $U -o cat --since "@$t" | grep -F "op registry mismatch, refusing to start" | grep -qF "$1"; }
restore() { systemctl stop $U; rm -rf "$G" && cp -a $B "$G"; systemctl reset-failed $U; }
check "the release ships gen/ with the six generated files" '[ "$(ls "$G" | tr "\n" " ")" = "ask.v1.json audit-deny.v1.json cedar.schema denial.v1.json mcp-tools.json ops.schema.json " ]'
check "rootd is active on the shipped gen/" 'systemctl is-active -q $U'
check "  ... and logged the match" 'journalctl -b -u $U -o cat | grep -q " op registry matches $G: [0-9]* ops$"'
printf " " >> "$G/cedar.schema"
check "one byte appended to cedar.schema: rootd refuses to start" 'refused "cedar.schema differs from what the registry generates"'
restore
sed -i "s/\"name\": \"ask.quote\"/\"name\": \"ask.quot\"/" "$G/mcp-tools.json"
check "an MCP tool renamed: rootd refuses to start" 'refused "mcp-tools.json does not match the registry one to one: missing ask.quote, extra ask.quot"'
restore
sed -i "s/^  \"args\": {/  \"args\": {\n    \"file.delete\": {},/" "$G/ops.schema.json"
check "an op added to the JSON schemas: rootd refuses to start" 'refused "ops.schema.json does not match the registry one to one: extra file.delete"'
restore
rm "$G/ops.schema.json"
check "ops.schema.json deleted: rootd refuses to start" 'refused "ops.schema.json: no such file"'
restore
: > "$G/extra.json"
check "an extra file in gen/: rootd refuses to start" 'refused "extra.json: not a generated file"'
restore
check "files restored: rootd starts" 'systemctl start $U && systemctl is-active -q $U'
systemctl start multi-user.target # the units that Requires= rootd and stopped with it
check "  ... and gen/ matches the release again" 'diff -r $B "$G"'
check "no failed units" 'sleep 5; [ -z "$(systemctl --failed --no-legend --plain)" ]'
journalctl -b -u $U -o short-precise --no-pager | grep -F "op registry" | tail -20
rm -rf $B
echo "fails=$fails"
EOF
  ;;
*) die "unknown stage $s (install or checks)" ;;
esac; done
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
while running; do sleep 2; done # a gate run next on this disk must not find the box still shutting down
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "registry gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "registry gate: all checks passed"

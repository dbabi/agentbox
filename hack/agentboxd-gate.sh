#!/bin/sh
# Week 4 agentboxd gate (PLAN.md row 4; ARCHITECTURE.md §2, §2.1, §5.2, §5.6, §9) on the local QEMU VM, arm64 UEFI,
# none mode, through the real agentboxd, rootd and auditd.
#   hack/agentboxd-gate.sh [install|checks ...]   default: both, in order
# install  hack/gate.sh none: the unattended install and the release pipeline, so the units and gen/ arrive the real way.
# checks   agentboxd runs with PrivateNetwork and AF_UNIX only. A task registered on svc-gate.sock (as rootd's
#          task.start will) gets its gate socket, usable by that agent's uid only. With rootd's test effect for
#          file.write (AGENTBOX_TEST_GATE_EFFECT): a valid request is INTENT (body hashed), ACK, effect, RESULT, with the
#          task and agent from the socket. A request that fails its schema, spoofs provenance or names an op no agent may
#          call gets a typed agentbox-denial/v1 and no INTENT and no effect. With AGENTBOX_TEST_AUDIT_RAW=1 rootd sends
#          the body unhashed: auditd NACKs the INTENT and no effect runs. An INTENT carrying a secret (secret.set's
#          drop-class value) or an unhashed gh.* body is NACKed too, and no RESULT can follow it. No refused value is
#          in the audit dir. Revoke removes the socket. The chain verifies.
# PASS/FAIL lines go to .vm/agentboxd-gate.txt, command output to .vm/agentboxd-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/agentboxd-gate.txt" LOG="$VM/agentboxd-gate.log"
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
  hack/gate.sh none >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-none.txt"
  log "PASS install: hack/gate.sh none (install, release pipeline, firstboot, no failed units)" ;;
checks)
  up
  guest <<'EOF'
fails=0
check() { if (eval "$2") >>/tmp/gate-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
B=/var/lib/agentbox/current/bin/agentbox
A=/var/lib/agentbox/audit
U=agentboxd.service
E=/var/lib/agentbox/gate-effect
D=/run/systemd/system/agentbox-rootd.service.d
S=/run/agentbox-gate/t/G1/gate.sock
intents() { cat $A/seg-*.jsonl | grep -c '"type":"INTENT"' || :; }
effects() { ls $E | wc -l; }
call() { runuser -u ag-gt -- $B gate call --socket $S "$1" > /tmp/gate-reply; r=$?; cat /tmp/gate-reply; return $r; }
# denied CODE REQ [FIELD]: a -32010 error with that code, a denial from the gate, no new INTENT and no effect
denied() { i=$(intents) e=$(effects); call "$2" && grep -qF '"code":-32010' /tmp/gate-reply && grep -qF "\"message\":\"$1\"" /tmp/gate-reply &&
  grep -qF "\"code\":\"$1\"" /tmp/gate-reply && grep -qF '"v":1,"id":"dn_' /tmp/gate-reply &&
  { [ -z "${3:-}" ] || grep -qF "\"subject\":{\"field\":\"$3\"}" /tmp/gate-reply; } && [ "$(intents)" = "$i" ] && [ "$(effects)" = "$e" ]; }
rootd_env() { mkdir -p $D && printf '[Service]\nEnvironment=%s\n' "$@" > $D/50-gate-test.conf && systemctl daemon-reload &&
  systemctl restart agentbox-rootd.service && systemctl is-active -q agentbox-rootd.service; }

P=$(systemctl show -P MainPID $U)
check "agentboxd is active and matched the op registry" 'systemctl is-active -q $U && journalctl -b -u $U -o cat | grep -q "op registry matches .*/gen: [0-9]* ops$"'
check "  ... PrivateNetwork=yes and RestrictAddressFamilies=AF_UNIX" '[ "$(systemctl show -P PrivateNetwork $U)" = yes ] && [ "$(systemctl show -P RestrictAddressFamilies $U)" = AF_UNIX ]'
check "  ... in its own network namespace, with only Unix sockets open" '[ "$(readlink /proc/$P/ns/net)" != "$(readlink /proc/1/ns/net)" ] &&
  ! ls -l /proc/$P/fd | grep socket: | while read -r l; do i=${l##*socket:[}; i=${i%]}; cat /proc/$P/net/unix /proc/net/unix | grep -qE " $i( |\$)" || echo $i; done | grep -q .'
check "svc-gate.sock is agentbox:root 0600, rootd.sock agentbox:agentbox 0600" '[ "$(stat -c "%U:%G %a" /run/agentbox-rootd/svc-gate.sock)" = "agentbox:root 600" ] &&
  [ "$(stat -c "%U:%G %a" /run/agentbox-rootd/rootd.sock)" = "agentbox:agentbox 600" ]'
check "systemd-analyze verify: agentboxd and its sockets" 'systemd-analyze verify agentboxd.service agentboxd-svc-gate.socket agentbox-rootd-gate.socket'

useradd -r -M -s /usr/sbin/nologin ag-gt 2>/dev/null || :
install -d -m 0700 $E
check "rootd with the test file.write effect" "rootd_env AGENTBOX_TEST_GATE_EFFECT=$E"
install -d -o agentbox -g ag-gt -m 2750 /run/agentbox-gate/t/G1
check "register G1 (agent gt) on svc-gate.sock as root" '$B gate register --task G1 --agent gt --chain G0'
check "  ... a non-root peer is refused there" '! runuser -u agentbox -- $B gate list'
check "gate.sock is agentbox:ag-gt 0660 in the 2750 dir" '[ "$(stat -c "%U:%G %a" $S)" = "agentbox:ag-gt 660" ]'
check "  ... another uid can't connect, and root's connection is refused by SO_PEERCRED" '! runuser -u nobody -- $B gate call --socket $S "{}" && ! $B gate call --socket $S "{}"'

body="gate-body-$$-plaintext"
sum=$(printf %s "$body" | sha256sum | cut -d" " -f1)
check "a valid file.write: result with an op id, INTENT then RESULT, the effect ran once" '
  i=$(intents) e=$(effects); call "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"file.write\",\"params\":{\"path\":\"/srv/gt/a\",\"content\":\"$body\"}}" &&
  id=$(sed -n "s/.*\"opId\":\"\(op_[0-9A-Z]*\)\".*/\1/p" /tmp/gate-reply) && [ -n "$id" ] && [ "$(cat $E/$id)" = "$body" ] &&
  [ "$(effects)" = $((e+1)) ] && [ "$(intents)" = $((i+1)) ] &&
  cat $A/seg-*.jsonl | grep "\"opId\":\"$id\"" > /tmp/gate-op && [ "$(wc -l < /tmp/gate-op)" = 2 ] &&
  head -1 /tmp/gate-op | grep -q "\"type\":\"INTENT\"" && tail -1 /tmp/gate-op | grep -q "\"type\":\"RESULT\".*\"status\":\"executed\""'
check "  ... the INTENT names task G1, agent gt, chain [G0] from the socket and holds the body as {sha256, len} only" '
  head -1 /tmp/gate-op | grep -F "\"task\":\"G1\"" | grep -F "\"agent\":\"gt\"" | grep -F "\"chain\":[\"G0\"]" | grep -F "\"origin\":\"gate\"" |
  grep -qF "\"content\":{\"len\":${#body},\"sha256\":\"$sum\"}" && ! grep -rqF "$body" $A'
check "schema: a missing field is INVALID_ARGS /content, no INTENT, no effect" 'denied INVALID_ARGS "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"file.write\",\"params\":{\"path\":\"/srv/gt/a\"}}" /content'
check "schema: a wrong type is INVALID_ARGS /content" 'denied INVALID_ARGS "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"file.write\",\"params\":{\"path\":\"/srv/gt/a\",\"content\":7}}" /content'
check "schema: a spoofed task in params is INVALID_ARGS /task" 'denied INVALID_ARGS "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"file.write\",\"params\":{\"path\":\"/srv/gt/a\",\"content\":\"x\",\"task\":\"G2\"}}" /task'
check "schema: a body with the op marker is INVALID_ARGS /body" 'denied INVALID_ARGS "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"gh.pr.comment\",\"params\":{\"remote\":\"r\",\"number\":1,\"body\":\"agentbox-op: x\"}}" /body'
check "an unknown op is UNKNOWN_OP" 'denied UNKNOWN_OP "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"file.delete\",\"params\":{}}"'
check "an admin op (secret.set) is UNKNOWN_OP and its value is never logged" 'denied UNKNOWN_OP "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"secret.set\",\"params\":{\"name\":\"k\",\"value\":\"sk-gate-secret-1\"}}" &&
  ! grep -rqF sk-gate-secret-1 $A && ! journalctl -b -o cat | grep -qF sk-gate-secret-1'
check "a registry op rootd can't run yet is UNKNOWN_OP from the floor, relayed unchanged" 'denied UNKNOWN_OP "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"app.start\",\"params\":{\"app\":\"a\"}}" &&
  grep -qF "\"by\":\"floor\",\"rule\":\"floor.not_built\"" /tmp/gate-reply'
check "  ... and the gate logged a DENY line per refusal" '[ "$(journalctl -b -u $U -o cat | grep -c "DENY by=gate task=G1")" -ge 6 ]'

raw="raw-body-$$-plaintext"
check "rootd sending the body unhashed (AGENTBOX_TEST_AUDIT_RAW=1)" "rootd_env AGENTBOX_TEST_GATE_EFFECT=$E AGENTBOX_TEST_AUDIT_RAW=1"
check "  ... auditd NACKs the INTENT: EFFECT_FAILED, no INTENT, no effect, the body is nowhere in the audit dir" '
  denied EFFECT_FAILED "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"file.write\",\"params\":{\"path\":\"/srv/gt/a\",\"content\":\"$raw\"}}" &&
  grep -qF "\"rule\":\"audit.bad_record\"" /tmp/gate-reply && ! grep -rqF "$raw" $A &&
  journalctl -b -u agentbox-auditd.service -o cat | grep -qF "INTENT from rootd NACKed: /args/content: hash-class field not in {sha256, len} form"'
check "an INTENT with a secret (secret.set value) is NACKed BAD_RECORD; no RESULT can follow it" '
  ! $B audit send --socket /run/agentbox-audit/rootd.sock "{\"type\":\"INTENT\",\"opId\":\"gate-sec-1\",\"name\":\"secret.set\",\"origin\":\"admin\",\"args\":{\"name\":\"k\",\"value\":\"sk-gate-secret-2\"}}" > /tmp/gate-a &&
  grep -qF "\"code\":\"BAD_RECORD\"" /tmp/gate-a && grep -qF "/args/value: drop-class field present" /tmp/gate-a &&
  ! $B audit send --socket /run/agentbox-audit/rootd.sock "{\"type\":\"RESULT\",\"opId\":\"gate-sec-1\",\"status\":\"executed\"}" | grep -qF "\"ok\":true" &&
  ! grep -rqF sk-gate-secret-2 $A && ! journalctl -b -o cat | grep -qF sk-gate-secret-2'
check "an INTENT with an unhashed gh.pr.comment body is NACKed BAD_RECORD" '
  ! $B audit send --socket /run/agentbox-audit/rootd.sock "{\"type\":\"INTENT\",\"opId\":\"gate-body-1\",\"name\":\"gh.pr.comment\",\"args\":{\"remote\":\"r\",\"number\":1,\"body\":\"gate-unhashed-3\"}}" > /tmp/gate-a &&
  grep -qF "/args/body: hash-class field not in {sha256, len} form" /tmp/gate-a && ! grep -rqF gate-unhashed-3 $A'

rm -f $D/50-gate-test.conf; systemctl daemon-reload
check "rootd back without the test hooks" 'systemctl restart agentbox-rootd.service && systemctl is-active -q agentbox-rootd.service'
check "  ... and without an effect a valid file.write is UNKNOWN_OP (floor.not_built), no INTENT" 'denied UNKNOWN_OP "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"file.write\",\"params\":{\"path\":\"/srv/gt/a\",\"content\":\"x\"}}"'
check "revoke G1: the socket is gone and a connect fails" '$B gate revoke --task G1 && [ ! -e $S ] && ! call "{}"'
check "the audit chain verifies" '$B audit verify'
systemctl start multi-user.target
check "no failed units" 'sleep 5; [ -z "$(systemctl --failed --no-legend --plain)" ]'
journalctl -b -u $U -o short-precise --no-pager | tail -40
journalctl -b -u agentbox-auditd.service -o short-precise --no-pager | grep NACK | tail -10
rm -rf $E /run/agentbox-gate/t/G1 /tmp/gate-*; userdel ag-gt 2>/dev/null || :
echo "fails=$fails"
EOF
  ;;
*) die "unknown stage $s (install or checks)" ;;
esac; done
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "agentboxd gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "agentboxd gate: all checks passed"

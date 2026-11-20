#!/bin/sh
# agentbox-auditd gates (PLAN.md milestone row 3, ARCHITECTURE.md §9, §5.2 taint fence) on the local QEMU VM.
#   hack/audit-gate.sh [install] [audit]   default: both, in order
# install  hack/gate.sh none: the unattended install, then firstboot installs the release that ships auditd, its
#          producer sockets and the seal stand-in (make release, install.sh, systemd/), from --dev release URLs.
# audit    on that box, as root: socket owners and modes, SO_PEERCRED; auditd down (stopped, or hung with a producer
#          waiting) means the test producer's effect never runs; the taint write rules from every producer socket; a
#          clear only as a rootd admin taint.clear INTENT then RESULT, after which the row stays with its epoch moved;
#          taint.get names task or session per writer; disk full (fallocate) refuses everything but rootd admin ops, and
#          taint.clear still runs; a torn tail, a backward clock step across UTC midnight, and SIGKILL at each of the
#          four seal steps (auditd after close and after the seal, rootd's seal after +i and after creating the next
#          segment) don't stop ACKs; then a reboot rotates; `agentbox audit verify` passes after each.
# Checks print PASS/FAIL to .vm/audit-gate.txt, command output goes to .vm/audit-gate.log; exit 1 on any FAIL. The VM is
# powered off at the end. AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install audit
OUT="$VM/audit-gate.txt" LOG="$VM/audit-gate.log"
mkdir -p "$VM"
: > "$OUT"; : > "$LOG"
! command -v caffeinate >/dev/null || { caffeinate -i -w $$ & }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT"; }
die() { log "ABORT $*"; exit 1; }
root() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s'; } # stdin: a script run as root on the VM
running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }
bootid() { hack/vm.sh ssh cat /proc/sys/kernel/random/boot_id 2>/dev/null || :; }
wait_boot() { end=$(( $(date +%s) + $2 ))
  while :; do b=$(bootid); [ -n "$b" ] && [ "$b" != "$1" ] && return 0; [ "$(date +%s)" -lt $end ] || return 1; sleep 5; done; }
vm_off() { echo 'systemctl poweroff' | root >/dev/null 2>&1 || :; i=0
  while running; do i=$((i+1)); [ $i -lt 60 ] || kill "$(cat "$VM/qemu.pid")"; sleep 2; done; }

# The guest half: every check runs inside the VM, so nothing the guest reports is parsed on the Mac.
guest_lib='
A=/var/lib/agentbox/current/bin/agentbox D=/var/lib/agentbox/audit S=/run/agentbox-audit
fails=0
check() { if (eval "$2") >>/run/audit-gate.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
# psend USER PRODUCER JSON...: a test producer that runs as USER on PRODUCER.sock; exit 0 only on an ACK of every record
psend() { u=$1 p=$2; shift 2; runuser -u "$u" -- $A audit send --timeout 20s --socket $S/$p.sock "$@"; }
send() { psend root rootd "$@"; }
# nack CODE USER PRODUCER JSON: refused with CODE
nack() { c=$1; shift; if out=$(psend "$@"); then echo "ACKed: $out"; return 1; fi; echo "$out"; echo "$out" | grep -q "\"code\":\"$c\""; }
# row HOLDER SUBJECT TAINTED EPOCH: taint.get on agentboxd.sock shows SUBJECT so
row() { psend agentbox agentboxd "{\"type\":\"taint.get\",\"holder\":\"$1\"}" | grep -qF "{\"subject\":\"$2\",\"tainted\":$3,\"epoch\":$4}"; }
newest() { ls $D | grep "^seg-[0-9]*\.jsonl$" | tail -n 1; }
nsegs() { ls $D | grep -c "^seg-[0-9]*\.jsonl$"; }
verify() { $A audit verify | tee /run/audit-verify.txt | grep -q "^audit verify: OK"; }
mainpid() { systemctl show -P MainPID agentbox-auditd.service; }
SOCKS="agentbox-auditd-rootd.socket agentbox-auditd-agentboxd.socket agentbox-auditd-proxy.socket agentbox-auditd-keys.socket agentbox-auditd-git.socket"
'

sc_install() {
  log "install: hack/gate.sh none (about 30 min)"
  hack/gate.sh none uefi >>"$LOG" 2>&1 || die "install gate failed (see $LOG and $VM/gate-none.txt)"
  cat "$VM/gate-none.txt" >>"$OUT"
}

sc_audit() {
  running || { hack/vm.sh boot >>"$LOG" 2>&1 & }
  wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"
  echo 'systemctl is-system-running --wait >/dev/null; : > /run/audit-gate.log' | root >>"$LOG" 2>&1 || :
  { echo "$guest_lib"; cat <<'EOF'; } | root | tee -a "$OUT"
check "auditd active as agentbox-audit, PrivateNetwork, no capabilities" '[ "$(systemctl is-active agentbox-auditd.service)" = active ] &&
  [ "$(ps -o user= -p "$(mainpid)")" = agentbox-audit ] && [ "$(systemctl show -P PrivateNetwork agentbox-auditd.service)" = yes ] &&
  [ -z "$(systemctl show -P CapabilityBoundingSet agentbox-auditd.service)" ]'
check "one socket per producer: agentbox-audit:<producer> 0660, dir 0711" '[ "$(stat -c "%U:%G %a" $S)" = "agentbox-audit:agentbox-audit 711" ] &&
  for pg in rootd:root agentboxd:agentbox proxy:agentbox-proxy keys:agentbox-keys git:agentbox-git; do
    [ "$(stat -c "%U:%G %a %F" $S/${pg%%:*}.sock)" = "agentbox-audit:${pg#*:} 660 socket" ] || exit 1; done'
check "audit dir agentbox-audit 0750; open segment 0640, +a not +i; taint.db in WAL; 512 MiB reserve" '
  [ "$(stat -c "%U:%G %a" $D)" = "agentbox-audit:agentbox-audit 750" ] && s=$(newest) &&
  [ "$(stat -c "%U:%G %a" $D/$s)" = "agentbox-audit:agentbox-audit 640" ] && lsattr $D/$s | cut -d" " -f1 | grep -q a &&
  ! lsattr $D/$s | cut -d" " -f1 | grep -q i && [ -e $D/taint.db-wal ] && [ "$(stat -c %s $D/.reserve)" = 536870912 ]'
check "SO_PEERCRED: root on agentboxd.sock is refused" 'nack NOT_ALLOWED root agentboxd "{\"type\":\"TAINT\",\"subject\":\"task:x\",\"source\":\"s\"}"'
check "socket mode: agentbox-proxy cannot connect to rootd.sock" '! psend agentbox-proxy rootd "{\"type\":\"TAINT\",\"subject\":\"task:x\",\"source\":\"s\"}"'
check "every producer gets an ACK on its own socket" 'for up in root:rootd agentbox:agentboxd agentbox-proxy:proxy agentbox-keys:keys agentbox-git:git; do
  psend ${up%%:*} ${up#*:} "{\"type\":\"DENY\",\"id\":\"d-${up#*:}\",\"code\":\"X\"}" || exit 1; done'

# auditd down: nothing executes. The effect is `touch`, run only after the test producer's ACK.
systemctl stop agentbox-auditd.service $SOCKS
check "auditd and its sockets stopped: the INTENT gets no ACK and the effect never runs" '! send "{\"type\":\"INTENT\",\"opId\":\"down-1\",\"name\":\"app.start\"}" && touch /run/gate-eff1; [ ! -e /run/gate-eff1 ]'
systemctl start $SOCKS agentbox-auditd.service
kill -STOP "$(mainpid)"
( send "{\"type\":\"INTENT\",\"opId\":\"down-2\",\"name\":\"app.start\"}" >/run/gate-eff2.reply && touch /run/gate-eff2 ) &
sleep 8
check "auditd hung: the producer waits and the effect has not run after 8 s" '[ ! -e /run/gate-eff2 ] && kill -0 $!'
kill -CONT "$(mainpid)"; wait $! || :
check "auditd back: the ACK arrives, then the effect runs, and the INTENT is in the chain" '[ -e /run/gate-eff2 ] && grep -q "\"ok\":true" /run/gate-eff2.reply &&
  grep -qF "\"opId\":\"down-2\"" $D/$(newest)'

# Taint write rules (§9) and the taint fence (§5.2)
check "a producer raises taint; writers register; taint.get names task and session" '
  psend agentbox-proxy proxy "{\"type\":\"TAINT\",\"subject\":\"workspace:a\",\"source\":\"proxy:connect\"}" &&
  send "{\"type\":\"WRITER_ADD\",\"holder\":\"task:g1\",\"workspace\":\"workspace:a\"}" "{\"type\":\"WRITER_ADD\",\"holder\":\"session:g2\",\"workspace\":\"workspace:a\"}" &&
  row task:g1 workspace:a true 1 && psend agentbox agentboxd "{\"type\":\"taint.get\",\"holder\":\"task:g1\"}" | grep -qF "\"holder\":\"task:g1\",\"kind\":\"task\"" &&
  psend agentbox agentboxd "{\"type\":\"taint.get\",\"holder\":\"session:g2\"}" | grep -qF "\"holder\":\"session:g2\",\"kind\":\"session\""'
check "re-taint from another producer keeps the epoch" 'psend agentbox-keys keys "{\"type\":\"TAINT\",\"subject\":\"workspace:a\",\"source\":\"keys\"}" && row task:g1 workspace:a true 1'
check "an INTENT bound to a moved epoch is NACKed STALE and its effect never runs" 'nack STALE root rootd "{\"type\":\"INTENT\",\"opId\":\"st-1\",\"name\":\"app.deploy\",\"taintEpochs\":{\"workspace:a\":0}}" && touch /run/gate-eff3; [ ! -e /run/gate-eff3 ]'
v0=$(grep -ho "\"type\":\"violation\"" $D/seg-*.jsonl | wc -l)
for up in agentbox:agentboxd agentbox-proxy:proxy agentbox-keys:keys agentbox-git:git; do u=${up%%:*} p=${up#*:}
  check "$p.sock: tainted=0 is a violation" 'nack VIOLATION $u $p "{\"type\":\"TAINT\",\"subject\":\"workspace:a\",\"source\":\"s\",\"tainted\":0}"'
  check "$p.sock: an epoch field is a violation" 'nack VIOLATION $u $p "{\"type\":\"TAINT\",\"subject\":\"workspace:a\",\"source\":\"s\",\"epoch\":5}"'
  check "$p.sock: a taint.clear INTENT is a violation" 'nack VIOLATION $u $p "{\"type\":\"INTENT\",\"opId\":\"evil-$p\",\"name\":\"taint.clear\",\"origin\":\"admin\",\"args\":{\"subject\":\"workspace:a\",\"contentId\":\"c\"},\"taintEpochs\":{\"workspace:a\":1}}"'
  check "$p.sock: a taint.clear RESULT is a violation" 'nack VIOLATION $u $p "{\"type\":\"RESULT\",\"opId\":\"evil-$p\",\"name\":\"taint.clear\",\"status\":\"executed\"}"'
done
check "rootd: a clear that is not an admin op, or a RESULT with no INTENT, is refused" '
  nack BAD_RECORD root rootd "{\"type\":\"INTENT\",\"opId\":\"cl-0\",\"name\":\"taint.clear\",\"args\":{\"subject\":\"workspace:a\",\"contentId\":\"c\"},\"taintEpochs\":{\"workspace:a\":1}}" &&
  nack UNKNOWN_OP root rootd "{\"type\":\"RESULT\",\"opId\":\"cl-none\",\"status\":\"executed\"}" &&
  nack BAD_RECORD root rootd "{\"type\":\"TAINT\",\"subject\":\"workspace:a\",\"source\":\"s\",\"tainted\":0}"'
check "after every refused clear the subject is still tainted at epoch 1, and 16 violations are logged" 'row task:g1 workspace:a true 1 &&
  [ $(( $(grep -ho "\"type\":\"violation\"" $D/seg-*.jsonl | wc -l) - v0 )) -ge 16 ]'
check "rootd admin taint.clear: INTENT, then RESULT clears it; the row survives with its epoch moved (2)" '
  send "{\"type\":\"INTENT\",\"opId\":\"cl-1\",\"name\":\"taint.clear\",\"origin\":\"admin\",\"signer\":\"gate\",\"args\":{\"subject\":\"workspace:a\",\"contentId\":\"snap1\"},\"taintEpochs\":{\"workspace:a\":1}}" &&
  send "{\"type\":\"RESULT\",\"opId\":\"cl-1\",\"status\":\"executed\"}" | grep -q "\"applied\":true" && row task:g1 workspace:a false 2'
check "audit verify after the rules" verify

# Disk full: only rootd admin ops are ACKed, and taint.clear still runs
psend agentbox-git git '{"type":"TAINT","subject":"workspace:b","source":"git"}' >/dev/null
send '{"type":"WRITER_ADD","holder":"task:g3","workspace":"workspace:b"}' >/dev/null
sync; av=$(df --output=avail -B1 $D | tail -n 1)
fallocate -l $((av - 300 * 1024 * 1024)) /var/tmp/gate-fill; sync
check "disk full: a producer TAINT is refused DISK_FULL, the reserve is deleted, a critical alert is logged" '
  nack DISK_FULL agentbox-proxy proxy "{\"type\":\"TAINT\",\"subject\":\"workspace:z\",\"source\":\"p\"}" && [ ! -e $D/.reserve ] &&
  grep -qF "\"type\":\"alert\"" $D/$(newest) && grep -qF "disk_full" $D/$(newest) && journalctl -u agentbox-auditd.service -b -o cat | grep -q "CRITICAL: disk-full mode"'
check "disk full: a non-admin rootd INTENT is refused and its effect never runs" '! send "{\"type\":\"INTENT\",\"opId\":\"df-1\",\"name\":\"app.start\"}" && touch /run/gate-eff4; [ ! -e /run/gate-eff4 ]'
check "disk full: taint.clear (rootd-admin) is ACKed and executes" '
  send "{\"type\":\"INTENT\",\"opId\":\"cl-2\",\"name\":\"taint.clear\",\"origin\":\"admin\",\"signer\":\"gate\",\"args\":{\"subject\":\"workspace:b\",\"contentId\":\"snap2\"},\"taintEpochs\":{\"workspace:b\":1}}" &&
  send "{\"type\":\"RESULT\",\"opId\":\"cl-2\",\"status\":\"executed\"}" | grep -q "\"applied\":true" && row task:g3 workspace:b false 2'
rm -f /var/tmp/gate-fill; sync; btrfs filesystem sync $D >/dev/null 2>&1 || :
check "space back: ACKs resume and the 512 MiB reserve is recreated" 'i=0; until psend agentbox-proxy proxy "{\"type\":\"TAINT\",\"subject\":\"workspace:c\",\"source\":\"p\"}"; do
  i=$((i+1)); [ $i -lt 30 ] || exit 1; sleep 2; done; [ "$(stat -c %s $D/.reserve)" = 536870912 ]'
check "audit verify after disk full" verify

# Torn tail: bytes past the last complete record, never ACKed
systemctl stop agentbox-auditd.service
printf '%s' '{"seq":999999,"prev":"torn-by-the-gate' >> $D/$(newest)
systemctl start agentbox-auditd.service
check "torn tail: auditd starts and ACKs" 'send "{\"type\":\"TAINT\",\"subject\":\"task:torn\",\"source\":\"s\"}" && grep -qF "\"type\":\"torn\"" $D/$(newest)'
check "audit verify skips the declared torn bytes and passes" 'verify && grep -q "torn bytes .* skipped" /run/audit-verify.txt'

# A backward wall-clock step across UTC midnight: logged, never rotates, never stops ACKs
timedatectl set-ntp false >/dev/null 2>&1 || :
now=$(date +%s) s0=$(newest); m=$(( (now / 86400 + 1) * 86400 ))
date -u -s "@$((m + 30))" >/dev/null
check "clock 00:00:30 UTC: ACK" 'send "{\"type\":\"TAINT\",\"subject\":\"task:clk1\",\"source\":\"s\"}"'
date -u -s "@$((m - 30))" >/dev/null
check "clock stepped back to 23:59:30 UTC: ACK, a clock_step with a negative delta, the same segment" '
  send "{\"type\":\"TAINT\",\"subject\":\"task:clk2\",\"source\":\"s\"}" && [ "$(newest)" = "$s0" ] && grep -F "\"type\":\"clock_step\"" $D/$s0 | grep -q "\"delta_ms\":-"'
date -u -s "@$(( now + 5 ))" >/dev/null; timedatectl set-ntp true >/dev/null 2>&1 || :
check "audit verify after the clock steps; segments are named by sequence only" 'verify && [ -z "$(ls $D | grep -v -e "^seg-[0-9]\{6\}\.jsonl$" -e "^taint\.db" -e "^\.reserve$")" ]'

# Crash mid-seal: SIGKILL at each seal step, with 4 KiB segments so records rotate them
mkdir -p /run/systemd/system/agentbox-auditd.service.d /run/systemd/system/agentbox-audit-seal.service.d
crashat() { # UNIT-DROPIN-DIR POINT
  printf '[Service]\nExecStart=\nExecStart=%s auditd --segment-bytes 4096\n' $A > /run/systemd/system/agentbox-auditd.service.d/gate.conf
  rm -f /run/systemd/system/agentbox-audit-seal.service.d/gate.conf
  printf '[Service]\nEnvironment=AGENTBOX_TEST_CRASH=%s:%s/.gate-crash-%s\n' $2 $D $2 >> /run/systemd/system/$1.service.d/gate.conf
  systemctl daemon-reload; systemctl restart agentbox-audit-seal.service agentbox-auditd.service
}
pad=$(head -c 600 /dev/zero | tr "\0" p)
for up in agentbox-auditd:close-written agentbox-auditd:sealed agentbox-audit-seal:immutable-set agentbox-audit-seal:next-created; do
  u=${up%%:*} pt=${up#*:}
  crashat $u $pt; n0=$(nsegs)
  check "SIGKILL in $u at $pt: it fired, ACKs resume, a new segment is open, every older one is +i" 'i=0 acked=0
    until [ -e $D/.gate-crash-$pt ] && [ $acked = 1 ]; do i=$((i+1)); [ $i -lt 60 ] || exit 1
      if send "{\"type\":\"TAINT\",\"subject\":\"task:crash-$i\",\"source\":\"$pad\"}" >/dev/null 2>&1; then [ -e $D/.gate-crash-$pt ] && acked=1; else sleep 1; fi; done
    [ $(nsegs) -gt $n0 ] && journalctl -b -u $u.service -o cat | grep -q "AGENTBOX_TEST_CRASH: SIGKILL at $pt" &&
    for s in $(ls $D | grep "^seg-[0-9]*\.jsonl$" | grep -vx $(newest)); do lsattr $D/$s | cut -d" " -f1 | grep -q i || exit 1; done'
  check "audit verify after the crash at $pt" verify
done
rm -f /run/systemd/system/agentbox-auditd.service.d/gate.conf /run/systemd/system/agentbox-audit-seal.service.d/gate.conf $D/.gate-crash-*
systemctl daemon-reload; systemctl restart agentbox-audit-seal.service agentbox-auditd.service
check "back on the shipped units: ACK" 'send "{\"type\":\"TAINT\",\"subject\":\"task:after\",\"source\":\"s\"}"'
check "no failed units" '[ -z "$(systemctl --failed --no-legend --plain)" ]'
nsegs > /var/tmp/gate-nsegs
echo "audit-fails=$fails"
EOF
  b=$(bootid)
  echo 'systemctl reboot' | root >/dev/null 2>&1 || :
  wait_boot "$b" 900 || die "no SSH after the reboot"
  { echo "$guest_lib"; cat <<'EOF'; } | root | tee -a "$OUT"
systemctl is-system-running --wait >/dev/null
check "after a reboot: auditd ACKs, and its first start in the new boot rotated to a new segment" '
  send "{\"type\":\"TAINT\",\"subject\":\"task:reboot\",\"source\":\"s\"}" && [ $(nsegs) -gt $(cat /var/tmp/gate-nsegs) ] &&
  head -n 1 $D/$(newest) | grep -qF "\"boot_id\":\"$(cat /proc/sys/kernel/random/boot_id)\""'
check "audit verify after the reboot" verify
check "no failed units after the reboot" '[ -z "$(systemctl --failed --no-legend --plain)" ]'
cat /run/audit-verify.txt; rm -f /var/tmp/gate-nsegs
echo "audit-fails=$fails"
EOF
  echo 'cat /run/audit-gate.log' | root >>"$LOG" 2>&1 || :
  vm_off
}

for sc in "$@"; do
  case $sc in install|audit) log "== $sc"; "sc_$sc" ;; *) die "unknown scenario $sc (install, audit)" ;; esac
done
! grep -q '^FAIL' "$OUT" || die "audit gate failed; see $OUT and $LOG"
! { printf '%s\n' "$@" | grep -qx audit; } || [ "$(grep -c '^audit-fails=0$' "$OUT")" = 2 ] || die "audit gate did not finish its checks; see $OUT"
log "audit gate: all checks passed"

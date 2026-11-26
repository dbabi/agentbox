#!/bin/sh
# Agent accounts gate (PLAN.md row 5-6, ARCHITECTURE.md §4.1, Appendix C) on the local QEMU VM, arm64 UEFI, none mode.
#   hack/accounts-gate.sh [install|checks ...]   default: both, in order
# install  hack/gate.sh none: the unattended install and the release pipeline, so rootd, agentbox-accounts.service and
#          the regenerated gen/ reach the box by the real path (make release, install.sh).
# checks   `agentbox agent add` over rootd-admin.sock makes ag-<name> with uid/gid 70000+N, nologin and a root-owned
#          empty home; its 65536-wide sub-id block at 0x70000000+N*65536 in /etc/subuid and /etc/subgid; root-owned
#          XDG dirs with storage.conf; the user@ drop-in (Requires= and After= firewall, reconcile, rootd; the XDG env;
#          ExecStartPre=+fwcheck), the slice drop-in, linger and a running user manager; workspace, storage and
#          session-home subvolumes owned by the agent in qgroup 1/N under 2/0 with the requested limit. An agent at its quota gets
#          EDQUOT, also in its storage, while system state keeps writing and 2/0's limit still leaves the reserve. With drop_subtree_threshold 1
#          a snapshot delete makes qgroups inconsistent: rootd freezes the agent's slice, refuses file.write through the
#          task gate and task new with BUSY and alerts; after its rescan the flag is 0, the slice thaws and 1/N gives
#          EDQUOT again (#79). Removing the newest
#          agent deletes its user, sub-ids and drop-ins and archives its subvolumes; adding another never reuses its
#          uid or sub-id range, and re-adding its name gets a new N. A nested subvolume refuses agent.remove with
#          NESTED_SUBVOLUME and taints workspace:<name>#<N>; re-adding that name gets a clean workspace subject while the
#          old one stays tainted. An agent add that a rootd restart catches in its agentbox-accounts.service start
#          (held 20 s) finishes, with an executed RESULT, and a request during that drain is refused "stopping" at once
#          (#273). A foreign /etc/subuid entry inside the agentbox span stops reconcile. After a reboot reconcile rebuilds the same accounts and nothing failed.
# PASS/FAIL lines go to .vm/accounts-gate.txt, command output to .vm/accounts-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/accounts-gate.txt" LOG="$VM/accounts-gate.log"
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
settle() { echo '[ "$(timeout 600 systemctl is-system-running --wait)" = running ] || systemctl --failed --no-pager' | root >>"$LOG" 2>&1 || :; }
up() { running || { hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"; settle; }
reboot_vm() { old=$(bootid); echo 'systemctl reboot' | root >/dev/null 2>&1 || :; wait_boot "$old" 900 || die "no SSH after reboot"; settle; }
guest() {
  root >"$VM/guest.out" 2>>"$LOG" || :
  while IFS= read -r l; do case $l in PASS*|FAIL*) log "$l" ;; *) echo "$l" >>"$LOG" ;; esac; done <"$VM/guest.out"
  grep -q '^fails=' "$VM/guest.out" || log "FAIL the check block on the VM did not finish (see $LOG)"
}
# The guest-side helpers. ag runs the admin CLI and keeps its reply in /run/ag.json; f FIELD reads the reply's agent;
# qg ID FIELD reads one qgroup field; st/sg print a user's /etc/subuid and /etc/subgid lines.
PRELUDE='fails=0
check() { if (eval "$2") >>/tmp/gate-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
M=/var/lib/agentbox D=$M/data A=$M/current/bin/agentbox
ag() { $A agent "$@" > /run/ag.json; r=$?; cat /run/ag.json; return $r; }
f() { python3 -c "import json,sys; print(json.load(open(\"/run/ag.json\"))[\"agent\"][sys.argv[1]])" "$1"; }
qg() { btrfs --format=json qgroup show -p -r -e $M | python3 -c "import json,sys; r=[q for q in json.load(sys.stdin)[\"qgroup-show\"] if q[\"qgroupid\"]==sys.argv[1]]; v=r[0][sys.argv[2]] if r else \"absent\"; print(\",\".join(v) if isinstance(v,list) else v)" "$1" "$2"; }
qid() { echo "0/$(btrfs inspect-internal rootid "$1")"; }
st() { grep "^$1:" /etc/subuid; }
sg() { grep "^$1:" /etc/subgid; }
taint() { python3 -c "import sqlite3,sys; c=sqlite3.connect(\"file:$M/audit/taint.db?mode=ro\", uri=True); r=c.execute(\"select tainted from taint where subject=?\", (sys.argv[1],)).fetchone(); print(r[0] if r else \"\")" "$1"; }
users() { getent passwd | awk -F: "\$3 >= 70000 && \$3 < 71000 {print \$1, \$3}" | sort; }
failed() { systemctl --failed --no-legend --plain | while read -r u _; do echo "failed unit $u:"; journalctl -b -u "$u" -o short-precise --no-pager | tail -n 40; done; }
S=$(( $(stat -f -c %b $M) * $(stat -f -c %S $M) )); R=$((S / 10)); [ $R -ge 4294967296 ] || R=4294967296
# leaves: the 2/0 limit leaves the reserve R free: at most its bound (free space + what 2/0 references - R), and
# within 256 MiB of it (quota.Refresh sets it 64 MiB below and lets it drift 128 MiB more)
leaves() { l=$(qg 2/0 max_referenced) b=$(( $(stat -f -c %a $M) * $(stat -f -c %S $M) + $(qg 2/0 referenced) - R )); echo "2/0 limit $l, bound $b"
  [ "$l" -le $b ] && [ "$l" -ge $((b - (256 << 20))) ]; }
'

for s; do case $s in
install)
  hack/gate.sh none >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-none.txt"
  log "PASS install: hack/gate.sh none (install, release pipeline, firstboot, no failed units)" ;;
checks)
  up
  { echo "$PRELUDE"; cat <<'EOF'; } | guest
# names unique per run, so the checks also pass on a box that ran them before
X=$(date +%s | tail -c 6) QA=qa$X QB=qb$X QC=qc$X
check "agent add $QA --disk-bytes 64 MiB: rootd answers ok" 'ag add --name $QA --disk-bytes $((64 << 20)) && [ "$(f name)" = $QA ]'
NA=$(f n); UA=$((70000 + NA)); BA=$((0x70000000 + NA * 65536))
check "ag-$QA: uid and gid 70000+N ($UA), nologin" '[ "$(getent passwd ag-$QA | cut -d: -f3,4,7)" = "$UA:$UA:/usr/sbin/nologin" ] && [ "$(getent group ag-$QA | cut -d: -f3)" = $UA ]'
check "  ... its home is root-owned, 0755 and empty" 'h=$(getent passwd ag-$QA | cut -d: -f6) && [ "$h" = $D/agents/$QA/account ] && [ "$(stat -c "%U %a" $h)" = "root 755" ] && [ -z "$(ls -A $h)" ]'
check "  ... sub-ids: one 65536-wide block at 0x70000000+N*65536 in /etc/subuid and /etc/subgid" '[ "$(st ag-$QA)" = "ag-$QA:$BA:65536" ] && [ "$(sg ag-$QA)" = "ag-$QA:$BA:65536" ]'
check "  ... root-owned XDG_CONFIG_HOME and XDG_DATA_HOME the agent can read, storage.conf with graphroot in data/agents" 'x=$M/control/xdg/$QA &&
  [ "$(stat -c "%U %a" $x/config $x/config/containers $x/data)" = "$(printf "root 755\nroot 755\nroot 755")" ] && [ "$(stat -c "%U %a" $x/config/containers/storage.conf)" = "root 644" ] &&
  grep -qx "graphroot = \"$D/agents/$QA/storage\"" $x/config/containers/storage.conf && grep -qx "runroot = \"/run/user/$UA/containers\"" $x/config/containers/storage.conf &&
  [ "$(stat -c "%U %a" $M/control $M/control/xdg)" = "$(printf "root 711\nroot 711")" ] && runuser -u ag-$QA -- cat $x/config/containers/storage.conf >/dev/null'
check "  ... user@$UA: Requires= and After= firewall, reconcile and rootd; the XDG env; ExecStartPre=+fwcheck" 'u=user@$UA.service &&
  for p in Requires After; do for d in agentbox-firewall agentbox-reconcile agentbox-rootd; do systemctl show -P $p $u | grep -qw $d.service || exit 1; done; done &&
  systemctl show -P Environment $u | grep -q "XDG_CONFIG_HOME=$M/control/xdg/$QA/config" && systemctl show -P ExecStartPre $u | grep -q "agentbox fwcheck"'
check "  ... slice drop-in: MemoryMax 8G, TasksMax 4096" '[ "$(systemctl show -P MemoryMax user-$UA.slice)" = 8589934592 ] && [ "$(systemctl show -P TasksMax user-$UA.slice)" = 4096 ]'
check "  ... linger on, and its user manager runs" '[ "$(loginctl show-user ag-$QA -P Linger)" = yes ] && for i in $(seq 30); do systemctl is-active -q user@$UA.service && exit 0; sleep 1; done; exit 1'
W=$D/workspaces/$QA ST=$D/agents/$QA/storage SH=$D/agents/$QA/session-home
check "  ... workspace, storage and session-home: subvolumes owned by ag-$QA, 0700, in qgroup 1/$NA" 'for p in $W $ST $SH; do
  [ "$(stat -c "%i %u %a" $p)" = "256 $UA 700" ] && qg "$(qid $p)" parents | tr , "\n" | grep -qx 1/$NA || exit 1; done'
check "  ... 1/$NA is under 2/0 with a 64 MiB exclusive limit; 2/0's limit still leaves the max(10%, 4 GiB) reserve" '
  qg 1/$NA parents | tr , "\n" | grep -qx 2/0 && [ "$(qg 1/$NA max_exclusive)" = $((64 << 20)) ] && leaves'
check "an agent at its 64 MiB quota gets EDQUOT" 'e=$(runuser -u ag-$QA -- dd if=/dev/urandom of=$W/fill bs=1M count=200 conv=fsync 2>&1); echo "$e" | grep -aq "Disk quota exceeded" && [ $(stat -c %s $W/fill) -le $((64 << 20)) ]'
check "  ... and its storage shares the quota: EDQUOT there too" '! runuser -u ag-$QA -- dd if=/dev/urandom of=$ST/more bs=1M count=8 conv=fsync'
check "  ... while system state (outside 2/0) still writes 100 MiB" 'mkdir -p $M/audit && dd if=/dev/urandom of=$M/audit/gate-fill bs=1M count=100 conv=fsync && [ $(stat -c %s $M/audit/gate-fill) = $((100 << 20)) ]'
rm -f $M/audit/gate-fill $W/fill $ST/more
# #79: a snapshot drop past qgroups/drop_subtree_threshold makes qgroups inconsistent; rootd fences the 2/0 writers until
# a rescan. The hold file keeps the fence up while the checks look; rootd restarts once to read its env.
Q=/sys/fs/btrfs/$(btrfs filesystem show $M | sed -n "s/.* uuid: \([0-9a-f-]*\).*/\1/p")/qgroups CG=/sys/fs/cgroup/user.slice/user-$UA.slice
fenced() { $A quota check > /run/qc.json; grep -q "\"fenced\":$1" /run/qc.json; }
mkdir -p /run/systemd/system/agentbox-rootd.service.d
printf '[Service]\nEnvironment=AGENTBOX_TEST_QUOTA_HOLD=/run/agentbox-quota-hold\n' > /run/systemd/system/agentbox-rootd.service.d/50-gate-hold.conf
systemctl daemon-reload && systemctl restart agentbox-rootd.service
for i in $(seq 60); do systemctl is-active -q user@$UA.service && fenced false && break; sleep 1; done
check "qgroups consistent and rootd's fence down before the snapshot drop" '[ "$(cat $Q/inconsistent)" = 0 ] && fenced false && grep -qx "frozen 0" $CG/cgroup.events'
touch /run/agentbox-quota-hold
btrfs subvolume create $D/qg-gate >/dev/null
python3 -c "import os,sys; [open(os.path.join(sys.argv[1], 'f%d' % i), 'wb').write(os.urandom(2000)) for i in range(20000)]" $D/qg-gate
echo 1 > $Q/drop_subtree_threshold
btrfs subvolume snapshot $D/qg-gate $D/qg-snap >/dev/null && sync && btrfs subvolume delete $D/qg-snap >/dev/null && btrfs subvolume sync $D
check "drop_subtree_threshold 1, a snapshot deleted: qgroups/inconsistent reads 1" '[ "$(cat $Q/inconsistent)" = 1 ]'
( $A quota check > /run/qc-held.json 2>&1 & )
check "  ... rootd fences: quota check says fenced, ag-$QA's user slice is frozen" 'for i in $(seq 30); do grep -qx "frozen 1" $CG/cgroup.events && break; sleep 1; done &&
  grep -qx "frozen 1" $CG/cgroup.events && fenced true'
install -d -o agentbox -g ag-$QA -m 2750 /run/agentbox-gate/t/QF$X && $A gate register --task QF$X --agent $QA >/dev/null
check "  ... a file.write through the task gate gets the typed denial BUSY by floor, with no reason (rootd logged floor.quota_fence for its id)" '
  setpriv --reuid ag-$QA --regid ag-$QA --init-groups $A gate call --socket /run/agentbox-gate/t/QF$X/gate.sock "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"file.write\",\"params\":{\"path\":\"/srv/x\",\"content\":\"x\"}}" > /run/qf.json &&
  grep -qF "\"code\":-32010" /run/qf.json && grep -qF "\"code\":\"BUSY\"" /run/qf.json && grep -qF "\"by\":\"floor\"" /run/qf.json &&
  ! grep -qE "quota|\"rule\"" /run/qf.json && id=$(sed -n "s/.*\"id\":\"\(dn_[0-9A-Z]*\)\".*/\1/p" /run/qf.json) && [ -n "$id" ] &&
  for n in 1 2 3 4 5; do journalctl -b -u agentbox-rootd -o cat | grep -qF "rule=floor.quota_fence id=$id" && exit 0; sleep 1; done; exit 1'
check "  ... task new is refused with the same denial" '! echo hi | $A task new --agent $QA > /run/qt.json 2>&1; grep -qF "\"code\":\"BUSY\"" /run/qt.json'
check "  ... rootd sent the ALERT" 'journalctl -b -u agentbox-rootd -o cat | grep -q "ALERT quota: qgroups are inconsistent"'
rm -f /run/agentbox-quota-hold
check "hold released: the rescan runs, quota check says not fenced" 'for i in $(seq 120); do fenced false && exit 0; sleep 1; done; exit 1'
check "  ... qgroups/inconsistent reads 0 and the slice is thawed" '[ "$(cat $Q/inconsistent)" = 0 ] && grep -qx "frozen 0" $CG/cgroup.events &&
  journalctl -b -u agentbox-rootd -o cat | grep -q "qgroups consistent, writers thawed"'
check "  ... and 1/$NA limits again: a write past 64 MiB gets EDQUOT" 'e=$(runuser -u ag-$QA -- dd if=/dev/urandom of=$W/fill bs=1M count=200 conv=fsync 2>&1); echo "$e" | grep -aq "Disk quota exceeded" && [ $(stat -c %s $W/fill) -le $((64 << 20)) ]'
$A gate revoke --task QF$X >/dev/null; rm -f $W/fill /run/systemd/system/agentbox-rootd.service.d/50-gate-hold.conf
echo 3 > $Q/drop_subtree_threshold && btrfs subvolume delete $D/qg-gate >/dev/null && btrfs subvolume sync $D && systemctl daemon-reload
check "  ... threshold back to 3, the test subvolume gone, qgroups still consistent" '[ "$(cat $Q/drop_subtree_threshold)" = 3 ] && [ "$(cat $Q/inconsistent)" = 0 ]'
check "agent add $QB: the next N" 'ag add --name $QB && [ "$(f n)" = $((NA + 1)) ]'
NB=$(f n); UB=$((70000 + NB)); BB=$((0x70000000 + NB * 65536))
check "agent remove $QB (the newest): ok, retired" 'ag remove --name $QB && [ "$(f active)" = False ]'
check "  ... ag-$QB, its group, sub-ids, linger, drop-ins and processes are gone" '! getent passwd ag-$QB && ! getent group ag-$QB &&
  ! grep -q "^ag-$QB:" /etc/subuid /etc/subgid && [ ! -e /var/lib/systemd/linger/ag-$QB ] && [ ! -e /etc/systemd/system/user@$UB.service.d ] &&
  ! systemctl is-active -q user@$UB.service && ! pgrep -U $UB'
check "  ... its subvolumes moved to data/archive/agent-$NB, still in 1/$NB under 2/0" 'a=$D/archive/agent-$NB &&
  [ "$(stat -c "%i %u" $a/workspace $a/agent/storage $a/agent/session-home)" = "$(printf "256 $UB\n256 $UB\n256 $UB")" ] && [ ! -e $D/workspaces/$QB ] && [ ! -e $D/agents/$QB ] &&
  qg "$(qid $a/workspace)" parents | tr , "\n" | grep -qx 1/$NB && qg 1/$NB parents | tr , "\n" | grep -qx 2/0 && [ ! -e $M/control/xdg/$QB ]'
check "  ... its ids row stays, retired" 'python3 -c "import sqlite3,sys; c=sqlite3.connect(\"file:$M/rootd.db?mode=ro\", uri=True); exit(0 if c.execute(\"select name, state from ids where kind=\x27agent\x27 and n=?\", (int(sys.argv[1]),)).fetchone() == (sys.argv[2], \"retired\") else 1)" $NB $QB'
check "agent add $QC after removing $QB: a new N, so neither the uid nor the sub-id range is reused" 'ag add --name $QC && NC=$(f n) &&
  [ $NC = $((NB + 1)) ] && [ "$(f uid)" = $((70000 + NC)) ] && [ "$(st ag-$QC)" = "ag-$QC:$((0x70000000 + NC * 65536)):65536" ] &&
  ! grep -q ":$BB:" /etc/subuid /etc/subgid && ! getent passwd $UB'
NC=$(f n)
check "agent add $QB again: its name comes back with a new N, not $NB" 'ag add --name $QB && [ "$(f n)" = $((NC + 1)) ] && [ "$(id -u ag-$QB)" != $UB ]'
btrfs subvolume create $D/workspaces/$QC/nested >/dev/null
check "a nested subvolume in $QC's workspace: agent remove is refused NESTED_SUBVOLUME" '! ag remove --name $QC && grep -q "\"code\":\"NESTED_SUBVOLUME\"" /run/ag.json && grep -q "\"tainted\":true" /run/ag.json'
check "  ... $QC is untouched: user, workspace and the nested subvolume remain" 'getent passwd ag-$QC && [ -d $D/workspaces/$QC/nested ]'
check "  ... and taint.db has workspace:$QC#$NC tainted, keyed by N" 'taint "workspace:$QC#$NC" | grep -qx 1'
btrfs subvolume delete $D/workspaces/$QC/nested >/dev/null
check "  ... with it deleted by hand, agent remove $QC succeeds" 'ag remove --name $QC'
check "agent add $QC again: a new N" 'ag add --name $QC && [ "$(f n)" -gt $NC ]'
NC2=$(f n)
check "  ... its workspace subject workspace:$QC#$NC2 starts clean, while workspace:$QC#$NC stays tainted" '
  [ -z "$(taint "workspace:$QC#$NC2")" ] && [ "$(taint "workspace:$QC#$NC")" = 1 ] && [ -z "$(taint "workspace:$QC")" ]'
ag remove --name $QC >/dev/null
# #273: a rootd stop waits for the agent add in flight, and SIGTERM reaches rootd alone (KillMode=mixed), so the
# systemctl start of agentbox-accounts.service it waits for, held here 20 s, keeps running
QD=qd$X DR=/run/systemd/system/agentbox-accounts.service.d
mkdir -p $DR && printf '[Service]\nExecStartPre=/bin/sleep 20\n' > $DR/50-gate-slow.conf && systemctl daemon-reload
( $A agent add --name $QD > /run/qd.json 2>&1; echo $? > /run/qd.rc ) &
for i in $(seq 100); do [ "$(systemctl show -P ActiveState agentbox-accounts.service)" = activating ] && break; sleep 0.1; done
t0=$(date +%s)
( systemctl restart agentbox-rootd.service; echo $? > /run/qd-restart.rc ) &
for i in $(seq 150); do journalctl -u agentbox-rootd --since "@$t0" -o cat | grep -qF "stop: new requests get stopping" && break; sleep 0.1; done
t1=$(date +%s%N); $A agent list > /run/qd-list.json 2>&1; echo $? > /run/qd-list.rc; t2=$(date +%s%N)
wait
check "a rootd restart while agent add $QD waits for agentbox-accounts.service: the add ends ok, ag-$QD exists" '
  cat /run/qd.json; [ "$(cat /run/qd.rc)" = 0 ] && grep -q "\"ok\":true" /run/qd.json && getent passwd ag-$QD'
check "  ... and its audit RESULT says executed" 'id=$(python3 -c "import json; print(json.load(open(\"/run/qd.json\"))[\"opId\"])") &&
  cat $M/audit/seg-*.jsonl | grep -F "\"opId\":\"$id\"" | grep -F "\"type\":\"RESULT\"" | grep -qF "\"status\":\"executed\""'
check "  ... a request during the drain is refused \"stopping\" at once, nothing run" 'cat /run/qd-list.json; [ "$(cat /run/qd-list.rc)" != 0 ] &&
  grep -qF "\"reason\":\"stopping\"" /run/qd-list.json && [ $(( (t2 - t1) / 1000000 )) -lt 2000 ]'
check "  ... and the restart ends with rootd active" '[ "$(cat /run/qd-restart.rc)" = 0 ] && systemctl is-active -q agentbox-rootd.service'
rm -f $DR/50-gate-slow.conf; systemctl daemon-reload
check "  ... and agent remove $QD then goes through" 'ag remove --name $QD'
check "agent list shows every row, retired ones included" 'ag list && for n in $QA $QB $QC; do grep -q "\"name\":\"$n\"" /run/ag.json || exit 1; done'
cp /etc/subuid /run/subuid.ok
echo "evil:$((0x70000000)):65536" >> /etc/subuid
check "a foreign /etc/subuid entry inside the agentbox span: reconcile refuses" '! $A reconcile 2>/run/rec.err && grep -q "overlaps the agentbox sub-id span" /run/rec.err'
cp /run/subuid.ok /etc/subuid
check "  ... removed: reconcile passes and changes no sub-id line" '$A reconcile && cmp /etc/subuid /run/subuid.ok'
# what the reboot must bring back (/var/tmp survives it)
users > /var/tmp/accounts-gate.users && cat /etc/subuid /etc/subgid > /var/tmp/accounts-gate.subids
echo $QA > /var/tmp/accounts-gate.qa
failed # names each failed unit, with its journal, in the gate log
check "no failed units" '[ -z "$(systemctl --failed --no-legend --plain)" ]'
echo "fails=$fails"
EOF
  reboot_vm
  { echo "$PRELUDE"; cat <<'EOF'; } | guest
QA=$(cat /var/tmp/accounts-gate.qa) && UA=$(id -u ag-$QA)
check "after a reboot, reconcile brings back the same agent users and uids" '[ -s /var/tmp/accounts-gate.users ] && [ "$(users)" = "$(cat /var/tmp/accounts-gate.users)" ]'
check "  ... and the same /etc/subuid and /etc/subgid" '[ "$(cat /etc/subuid /etc/subgid)" = "$(cat /var/tmp/accounts-gate.subids)" ]'
check "  ... and the user manager of ag-$QA runs again (linger)" 'for i in $(seq 60); do systemctl is-active -q user@$UA.service && exit 0; sleep 1; done; exit 1'
check "  ... a rerun of reconcile changes nothing" 'a=$(users; cat /etc/subuid /etc/subgid) && $A reconcile && [ "$(users; cat /etc/subuid /etc/subgid)" = "$a" ]'
failed
check "  ... no failed units" '[ -z "$(systemctl --failed --no-legend --plain)" ]'
rm -f /var/tmp/accounts-gate.*
echo "fails=$fails"
EOF
  ;;
*) die "unknown stage $s (install or checks)" ;;
esac; done
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "accounts gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "accounts gate: all checks passed"

#!/bin/sh
# Week 3 gates for the disk reserve and packaged ntfy (PLAN.md row 3, ARCHITECTURE.md §2, §2.1, §3.2, §4.1, §6.1) on
# the local QEMU VM, arm64 UEFI, none mode.
#   hack/quota-ntfy-gate.sh [install|quota|ntfy ...]   default: all three, in order
# install  hack/gate.sh none: the unattended install and the release pipeline; firstboot's install.sh puts in the
#          ntfy package and agentbox-reconcile sets up quotas and ntfy.
# quota    full-mode quotas, 2/0 limited to the file system size minus max(10%, 4 GiB) over every fillable store,
#          control state and generations outside it, the CAS cap; reconcile is idempotent. An agent-data writer at its
#          1/N quota gets EDQUOT while system state keeps writing; so does a writer that fills 2/0 itself (its limit
#          lowered for the test), and the next reconcile restores the limit.
# ntfy     with no agentbox-firewall.service on the box, ntfy stays down. The gate then adds a stub firewall unit
#          (Appendix B's ntfy rules only; skipped once the real unit ships) and reboots: ntfy runs as _ntfy from the
#          packaged unit with the drop-in, ss shows only its Unix socket (no TCP or UDP listener), the socket dir is
#          setgid _ntfy:agentbox-notify, topic ACLs hold, rootd's refresh fills ntfy_dst4/6 with checked ntfy.sh answers
#          and _ntfy reaches only those. A stub agent unit (Requires= the firewall, ExecStartPre=+fwcheck, as an agent's
#          user@ drop-in) starts; with ntfy's unit set to any other user, or a ntfy_dst element rootd didn't add,
#          fwcheck fails and it can't start.
# PASS/FAIL lines go to .vm/quota-ntfy-gate.txt, command output to .vm/quota-ntfy-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install quota ntfy
OUT="$VM/quota-ntfy-gate.txt" LOG="$VM/quota-ntfy-gate.log"
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
# guest: run the check script on stdin as root; its PASS/FAIL lines land in OUT, a missing "fails=0" counts as a FAIL
guest() {
  root >"$VM/guest.out" 2>>"$LOG" || :
  while IFS= read -r l; do case $l in PASS*|FAIL*) log "$l" ;; *) echo "$l" >>"$LOG" ;; esac; done <"$VM/guest.out"
  grep -q '^fails=' "$VM/guest.out" || log "FAIL the check block on the VM did not finish (see $LOG)"
}
# The guest-side helpers every check block starts with. qg ID FIELD reads one qgroup field from btrfs's JSON.
PRELUDE='fails=0
check() { if (eval "$2") >>/tmp/gate-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
M=/var/lib/agentbox A=$M/current/bin/agentbox
qg() { btrfs --format=json qgroup show -p -r -e $M | python3 -c "import json,sys; r=[q for q in json.load(sys.stdin)[\"qgroup-show\"] if q[\"qgroupid\"]==sys.argv[1]]; v=r[0][sys.argv[2]] if r else \"absent\"; print(\",\".join(v) if isinstance(v,list) else v)" "$1" "$2"; }
qid() { echo "0/$(btrfs inspect-internal rootid "$1")"; }
S=$(( $(stat -f -c %b $M) * $(stat -f -c %S $M) )); R=$((S / 10)); [ $R -ge 4294967296 ] || R=4294967296
limits() { btrfs --format=json qgroup show -p -r -e $M | python3 -c "import json,sys; [print(q[\"qgroupid\"], q[\"max_referenced\"], q[\"max_exclusive\"], sorted(q[\"parents\"])) for q in json.load(sys.stdin)[\"qgroup-show\"]]"; }
'

for s; do case $s in
install)
  hack/gate.sh none >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-none.txt"
  log "PASS install: hack/gate.sh none (install, release pipeline, firstboot, reconcile, no failed units)" ;;
quota)
  up
  { echo "$PRELUDE"; cat <<'EOF'; } | guest
check "btrfs quotas on, full (qgroup) mode, not simple" 'btrfs quota status $M | grep -Eq "^ *Mode: *qgroup "'
check "2/0 exists, max referenced = fs size - max(10%, 4 GiB) = $((S - R))" '[ "$(qg 2/0 max_referenced)" = $((S - R)) ]'
for p in state memory cas git data data/images /srv; do case $p in /*) ;; *) p=$M/$p ;; esac
  check "$p is a subvolume under 2/0" '[ "$(stat -c %i $p)" = 256 ] && qg "$(qid $p)" parents | tr , "\n" | grep -qx 2/0'
done
for p in $M /; do check "$p (control state / the generation) is outside 2/0" '! qg "$(qid $p)" parents | tr , "\n" | grep -qx 2/0'; done
check "cas/ max exclusive = 10% of the pool ($((S / 10)))" '[ "$(qg "$(qid $M/cas)" max_exclusive)" = $((S / 10)) ]'
check "reconcile is idempotent: a rerun changes no limit or parent" 'a=$(limits) && $A reconcile && [ "$(limits)" = "$a" ]'
# an agent-data writer at its quota: a workspace subvolume in a 1/N under 2/0, as agent.add will make it
W=$M/data/workspaces/gate
mkdir -p $M/data/workspaces && btrfs subvolume create $W >/dev/null && chown nobody $W
{ [ "$(qg 1/999 qgroupid)" = 1/999 ] || btrfs qgroup create 1/999 $M; } && btrfs qgroup assign "$(qid $W)" 1/999 $M && btrfs qgroup assign 1/999 2/0 $M &&
  btrfs qgroup limit -e 64M 1/999 $M && btrfs quota rescan -W $M
check "an agent writer (uid nobody) at its 64 MiB 1/N quota gets EDQUOT" 'e=$(runuser -u nobody -- dd if=/dev/urandom of=$W/fill bs=1M count=200 conv=fsync 2>&1); echo "$e" | grep -aq "Disk quota exceeded" && [ $(stat -c %s $W/fill) -le $((64 << 20)) ]'
check "  ... and keeps getting it" '! runuser -u nobody -- dd if=/dev/urandom of=$W/more bs=1M count=8 conv=fsync'
check "  ... while system state (outside 2/0) still writes 100 MiB" 'mkdir -p $M/audit && dd if=/dev/urandom of=$M/audit/gate-fill bs=1M count=100 conv=fsync && [ $(stat -c %s $M/audit/gate-fill) = $((100 << 20)) ]'
# the reserve itself: 2/0 lowered to 64 MiB above its current use, then filled by a store with no limit of its own
r=$(qg 2/0 referenced); btrfs qgroup limit $((r + (64 << 20))) 2/0 $M
check "a writer into data/images (no own limit) that fills 2/0 gets EDQUOT" 'e=$(dd if=/dev/urandom of=$M/data/images/gate-fill bs=1M count=200 conv=fsync 2>&1); echo "$e" | grep -aq "Disk quota exceeded"'
check "  ... while system state still writes 128 MiB, more than 2/0 had left" 'dd if=/dev/urandom of=$M/audit/gate-fill2 bs=1M count=128 conv=fsync && [ $(stat -c %s $M/audit/gate-fill2) = $((128 << 20)) ]'
check "the next reconcile restores 2/0's limit" '$A reconcile && [ "$(qg 2/0 max_referenced)" = $((S - R)) ]'
rm -f $M/audit/gate-fill $M/audit/gate-fill2 $M/data/images/gate-fill; rmdir $M/audit 2>/dev/null || :
btrfs subvolume delete $W >/dev/null && btrfs subvolume sync $M && btrfs qgroup destroy 1/999 $M && rmdir $M/data/workspaces
btrfs qgroup clear-stale $M >/dev/null 2>&1 || :
check "reconcile still passes after the cleanup" '$A reconcile'
echo "fails=$fails"
EOF
  ;;
ntfy)
  up
  { echo "$PRELUDE"; cat <<'EOF'; } | guest
check "ntfy 2.11 from the archive; _ntfy from its sysusers entry" 'dpkg -s ntfy | grep -q "^Version: 2\.11\." && getent passwd _ntfy && grep -Eq "^u\s+_ntfy\s" /usr/lib/sysusers.d/ntfy.conf'
check "ntfy enabled, but down with no agentbox-firewall.service (Requires=), and not failed" '[ "$(systemctl is-enabled ntfy)" = enabled ] && { systemctl cat agentbox-firewall.service || [ "$(systemctl is-active ntfy)" = inactive ]; }'
check "reconcile is ordered before ntfy" 'systemctl show -P Before agentbox-reconcile.service | grep -qw ntfy.service'
check "drop-in: Requires= and After= agentbox-firewall.service, ExecStartPre=+fwcheck" 'systemctl show -P Requires ntfy | grep -qw agentbox-firewall.service && systemctl show -P After ntfy | grep -qw agentbox-firewall.service && systemctl show -P ExecStartPre ntfy | grep -q "agentbox fwcheck"'
for f in /etc/ntfy/server.yml /etc/tmpfiles.d/agentbox-ntfy.conf /etc/systemd/system/ntfy.service.d/50-agentbox.conf; do
  check "$f is root:root 0644" '[ "$(stat -c "%U:%G %a" $f)" = "root:root 644" ]'; done
check "server.yml: no HTTP listener, Unix socket 0660, deny-all with an auth-file, upstream with a base-url" 'f=/etc/ntfy/server.yml; grep -qx "listen-http: \"-\"" $f && grep -qx "listen-unix: /run/ntfy/ntfy.sock" $f && grep -qx "listen-unix-mode: 0660" $f && grep -qx "auth-default-access: deny-all" $f && grep -qx "auth-file: /var/lib/ntfy/user.db" $f && grep -qx "upstream-base-url: \"https://ntfy.sh\"" $f && grep -q "^base-url: \"https://" $f'
check "agentbox-notify group; notify token root-only" 'getent group agentbox-notify && [ "$(stat -c "%U %a" $M/control/ntfy/notify.token)" = "root 600" ]'
echo "fails=$fails"
EOF
  # The stub firewall stands in for the firewall area's agentbox-firewall.service: Appendix B's ntfy rules only.
  root >>"$LOG" 2>&1 <<'EOF'
systemctl cat agentbox-firewall.service >/dev/null 2>&1 && exit 0
mkdir -p /etc/agentbox-gate
cat > /etc/agentbox-gate/ntfy-fw.nft <<'NFT'
add table inet agentbox
add chain inet agentbox output { type filter hook output priority filter; policy accept; }
flush chain inet agentbox output
table inet agentbox {
  set ntfy_dst4 { typeof ip daddr . tcp dport; flags timeout; }
  set ntfy_dst6 { typeof ip6 daddr . tcp dport; flags timeout; }
  set private4 { typeof ip daddr; flags interval; elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
                 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/3 } }
  set private6 { typeof ip6 daddr; flags interval; elements = { ::/127, ::ffff:0:0/96, 64:ff9b:1::/48, 100::/64, 2001:db8::/32, fc00::/7,
                 fe80::/10, fec0::/10, ff00::/8 } }
  chain output {
    type filter hook output priority filter; policy accept;
    ct direction original ct state established accept
    meta skuid "_ntfy" ip daddr 127.0.0.53 meta l4proto { udp, tcp } th dport 53 accept
    meta skuid "_ntfy" fib daddr type { local, broadcast, multicast, anycast } counter drop
    meta skuid "_ntfy" ip daddr @private4 counter drop
    meta skuid "_ntfy" ip6 daddr @private6 counter drop
    meta skuid "_ntfy" ip daddr . tcp dport @ntfy_dst4 accept
    meta skuid "_ntfy" ip6 daddr . tcp dport @ntfy_dst6 accept
    meta skuid "_ntfy" counter drop
  }
}
NFT
printf '%s\n' '# hack/quota-ntfy-gate.sh stub: Appendix B ntfy rules only, until the firewall area ships this unit' '[Unit]' \
  'Description=agentbox firewall (gate stub)' '[Service]' 'Type=oneshot' 'RemainAfterExit=yes' \
  'ExecStart=/usr/sbin/nft -f /etc/agentbox-gate/ntfy-fw.nft' '[Install]' 'WantedBy=multi-user.target' \
  > /etc/systemd/system/agentbox-firewall.service
printf '%s\n' '# hack/quota-ntfy-gate.sh stub for an agent unit (an agent user@ drop-in has the same three lines, Appendix C)' \
  '[Unit]' 'Requires=agentbox-firewall.service agentbox-reconcile.service' 'After=agentbox-firewall.service agentbox-reconcile.service' \
  '[Service]' 'Type=oneshot' 'RemainAfterExit=yes' 'ExecStartPre=+/var/lib/agentbox/current/bin/agentbox fwcheck' 'ExecStart=/bin/true' \
  '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/agentbox-agentstub.service
systemctl daemon-reload && systemctl enable agentbox-firewall.service agentbox-agentstub.service
EOF
  reboot_vm
  { echo "$PRELUDE"; cat <<'EOF'; } | guest
check "boot finishes with ntfy and the stub agent unit up" '[ "$(timeout 600 systemctl is-system-running --wait)" = running ] && systemctl is-active ntfy agentbox-agentstub'
check "ntfy's unit runs as _ntfy, and so does its process (all four uids)" '[ "$(systemctl show -P User ntfy)" = _ntfy ] && u=$(id -u _ntfy) && grep -Eq "^Uid:\s+$u\s+$u\s+$u\s+$u$" /proc/$(systemctl show -P MainPID ntfy)/status'
check "ss: ntfy has no TCP or UDP listener" '! ss -Htulnp | grep -q "\"ntfy\""'
check "ss: ntfy's only listener is /run/ntfy/ntfy.sock" '[ "$(ss -Hxlp | grep "\"ntfy\"" | awk "{print \$5}")" = /run/ntfy/ntfy.sock ]'
check "socket dir _ntfy:agentbox-notify 2750, socket 0660 with the dir's group" '[ "$(stat -c "%U:%G %a" /run/ntfy)" = "_ntfy:agentbox-notify 2750" ] && [ "$(stat -c "%U:%G %a %F" /run/ntfy/ntfy.sock)" = "_ntfy:agentbox-notify 660 socket" ]'
check "/var/lib/ntfy _ntfy:_ntfy 0750, user.db owned by _ntfy" '[ "$(stat -c "%U:%G %a" /var/lib/ntfy)" = "_ntfy:_ntfy 750" ] && [ "$(stat -c %U /var/lib/ntfy/user.db)" = _ntfy ]'
check "a uid outside agentbox-notify can't connect to the socket" '! runuser -u nobody -- curl -s -m 5 --unix-socket /run/ntfy/ntfy.sock http://localhost/v1/health'
T=$(cat $M/control/ntfy/notify.token)
c() { curl -s -o /dev/null -w "%{http_code}" -m 10 --unix-socket /run/ntfy/ntfy.sock "$@"; }
check "ACL: anonymous publish refused (deny-all)" '[ "$(c -d gate http://localhost/agentbox-gate)" = 403 ]'
check "ACL: agentbox-notify publishes to agentbox-*" '[ "$(c -H "Authorization: Bearer $T" -d gate http://localhost/agentbox-gate)" = 200 ]'
check "ACL: agentbox-notify can't publish outside agentbox-*" '[ "$(c -H "Authorization: Bearer $T" -d gate http://localhost/other)" = 403 ]'
check "ACL: agentbox-notify is write-only (no read)" '[ "$(c -H "Authorization: Bearer $T" "http://localhost/agentbox-gate/json?poll=1")" = 403 ]'
check "ntfy_dst refresh timer enabled and ran" '[ "$(systemctl is-enabled agentbox-ntfy-dst.timer)" = enabled ] && [ "$(systemctl show -P Result agentbox-ntfy-dst.service)" = success ] && [ "$(systemctl show -P ExecMainStatus agentbox-ntfy-dst.service)" = 0 ] && [ -s /var/lib/agentbox/resolve/ntfy_dst.json ]'
check "ntfy_dst4/6 hold exactly resolved's ntfy.sh A (and with an IPv6 default route, AAAA) answers on :443, each with a 10 min timeout" 'systemctl start agentbox-ntfy-dst.service &&
  want=$({ resolvectl query --legend=no -t A ntfy.sh; resolvectl query --legend=no -t AAAA ntfy.sh; } | awk -v v6="$(ip -6 route show default)" "\$2 == \"IN\" && (v6 != \"\" || \$3 == \"A\") {print \$4}" | sort) && [ -n "$want" ] &&
  got=$(nft -j list set inet agentbox ntfy_dst4; nft -j list set inet agentbox ntfy_dst6) &&
  [ "$(echo "$got" | python3 -c "import json,sys; d=sys.stdin.read().replace(\"}{\",\"}\n{\"); print(\"\n\".join(sorted(e[\"elem\"][\"val\"][\"concat\"][0] for l in d.splitlines() for o in json.loads(l)[\"nftables\"] if \"set\" in o for e in o[\"set\"].get(\"elem\",[]) if e[\"elem\"][\"val\"][\"concat\"][1]==443 and e[\"elem\"][\"timeout\"]==600)))")" = "$want" ]'
check "_ntfy reaches ntfy.sh:443 through ntfy_dst" 'runuser -u _ntfy -- curl -s -m 10 -o /dev/null https://ntfy.sh/v1/health'
check "_ntfy can't reach any other host (1.1.1.1:443)" '! runuser -u _ntfy -- curl -s -m 5 -o /dev/null https://1.1.1.1/'
check "fwcheck passes" '$A fwcheck'
nft add element inet agentbox ntfy_dst4 "{ 1.1.1.1 . 443 timeout 10m }"
check "a ntfy_dst element rootd didn't add: fwcheck fails" '! $A fwcheck 2>&1 && $A fwcheck 2>&1 | grep -q "ntfy_dst4 holds 1.1.1.1 . 443"'
check "  ... and the agent unit can't start" '! systemctl restart agentbox-agentstub'
nft delete element inet agentbox ntfy_dst4 "{ 1.1.1.1 . 443 }"; systemctl reset-failed
check "  ... removed: the agent unit starts" 'systemctl restart agentbox-agentstub'
mkdir -p /run/systemd/system/ntfy.service.d && printf "[Service]\nUser=nobody\n" > /run/systemd/system/ntfy.service.d/90-gate.conf && systemctl daemon-reload
check "ntfy's unit as uid nobody: fwcheck fails" '$A fwcheck 2>&1 | grep -q "ntfy.service runs as user \"nobody\", not _ntfy"'
check "  ... and the agent unit can't start" '! systemctl restart agentbox-agentstub'
check "  ... and ntfy itself can't start" '! systemctl restart ntfy && [ "$(systemctl show -P MainPID ntfy)" = 0 ]'
rm /run/systemd/system/ntfy.service.d/90-gate.conf; systemctl daemon-reload; systemctl reset-failed
check "  ... back to _ntfy: ntfy and the agent unit start" 'systemctl restart ntfy && systemctl restart agentbox-agentstub'
check "no failed units" '[ -z "$(systemctl --failed --no-legend --plain)" ]'
echo "fails=$fails"
EOF
  ;;
*) die "unknown scenario $s (install, quota or ntfy)" ;;
esac; done
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "quota-ntfy gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "quota-ntfy gate: all checks passed"

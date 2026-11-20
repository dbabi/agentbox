#!/bin/sh
# Firewall gates (PLAN.md row 3; ARCHITECTURE.md §6.1, Appendix B) on the local arm64 QEMU VM.
#   hack/fw-gate.sh [install] [checks]   default: both
# install  hack/gate.sh none: the unattended install and its gates; firstboot installs this checkout's release (make
#          release, install.sh, systemd/), so agentbox-firewall.service and the stub come from the real install path.
# checks   on the installed box, as root:
#          - the firewall loads at boot, fwcheck passes, and the agent stand-in (agentbox-agent-stub.service:
#            Requires=agentbox-firewall.service, ExecStartPre=+agentbox fwcheck) starts
#          - each alteration (a rule inserted or deleted, a static element removed, an element rootd never recorded in a
#            dst set or port_allow, ntfy under another uid, the reserved-ports sysctl, nftables.service unmasked) keeps
#            the stand-in from starting; a hooked extra chain fails the firewall load itself
#          - reload, restart and `fw load` keep every set's elements, and an element's expiry keeps running
#          - 200 root connections to 127.0.0.1:43100 succeed; other uids, other reserved ports and ::1 get a reset
#          - a broker uid reaches only the address and port in its own dst set (dropped for the rest, private ranges and
#            DNS included); a confined uid reaches nothing
#          - a keys flow survives its element's expiry (conntrack), while a new connection is refused
#          - `nft flush ruleset`: within 60 s the health timer's fwcheck alerts and the table is back, sets refilled
#          - after a reboot: the sets are back and the stand-in starts at boot, with no failed unit
# rootd does not exist yet. A fixture unit stands in for its start step (`agentbox fw refill`, which rootd runs before
# READY=1), with Requires= on the firewall like rootd, and a sqlite3-made rootd.db holds the rows rootd would write.
# Checks print PASS/FAIL to .vm/fw-gate.txt, command output goes to .vm/fw-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
mkdir -p "$VM"
OUT="$VM/fw-gate.txt" LOG="$VM/fw-gate.log"
[ $# -gt 0 ] || set -- install checks
! command -v caffeinate >/dev/null || { caffeinate -i -w $$ & }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT"; }
die() { log "ABORT $*"; exit 1; }
# vmrun: stdin is a script; the VM saves it and runs it as root with stdin from /dev/null, so no command in it can
# read the rest of the script
vmrun() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -c "cat > /var/tmp/fw-gate-phase.sh && sh /var/tmp/fw-gate-phase.sh </dev/null"'; }
root() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s'; }
bootid() { hack/vm.sh ssh cat /proc/sys/kernel/random/boot_id 2>/dev/null || :; }
running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }
wait_boot() { end=$(( $(date +%s) + $2 ))
  while :; do b=$(bootid); [ -n "$b" ] && [ "$b" != "$1" ] && return 0; [ "$(date +%s)" -lt $end ] || return 1; sleep 5; done; }

# prelude: check() and helpers for every in-VM phase
prelude() { cat <<'EOF'
set -u
fails=0 A=/var/lib/agentbox/current/bin/agentbox DB=/var/lib/agentbox/rootd.db L=/var/tmp/fw-gate.log
check() { echo "== $1" >>$L; if (eval "$2") >>$L 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
# as USER HOST PORT [udp]: what a connect (and, for udp, a send) by USER gets: ok, EPERM, ECONNREFUSED, ...
as() { u=$1; shift; setpriv --reuid="$u" --regid="$(id -g "$u" 2>/dev/null || echo "$u")" --clear-groups python3 /var/tmp/conn.py "$@"; }
elems() { nft -j list set inet agentbox "$1" | python3 -c 'import json,sys
for o in json.load(sys.stdin)["nftables"]:
  for e in o.get("set",{}).get("elem",[]):
    print(json.dumps(e["elem"]["val"] if isinstance(e,dict) and "elem" in e else e))'; }
# dropped USER HOST PORT [udp]: nft dropped it. A dropped TCP SYN is retransmitted, so connect ends in a timeout, not
# EPERM (a dropped UDP send gets EPERM); the chain's drop counters must have moved too
drops() { nft list chain inet agentbox output | grep -o 'packets [0-9]*' | awk '{s += $2} END {print s + 0}'; }
dropped() { b=$(drops); r=$(as "$@"); a=$(drops); echo "$* -> $r, drop counters $b -> $a"
  case $r in EPERM|TimeoutError) [ "$a" -gt "$b" ] ;; *) false ;; esac; }
expires() { nft -j list set inet agentbox "$1" | grep -o '"expires": [0-9]*' | grep -o '[0-9]*$'; }
IP=$(cat /var/tmp/fw-ip 2>/dev/null || :)
EOF
}

phase1() { cat <<'EOF'
: >$L
IP=$(getent ahostsv4 ports.ubuntu.com | awk 'NR == 1 {print $1}'); echo "$IP" > /var/tmp/fw-ip
cat > /var/tmp/conn.py <<'P'
import errno, socket, sys
host, port = sys.argv[1], int(sys.argv[2])
udp = len(sys.argv) > 3
s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect((host, port))
    if udp:
        s.send(b"x")
    print("ok")
except OSError as e:
    print(errno.errorcode.get(e.errno, "") if e.errno else type(e).__name__)
P
cat > /var/tmp/listen.py <<'P'
import socket, threading
def serve(fam, addr, port):
    s = socket.socket(fam)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(512)
    while True:
        c, _ = s.accept()
        c.close()
for a in [(socket.AF_INET, "127.0.0.1", 43100), (socket.AF_INET, "127.0.0.1", 43101), (socket.AF_INET6, "::1", 43100)]:
    threading.Thread(target=serve, args=a, daemon=True).start()
threading.Event().wait()
P
cat > /var/tmp/many.py <<'P'
import socket
n = 0
for i in range(200):
    s = socket.create_connection(("127.0.0.1", 43100), timeout=5)
    p = s.getsockname()[1]
    assert not 43000 <= p <= 45999, "ephemeral port %d in the reserved range" % p
    s.close()
    n += 1
print(n)
P
check "boot: agentbox-firewall.service active, /etc/nftables.d/agentbox.nft and 60-agentbox.conf written" 'systemctl is-active agentbox-firewall.service && test -s /etc/nftables.d/agentbox.nft && grep -qx "net.ipv4.ip_local_reserved_ports = 43000-45999" /etc/sysctl.d/60-agentbox.conf'
check "boot: no failed units" '[ -z "$(systemctl --failed --no-legend --plain)" ]'
check "nftables.service masked; ntfy.service User=_ntfy; ip_local_reserved_ports covers 43000-45999" '[ "$(systemctl is-enabled nftables.service)" = masked ] && [ "$(systemctl show -p User --value ntfy.service)" = _ntfy ] && grep -q 43000-45999 /proc/sys/net/ipv4/ip_local_reserved_ports'
check "static sets as Appendix B: confined, private4, private6" 'nft list set inet agentbox confined | grep -qF "elements = { 70001-70999, 71001-71999, 1879048192-2013265919 }" && [ "$(elems private4 | wc -l)" = 13 ] && [ "$(elems private6 | wc -l)" = 9 ]'
check "fwcheck passes on a box with no rootd.db" '[ ! -e $DB ] && $A fwcheck'
check "the agent stand-in starts while the firewall is intact" 'systemctl start agentbox-agent-stub.service && systemctl is-active agentbox-agent-stub.service && systemctl stop agentbox-agent-stub.service'
check "the test address $IP (ports.ubuntu.com) is public: not in private4" '[ -n "$IP" ] && ! nft get element inet agentbox private4 "{ $IP }"'

# the rows rootd would have written before adding each element (rootd.db set_elements, Appendix E)
now=$(date +%s)
sqlite3 $DB "CREATE TABLE set_elements(set_name TEXT NOT NULL, element TEXT NOT NULL, expires_at INTEGER, PRIMARY KEY(set_name, element)) STRICT;
  INSERT INTO set_elements VALUES ('port_allow', '0 . 43100', NULL), ('proxy_dst4', '$IP . 80', $now + 600);"
cat > /etc/systemd/system/agentbox-rootd-standin.service <<'U'
[Unit]
Description=rootd stand-in (fw-gate fixture): rootd's start step, agentbox fw refill
Requires=agentbox-firewall.service
After=agentbox-firewall.service
# the gate restarts the firewall a dozen times in a minute; the default start limit would leave the refill undone
StartLimitIntervalSec=0
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/var/lib/agentbox/current/bin/agentbox fw refill
[Install]
WantedBy=multi-user.target
U
mkdir -p /etc/systemd/system/agentbox-agent-stub.service.d
printf '%s\n' '[Unit]' 'Requires=agentbox-rootd-standin.service' 'After=agentbox-rootd-standin.service' > /etc/systemd/system/agentbox-agent-stub.service.d/gate.conf
systemctl daemon-reload; systemctl enable agentbox-rootd-standin.service >>$L 2>&1
check "rootd's refill fills port_allow and proxy_dst4 from rootd.db, with the remaining timeout; fwcheck passes" 'systemctl start agentbox-rootd-standin.service && [ "$(elems port_allow)" = "{\"concat\": [0, 43100]}" ] && [ "$(elems proxy_dst4)" = "{\"concat\": [\"$IP\", 80]}" ] && [ "$(expires proxy_dst4)" -le 600 ] && $A fwcheck'

# Firewall altered: agents can't start. The health timer would repair in between, so it waits.
systemctl stop agentbox-health.timer
# restore: what fwcheck --repair does; the refill runs in the restart Requires= queues after the firewall's
restore() { systemctl reset-failed agentbox-agent-stub.service 2>/dev/null; systemctl restart agentbox-firewall.service || return 1
  for i in 1 2 3 4 5 6 7 8 9 10; do $A fwcheck && return 0; sleep 1; done; return 1; }
# $2 runs in braces: a redirection inside it (echo 0 > /proc/...) must not be overridden by the >/dev/null
altered() { t=$(date +%s); sleep 1
  check "altered ($1): fwcheck refuses, the agent stand-in does not start" "{ $2; }"' >/dev/null && ! systemctl start agentbox-agent-stub.service && ! systemctl is-active agentbox-agent-stub.service && journalctl -u agentbox-agent-stub.service --since @'$t' -o cat | grep -q "agentbox: fwcheck: "'
  check "altered ($1): a firewall restart repairs it, the stand-in starts" "${3:-:} && restore && systemctl start agentbox-agent-stub.service && systemctl stop agentbox-agent-stub.service"; }
altered "a rule inserted ahead of the confined drop" 'nft insert rule inet agentbox output meta skuid 70001 accept'
altered "the confined drop deleted" 'nft delete rule inet agentbox output handle $(nft -a list chain inet agentbox output | awk "/@confined/ {print \$NF}")'
altered "70001-70999 removed from the static confined set" "nft delete element inet agentbox confined '{ 70001-70999 }'"
altered "192.168.0.0/16 removed from private4" "nft delete element inet agentbox private4 '{ 192.168.0.0/16 }'"
altered "an answer rootd never recorded in proxy_dst4" "nft add element inet agentbox proxy_dst4 '{ 9.9.9.9 . 443 timeout 10m }'"
altered "a (uid . port) tuple rootd never recorded in port_allow" "nft add element inet agentbox port_allow '{ 65534 . 43100 }'"
altered "ntfy.service under another uid" 'mkdir -p /run/systemd/system/ntfy.service.d && printf "[Service]\nUser=nobody\n" > /run/systemd/system/ntfy.service.d/gate.conf && systemctl daemon-reload' 'rm -r /run/systemd/system/ntfy.service.d && systemctl daemon-reload'
altered "ip_local_reserved_ports cleared" 'echo 0 > /proc/sys/net/ipv4/ip_local_reserved_ports'
altered "nftables.service unmasked" 'systemctl unmask nftables.service' 'systemctl mask nftables.service'
check "a table with an extra hooked chain fails the firewall load itself (fail closed); deleting it restores" 'nft add chain inet agentbox evil "{ type filter hook output priority -10; policy accept; }" && ! systemctl restart agentbox-firewall.service && ! systemctl is-active agentbox-firewall.service && journalctl -u agentbox-firewall.service -n 20 -o cat | grep -q "stateless hash" && nft delete chain inet agentbox evil && systemctl reset-failed && restore'

# Reload, restart and fw load keep the sets
p=$(elems port_allow) d=$(elems proxy_dst4) e1=$(expires proxy_dst4)
check "reload, restart and fw load keep port_allow and proxy_dst4; the element's expiry keeps running" 'systemctl reload agentbox-firewall.service && systemctl restart agentbox-firewall.service && $A fw load && [ "$(elems port_allow)" = "$p" ] && [ "$(elems proxy_dst4)" = "$d" ] && [ -n "$p" ] && [ -n "$d" ] && [ "$(expires proxy_dst4)" -le "$e1" ] && $A fwcheck'
check "after the reloads, the agent stand-in starts" 'systemctl start agentbox-agent-stub.service && systemctl is-active agentbox-agent-stub.service'

# Reserved loopback ports
python3 /var/tmp/listen.py >>$L 2>&1 & LP=$!; sleep 2
check "200 root loopback connections to 127.0.0.1:43100 all succeed" '[ "$(python3 /var/tmp/many.py)" = 200 ]'
check "uid nobody to 127.0.0.1:43100 (no port_allow tuple): reset" '[ "$(as nobody 127.0.0.1 43100)" = ECONNREFUSED ]'
check "root to 127.0.0.1:43101 (listening, not in port_allow): reset" '[ "$(python3 /var/tmp/conn.py 127.0.0.1 43101)" = ECONNREFUSED ]'
check "root to [::1]:43100 (listening): reset" '[ "$(python3 /var/tmp/conn.py ::1 43100)" = ECONNREFUSED ]'
kill $LP

# A broker reaches only what rootd put in its own set
check "agentbox-proxy reaches $IP:80 (in proxy_dst4)" '[ "$(as agentbox-proxy $IP 80)" = ok ]'
check "agentbox-proxy can't reach $IP:443 (port not in its set): dropped" 'dropped agentbox-proxy $IP 443'
check "agentbox-keys and agentbox-git can't reach $IP:80 (not in their sets): dropped" 'dropped agentbox-keys $IP 80 && dropped agentbox-git $IP 80'
check "agentbox-proxy can't reach 1.1.1.1:443 (an IP rootd never resolved): dropped" 'dropped agentbox-proxy 1.1.1.1 443'
check "agentbox-proxy can't reach 10.0.2.2:22 (private4) or DNS on 127.0.0.53:53 (local): dropped" 'dropped agentbox-proxy 10.0.2.2 22 && dropped agentbox-proxy 127.0.0.53 53 udp'
check "a confined uid (70001) can't reach $IP:80: dropped" 'dropped 70001 $IP 80'
check "root still reaches $IP:80 (only agentbox uids are confined)" '[ "$(python3 /var/tmp/conn.py $IP 80)" = ok ]'

# A long broker flow survives its element's expiry: the established accept comes before the set checks
sqlite3 $DB "INSERT INTO set_elements VALUES ('keys_dst4', '$IP . 80', $(date +%s) + 5);"
systemctl restart agentbox-rootd-standin.service
cat > /var/tmp/flow.py <<'P'
import socket, sys, time
s = socket.create_connection((sys.argv[1], 80), timeout=10)
time.sleep(10)
s.sendall(b"HEAD / HTTP/1.1\r\nHost: ports.ubuntu.com\r\nConnection: close\r\n\r\n")
print(s.recv(64).split(b"\r\n")[0].decode())
P
setpriv --reuid=agentbox-keys --regid="$(id -g agentbox-keys)" --clear-groups python3 /var/tmp/flow.py $IP > /var/tmp/flow.out 2>>$L & FP=$!
sleep 8
check "keys_dst4's element for $IP:80 expired (5 s); a new keys connection is dropped" '[ -z "$(elems keys_dst4)" ] && dropped agentbox-keys $IP 80'
wait $FP || :
check "the keys flow opened before the expiry still gets its HTTP answer (ct established)" 'grep -q "^HTTP/1.1 " /var/tmp/flow.out'
sqlite3 $DB "DELETE FROM set_elements WHERE set_name = 'keys_dst4';"

# nft flush ruleset: the health timer's fwcheck alerts and restores within 60 s
systemctl stop agentbox-agent-stub.service; systemctl start agentbox-health.timer; sleep 2
t0=$(date +%s); nft flush ruleset; t1=0
for i in $(seq 90); do nft list table inet agentbox >/dev/null 2>&1 && { t1=$(date +%s); break; }; sleep 1; done
echo "flush at $t0, table back at $t1: $((t1 - t0)) s" >>$L
check "nft flush ruleset: the table is back within 60 s ($((t1 - t0)) s)" '[ $t1 -gt 0 ] && [ $((t1 - t0)) -le 60 ]'
sleep 5
check "nft flush ruleset: fwcheck alerted, restarted the firewall, and the refill restored rootd's sets" 'journalctl -u agentbox-health.service --since @$t0 -o cat | grep -q "agentbox: ALERT: firewall altered: nft list table inet agentbox" && journalctl -u agentbox-health.service --since @$t0 -o cat | grep -q "agentbox: firewall restored" && [ "$(elems port_allow)" = "$p" ] && [ "$(elems proxy_dst4)" = "$d" ] && $A fwcheck'
check "after the repair, the agent stand-in starts" 'systemctl start agentbox-agent-stub.service && systemctl is-active agentbox-agent-stub.service'

# for the reboot: a fresh answer, and the stand-in starts at boot like an agent's user manager
sqlite3 $DB "UPDATE set_elements SET expires_at = $(date +%s) + 600 WHERE set_name = 'proxy_dst4';"
ln -sf ../agentbox-agent-stub.service /etc/systemd/system/multi-user.target.wants/agentbox-agent-stub.service
systemctl reset-failed
echo "fails=$fails"
EOF
}

phase2() { cat <<'EOF'
echo "== after reboot" >>$L
check "reboot: firewall, rootd stand-in and agent stand-in active; no failed units" '[ "$(systemctl is-system-running --wait)" = running ] && systemctl is-active agentbox-firewall.service agentbox-rootd-standin.service agentbox-agent-stub.service'
check "reboot: the static sets are loaded and rootd's sets are back from rootd.db" 'nft list set inet agentbox confined | grep -qF 70001-70999 && [ "$(elems private4 | wc -l)" = 13 ] && [ "$(elems port_allow)" = "{\"concat\": [0, 43100]}" ] && [ "$(elems proxy_dst4)" = "{\"concat\": [\"$IP\", 80]}" ]'
check "reboot: fwcheck passes; agentbox-proxy reaches $IP:80 and nothing else" '$A fwcheck && [ "$(as agentbox-proxy $IP 80)" = ok ] && dropped agentbox-proxy 1.1.1.1 443'
check "reboot: the agent stand-in's own fwcheck ran and passed at boot" 'journalctl -b -u agentbox-agent-stub.service -o cat | grep -q "Started agentbox-agent-stub.service\|Started agentbox agent stand-in" && ! journalctl -b -u agentbox-agent-stub.service -o cat | grep -q "agentbox: fwcheck: "'
echo "fails=$fails"
EOF
}

sc_install() {
  hack/gate.sh none >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-none.txt"
  log "PASS hack/gate.sh none: install gates, and firstboot installed this checkout's release"
}

sc_checks() {
  running || { hack/vm.sh boot >>"$LOG" 2>&1 & }
  wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"
  echo 'systemctl is-system-running --wait' | root >>"$LOG" 2>&1 || :
  { prelude; phase1; } | vmrun | tee -a "$OUT"
  old=$(bootid)
  echo 'systemctl reboot' | root >/dev/null 2>&1 || :
  wait_boot "$old" 900 || die "no SSH after the reboot"
  { prelude; phase2; } | vmrun | tee -a "$OUT"
  u="-u agentbox-firewall.service -u agentbox-health.service -u agentbox-agent-stub.service -u agentbox-rootd-standin.service"
  echo "cat /var/tmp/fw-gate.log; for b in -1 0; do journalctl -b \$b --no-pager -o short-iso $u; done" | root >>"$LOG" 2>&1 || :
  echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
  while running; do sleep 2; done
}

: >"$LOG"
[ "$1" != install ] || : >"$OUT"
for s; do
  case "$s" in install|checks) log "== $s"; "sc_$s" ;; *) die "unknown scenario $s" ;; esac
done
if grep -q '^FAIL\|^ABORT' "$OUT" || [ "$(grep -c '^fails=0$' "$OUT")" -ne 2 ]; then log "fw gate failed; see $OUT and $LOG"; exit 1; fi
log "fw gate: all checks passed"

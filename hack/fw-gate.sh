#!/bin/sh
# Firewall gates (PLAN.md row 3; ARCHITECTURE.md §6.1, Appendix B) on the local arm64 QEMU VM.
#   hack/fw-gate.sh [uefi|bios] [install] [checks]   default: both
# uefi (default) is the arm64 VM, bios the amd64 one (hack/gate.sh's boot modes); only install uses it.
# install  hack/gate.sh none: the unattended install and its gates; firstboot installs this checkout's release (make
#          release, install.sh, systemd/), so agentbox-firewall.service and the stub come from the real install path.
# checks   on the installed box, as root:
#          - the firewall loads at boot, the live table has no log statement (drops stay silent), fwcheck passes, and
#            the agent stand-in (agentbox-agent-stub.service: Requires=agentbox-firewall.service,
#            ExecStartPre=+agentbox fwcheck) starts
#          - each alteration (a rule inserted or deleted, a static element removed, an element rootd never recorded in a
#            dst set or port_allow, ntfy under another uid, the reserved-ports sysctl, nftables.service unmasked) keeps
#            the stand-in from starting; a hooked extra chain fails the firewall load itself and stops rootd,
#            auditd, agentboxd and ntfy, and once it is gone `fwcheck --repair` restarts the firewall and starts all four
#          - with reconcile failing, a firewall restart still loads the table, input chain included, and rootd stays down,
#            and ntfy with it (Requires=), so its fwcheck never runs against sets rootd didn't refill
#          - reload, restart and `fw load` keep every set's elements, and an element's expiry keeps running
#          - 200 root connections to 127.0.0.1:43100 succeed; other uids, other reserved ports and ::1 get a reset
#          - a broker uid reaches only the address and port in its own dst set (dropped for the rest, private ranges and
#            DNS included); a confined uid reaches nothing
#          - a keys flow survives its element's expiry (conntrack), while a new connection is refused
#          - `nft flush ruleset`: within 60 s the health timer's fwcheck alerts and the table is back, sets refilled; the
#            alert reaches ntfy's agentbox-alerts topic once, with fixed text (#213)
#          - inbound (issue #80), with network-namespace peers on a LAN link (lan0) and on tailscale0: a listener on
#            0.0.0.0/[::]:11434 is unreachable from the LAN; SSH works only from the seed's --ssh-from prefixes (IPv4 and
#            IPv6, after neighbor discovery); Tailscale's direct UDP 41641 arrives; tailscale0 reaches everything; the
#            box's own connections get their replies; an enabled ufw that allows 11434 opens nothing
#          - the input chain's policy set to accept, a rule inserted in it, the chain deleted, or a prefix added to
#            ssh_from4 each keep the stand-in from starting, and a firewall restart repairs each
#          - after a reboot: the sets are back and the stand-in starts at boot, with no failed unit; the firewall was up
#            before network-pre.target and systemd-networkd, and needs nothing from reconcile
# The sets rootd fills come from the real agentbox-rootd.service: rootd records the fixed port_allow tuples itself, and
# the gate writes the dst answers rootd would have written (set_answers, with their entries on the allowlists) and asks rootd to
# refill (`agentbox egress refill`); a firewall restart restarts rootd through Requires=, and rootd refills before READY=1.
# Checks print PASS/FAIL to .vm/fw-gate.txt, command output goes to .vm/fw-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
mkdir -p "$VM"
OUT="$VM/fw-gate.txt" LOG="$VM/fw-gate.log"
BOOT=uefi; case ${1:-} in uefi|bios) BOOT=$1; shift ;; esac
G=none; [ "$BOOT" = uefi ] || G=none-bios # gate.sh writes .vm/gate-$G.txt
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
# sql STATEMENTS: write rootd.db as rootd would (rootd keeps it open in WAL mode; python's sqlite3 waits on its lock)
sql() { python3 -c 'import sqlite3, sys; c = sqlite3.connect(sys.argv[1], timeout=30); c.executescript(sys.argv[2]); c.commit()' $DB "$1"; }
nowms() { echo $(( $(date +%s) * 1000 )); }
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
# rdropped PATTERN USER HOST PORT [udp]: the one output rule whose text holds PATTERN dropped it (its own counter moved)
rcount() { nft list chain inet agentbox output | grep -F -- "$1" | grep -o 'packets [0-9]*' | awk '{s += $2} END {print s + 0}'; }
rdropped() { pat=$1; shift; b=$(rcount "$pat"); r=$(as "$@"); a=$(rcount "$pat"); echo "$* -> $r, '$pat' counter $b -> $a"
  case $r in EPERM|TimeoutError) [ "$a" -gt "$b" ] ;; *) false ;; esac; }
expires() { nft -j list set inet agentbox "$1" | grep -o '"expires": [0-9]*' | grep -o '[0-9]*$'; }
# port_allow as one line; rootd records the fixed tuples itself (fw.FixedPortAllow)
pa() { elems port_allow | sort | paste -sd " " -; }
PA='{"concat": [0, 43100]} {"concat": [0, 43200]}'
IP=$(cat /var/tmp/fw-ip 2>/dev/null || :)
EOF
}

# the gate's seed: the VM network's SSH forward (10.0.2.0/24) and the lan0 peers' halves (see phase1)
SSH_FROM="10.0.2.0/24 192.0.2.0/25 fd00:ab::/112"

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
check "static sets as Appendix B: confined, private4, private6" 'nft list set inet agentbox confined | grep -qF "elements = { 70001-70999, 71001-71999, 1879048192-2013265919 }" && [ "$(elems private4 | wc -l)" = 13 ] && [ "$(elems private6 | wc -l)" = 12 ]'
check "the live table logs nothing: no log, queue, dup or fwd statement, so drops stay silent (§6.1)" '! nft -j list table inet agentbox | grep -qE "\"(log|queue|dup|fwd)\":"'
check "rootd is up at boot, after the firewall, and fwcheck passes" 'systemctl is-active agentbox-rootd.service && [ -e $DB ] && $A fwcheck'
check "the agent stand-in starts while the firewall is intact" 'systemctl start agentbox-agent-stub.service && systemctl is-active agentbox-agent-stub.service && systemctl stop agentbox-agent-stub.service'
check "the test address $IP (ports.ubuntu.com) is public: not in private4" '[ -n "$IP" ] && ! nft get element inet agentbox private4 "{ $IP }"'

# Inbound (issue #80). Peers in network namespaces stand in for other hosts: on lan0, 192.0.2.10 and fd00:ab::10 are
# inside the seed's --ssh-from, 192.0.2.200 and fd00:ab::1:10 outside; tailscale0 is the name tailscaled gives its tun.
check "inbound: the input chain drops by default; ssh_from4/6 hold the seed's --ssh-from, written to /etc/agentbox/ssh-from" 'nft list chain inet agentbox input | grep -q "hook input priority filter; policy drop;" && [ "$(cat /etc/agentbox/ssh-from | paste -sd " " -)" = "10.0.2.0/24 192.0.2.0/25 fd00:ab::/112" ] && nft list set inet agentbox ssh_from4 | grep -qF "elements = { 10.0.2.0/24, 192.0.2.0/25 }" && nft list set inet agentbox ssh_from6 | grep -qF "elements = { fd00:ab::/112 }"'
check "inbound: the gate's own SSH session comes from the VM network, inside the seed's --ssh-from" 'ss -Htn state established "( sport = :22 )" | awk "{print \$4}" | grep -q "^10\.0\.2\.[0-9]*:"'
ip netns add lan; ip link add lan0 type veth peer name eth0 netns lan
ip addr add 192.0.2.1/24 dev lan0; ip addr add fd00:ab::1/64 dev lan0 nodad; ip link set lan0 up
for a in 192.0.2.10/24 192.0.2.200/24; do ip -n lan addr add $a dev eth0; done
for a in fd00:ab::10/64 fd00:ab::1:10/64; do ip -n lan addr add $a dev eth0 nodad; done
ip -n lan link set lo up; ip -n lan link set eth0 up
ip netns add ts; ip link add tailscale0 type veth peer name eth0 netns ts
ip addr add 100.100.1.1/24 dev tailscale0; ip link set tailscale0 up
ip -n ts addr add 100.100.1.2/24 dev eth0; ip -n ts link set lo up; ip -n ts link set eth0 up
cat > /var/tmp/probe.py <<'P'
import errno, socket, sys
src, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
udp = len(sys.argv) > 4
s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.bind((src, 0))
    s.connect((host, port))
    if udp:
        s.send(b"x")
        print("sent")
        sys.exit()
    try:
        print(("ok " + s.recv(64).split(b"-")[0].decode(errors="replace")).strip())  # "ok" when it closes at once
    except socket.timeout:
        print("ok")
except OSError as e:
    print(errno.errorcode.get(e.errno, "") if e.errno else type(e).__name__)
P
cat > /var/tmp/inlisten.py <<'P'
import select, socket, sys
log = open(sys.argv[1], "a", buffering=1)
ss = []
for t, p in ((socket.SOCK_STREAM, 11434), (socket.SOCK_DGRAM, 11434), (socket.SOCK_DGRAM, 41641)):
    s = socket.socket(socket.AF_INET6, t)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # [::] takes IPv4 too, like 0.0.0.0
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::", p))
    t == socket.SOCK_STREAM and s.listen()
    ss.append(s)
while True:
    for s in select.select(ss, [], [])[0]:
        if s.type == socket.SOCK_STREAM:
            c, a = s.accept(); c.close()
        else:
            a = s.recvfrom(512)[1]
        log.write("%s %d %s\n" % ("tcp" if s.type == socket.SOCK_STREAM else "udp", s.getsockname()[1], a[0].removeprefix("::ffff:")))
P
: > /var/tmp/inlisten.log
python3 /var/tmp/inlisten.py /var/tmp/inlisten.log 2>>$L & IL=$!
ip netns exec lan python3 -c 'import socket; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("192.0.2.200", 8080)); s.listen()
while True: s.accept()[0].close()' 2>>$L & PL=$!
sleep 2
# peer NS SRC DST PORT [udp]: what a connect from SRC in namespace NS gets
peer() { ns=$1; shift; ip netns exec $ns python3 /var/tmp/probe.py "$@"; }
seen() { grep -c "^$1 $2 $3\$" /var/tmp/inlisten.log; }
check "inbound: [::]:11434 listens on every address (the stand-in for a listener the owner adds)" '[ -n "$(ss -Hltn "sport = :11434")" ] && [ "$(python3 /var/tmp/conn.py 127.0.0.1 11434)" = ok ]'
check "inbound: 11434 is unreachable from the LAN, inside the SSH prefixes and outside, IPv4 and IPv6; it saw nothing" 'for s in 192.0.2.10 192.0.2.200; do [ "$(peer lan $s 192.0.2.1 11434)" = TimeoutError ] && [ "$(seen tcp 11434 $s)" = 0 ] || exit 1; done && for s in fd00:ab::10 fd00:ab::1:10; do [ "$(peer lan $s fd00:ab::1 11434)" = TimeoutError ] && [ "$(seen tcp 11434 $s)" = 0 ] || exit 1; done'
check "inbound: SSH from the seed's --ssh-from works: sshd's banner to 192.0.2.10 and fd00:ab::10 (IPv6 neighbor discovery passes)" '[ "$(peer lan 192.0.2.10 192.0.2.1 22)" = "ok SSH" ] && [ "$(peer lan fd00:ab::10 fd00:ab::1 22)" = "ok SSH" ]'
check "inbound: SSH from outside the seed's --ssh-from (192.0.2.200, fd00:ab::1:10) is dropped" '[ "$(peer lan 192.0.2.200 192.0.2.1 22)" = TimeoutError ] && [ "$(peer lan fd00:ab::1:10 fd00:ab::1 22)" = TimeoutError ]'
check "inbound: Tailscale's direct UDP 41641 from a LAN peer outside the SSH prefixes arrives; UDP 11434 does not" 'peer lan 192.0.2.200 192.0.2.1 41641 udp && peer lan fd00:ab::1:10 fd00:ab::1 41641 udp && peer lan 192.0.2.200 192.0.2.1 11434 udp && sleep 1 && [ "$(seen udp 41641 192.0.2.200)" = 1 ] && [ "$(seen udp 41641 fd00:ab::1:10)" = 1 ] && [ "$(seen udp 11434 192.0.2.200)" = 0 ]'
check "inbound: from tailscale0 (the tailnet, where tailscale serve fronts ntfy) the 11434 listener and SSH are reachable" '[ "$(peer ts 100.100.1.2 100.100.1.1 11434)" = ok ] && [ "$(seen tcp 11434 100.100.1.2)" = 1 ] && [ "$(peer ts 100.100.1.2 100.100.1.1 22)" = "ok SSH" ]'
check "inbound: the box's own connection to a LAN peer's listener gets its replies (ct state established)" '[ "$(python3 /var/tmp/conn.py 192.0.2.200 8080)" = ok ]'
# ufw's iptables-nft tables hook input in their own tables: a packet must pass every hook, so ufw can only drop more
check "inbound: an enabled ufw that allows 11434/tcp opens nothing the input chain drops; fwcheck passes; ufw disabled again" 'ufw allow 22/tcp && ufw allow 11434/tcp && ufw --force enable && ufw status | grep -q "Status: active" && [ "$(peer lan 192.0.2.10 192.0.2.1 11434)" = TimeoutError ] && [ "$(peer lan 192.0.2.10 192.0.2.1 22)" = "ok SSH" ] && $A fwcheck; r=$?; ufw --force disable; ufw delete allow 11434/tcp; ufw delete allow 22/tcp; exit $r'
kill $IL $PL; ip netns del lan; ip netns del ts

check "rootd recorded the fixed port_allow tuples itself (0 . 43100, 0 . 43200) and filled port_allow from them" '[ "$(python3 -c "import sqlite3; print(\",\".join(sorted(r[0] for r in sqlite3.connect(\"file:$DB?mode=ro\", uri=True).execute(\"select element from set_elements where set_name = \x27port_allow\x27\"))))")" = "0 . 43100,0 . 43200" ] && [ "$(pa)" = "$PA" ]'
# the row rootd would have written before adding the proxy's element (rootd.db set_answers, Appendix E); the answer is
# for an entry on its allowlist, or rootd's refill revokes it
$A egress allow --svc proxy --entry ports.ubuntu.com:80 >>$L 2>&1
sql "INSERT INTO set_answers VALUES ('proxy ports.ubuntu.com:80', 'proxy_dst4', '$IP . 80', $(nowms) + 600000);"
check "rootd's refill fills proxy_dst4 from rootd.db, with the remaining timeout; fwcheck passes" '$A egress refill && [ "$(pa)" = "$PA" ] && [ "$(elems proxy_dst4)" = "{\"concat\": [\"$IP\", 80]}" ] && [ "$(expires proxy_dst4)" -le 600 ] && $A fwcheck'

# Firewall altered: agents can't start. The health timer would repair in between, so it waits.
systemctl stop agentbox-health.timer
# restore: what fwcheck --repair does; rootd's refill runs in the restart Requires= queues after the firewall's
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
altered "the input chain's policy set to accept" 'nft chain inet agentbox input "{ policy accept; }"'
altered "an input rule accepting tcp dport 11434" 'nft insert rule inet agentbox input tcp dport 11434 accept'
altered "the input chain deleted" 'nft flush chain inet agentbox input && nft delete chain inet agentbox input'
altered "a prefix the seed never named added to ssh_from4" "nft add element inet agentbox ssh_from4 '{ 203.0.113.0/24 }'"
check "a table with an extra hooked chain fails the firewall load itself (fail closed)" 'nft add chain inet agentbox evil "{ type filter hook output priority -10; policy accept; }" && ! systemctl restart agentbox-firewall.service && ! systemctl is-active agentbox-firewall.service && journalctl -u agentbox-firewall.service -n 20 -o cat | grep -q "stateless hash"'
# #218: a restart restarts only the units that run, and the table checks out once the chain is gone: the repair restarts
# the failed firewall itself and starts what the failed load stopped
check "  ... which stops rootd, auditd, agentboxd and ntfy; with the chain deleted, fwcheck --repair restarts the failed firewall and starts all four" '! systemctl is-active agentbox-rootd.service agentbox-auditd.service agentboxd.service ntfy.service && nft delete chain inet agentbox evil &&
  $A fwcheck --repair && for u in agentbox-firewall.service agentbox-rootd.service agentbox-auditd.service agentboxd.service ntfy.service; do systemctl is-active -q $u || exit 1; done && $A fwcheck'
# #218: the firewall needs nothing reconcile writes. A foreign sub-id entry in the agentbox span fails reconcile; a
# firewall restart then loads the deleted table again, while rootd, auditd and agentboxd (Requires= reconcile) stay down
cp /etc/subuid /run/subuid.ok; echo "evil:$((0x70000000)):65536" >> /etc/subuid
# ntfy stops with rootd (Requires=, #220): the firewall restart can't start it into a fwcheck of sets rootd never refilled
check "reconcile failing: a firewall restart still loads the deleted table and its input chain; rootd, auditd, agentboxd and ntfy stay down" '! systemctl restart agentbox-reconcile.service && nft delete table inet agentbox && systemctl restart agentbox-firewall.service &&
  systemctl is-active -q agentbox-firewall.service && nft list chain inet agentbox input | grep -q "policy drop;" && ! systemctl is-active agentbox-rootd.service agentbox-auditd.service agentboxd.service ntfy.service'
cp /run/subuid.ok /etc/subuid
check "  ... with the entry gone, reconcile and rootd start, rootd refills its sets, and auditd, agentboxd and ntfy start" 'systemctl reset-failed && systemctl start agentbox-reconcile.service agentbox-rootd.service &&
  systemctl start agentbox-auditd.service agentboxd.service ntfy.service && [ "$(pa)" = "$PA" ] && $A fwcheck'

# Reload, restart and fw load keep the sets
p=$(pa) d=$(elems proxy_dst4) e1=$(expires proxy_dst4)
check "reload, restart and fw load keep port_allow and proxy_dst4; the element's expiry keeps running" 'systemctl reload agentbox-firewall.service && systemctl restart agentbox-firewall.service && $A fw load && [ "$(pa)" = "$p" ] && [ "$(elems proxy_dst4)" = "$d" ] && [ -n "$p" ] && [ -n "$d" ] && [ "$(expires proxy_dst4)" -le "$e1" ] && $A fwcheck'
check "after the reloads, the agent stand-in starts" 'systemctl start agentbox-agent-stub.service && systemctl is-active agentbox-agent-stub.service'

# Reserved loopback ports
python3 /var/tmp/listen.py >>$L 2>&1 & LP=$!; sleep 2
check "200 root loopback connections to 127.0.0.1:43100 all succeed" '[ "$(python3 /var/tmp/many.py)" = 200 ]'
check "uid nobody to 127.0.0.1:43100 (no port_allow tuple): reset" '[ "$(as nobody 127.0.0.1 43100)" = ECONNREFUSED ]'
# a listener that failed to bind would give the same ECONNREFUSED: check it is up, and that the reject rule sent it
rejects() { nft list chain inet agentbox output | grep -F "$1" | grep -F "reject with tcp reset" | grep -o 'packets [0-9]*' | awk '{print $2}'; }
check "root to 127.0.0.1:43101 (listening, not in port_allow): reset by the reject rule" '[ -n "$(ss -Hltn "sport = :43101")" ] && b=$(rejects "ip daddr 127.0.0.1") && [ "$(python3 /var/tmp/conn.py 127.0.0.1 43101)" = ECONNREFUSED ] && [ "$(rejects "ip daddr 127.0.0.1")" -gt "$b" ]'
check "root to [::1]:43100 (listening): reset by the reject rule" '[ -n "$(ss -Hltn "src [::1]:43100")" ] && b=$(rejects "ip6 daddr ::1") && [ "$(python3 /var/tmp/conn.py ::1 43100)" = ECONNREFUSED ] && [ "$(rejects "ip6 daddr ::1")" -gt "$b" ]'
kill $LP

# A broker reaches only what rootd put in its own set
check "agentbox-proxy reaches $IP:80 (in proxy_dst4)" '[ "$(as agentbox-proxy $IP 80)" = ok ]'
check "agentbox-proxy can't reach $IP:443 (port not in its set): dropped" 'dropped agentbox-proxy $IP 443'
check "agentbox-keys and agentbox-git can't reach $IP:80 (not in their sets): dropped" 'dropped agentbox-keys $IP 80 && dropped agentbox-git $IP 80'
check "agentbox-proxy can't reach 1.1.1.1:443 (an IP rootd never resolved): dropped" 'dropped agentbox-proxy 1.1.1.1 443'
# in proxy_dst4 on purpose, so the per-uid catch-all drop can't stand in for the private4 and fib rules
nft add element inet agentbox proxy_dst4 '{ 10.0.2.2 . 22 timeout 5m, 127.0.0.53 . 53 timeout 5m }'
check "agentbox-proxy can't reach 10.0.2.2:22 even with it in proxy_dst4: the private4 rule drops it" 'rdropped "ip daddr @private4 counter" agentbox-proxy 10.0.2.2 22'
check "agentbox-proxy can't reach DNS on 127.0.0.53:53 (tcp in proxy_dst4, and udp): the fib local rule drops it" 'rdropped "fib daddr type" agentbox-proxy 127.0.0.53 53 && rdropped "fib daddr type" agentbox-proxy 127.0.0.53 53 udp'
nft delete element inet agentbox proxy_dst4 '{ 10.0.2.2 . 22, 127.0.0.53 . 53 }'
check "a confined uid (70001) can't reach $IP:80: dropped" 'dropped 70001 $IP 80'
check "root still reaches $IP:80 (only agentbox uids are confined)" '[ "$(python3 /var/tmp/conn.py $IP 80)" = ok ]'

# A long broker flow survives its element's expiry: the established accept comes before the set checks
$A egress allow --svc keys --entry ports.ubuntu.com:80 >>$L 2>&1
sql "INSERT INTO set_answers VALUES ('keys ports.ubuntu.com:80', 'keys_dst4', '$IP . 80', $(nowms) + 5000);"
$A egress refill >>$L 2>&1
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
$A egress remove --svc keys --entry ports.ubuntu.com:80 >>$L 2>&1

# nft flush ruleset: the health timer's fwcheck alerts and restores within 60 s. A started timer first runs 1 min later
# (OnActiveSec, #218), so the gate runs the check once by hand: the timer's next run comes a whole period (50 s) after
# that one, and the flush comes right after it ends, so the repair has to wait out that period (the worst case)
systemctl stop agentbox-agent-stub.service
# the failed load above stopped ntfy.service with its Requires=, and the repair after it started it again (#218)
check "ntfy.service runs again, so the flush below can alert" 'systemctl is-active ntfy.service'
i0=$(systemctl show -P InactiveEnterTimestampMonotonic agentbox-health.service)
systemctl start agentbox-health.timer && systemctl start agentbox-health.service
check "the health check ran just before the flush, with the timer started" '[ "$(systemctl show -P InactiveEnterTimestampMonotonic agentbox-health.service)" != "$i0" ] && systemctl is-active -q agentbox-health.timer'
t0=$(date +%s); nft flush ruleset; t1=0
for i in $(seq 90); do nft list table inet agentbox >/dev/null 2>&1 && { t1=$(date +%s); break; }; sleep 1; done
echo "flush at $t0, table back at $t1: $((t1 - t0)) s" >>$L
check "nft flush ruleset: the table is back within 60 s ($((t1 - t0)) s)" '[ $t1 -gt 0 ] && [ $((t1 - t0)) -le 60 ]'
sleep 5
check "nft flush ruleset: fwcheck alerted, restarted the firewall, and the refill restored rootd's sets" 'journalctl -u agentbox-health.service --since @$t0 -o cat | grep -q "agentbox: ALERT: firewall altered: nft list table inet agentbox" && journalctl -u agentbox-health.service --since @$t0 -o cat | grep -q "agentbox: firewall restored" && [ "$(pa)" = "$p" ] && [ "$(elems proxy_dst4)" = "$d" ] && $A fwcheck'
# ntfy.service restarts with the firewall (Requires=): fwcheck sent the alert before the restart, and ntfy's cache keeps it
check "nft flush ruleset: the alert reached ntfy's agentbox-alerts topic once, with fixed text (#213)" 'journalctl -u agentbox-health.service --since @$t0 -o cat | grep -q "agentbox: alert sent: the firewall was altered at runtime" &&
  [ "$(python3 -c "import sqlite3; c=sqlite3.connect(\"file:/var/lib/ntfy/cache.db?mode=ro\",uri=True); print(c.execute(\"select count(*) from messages where topic=\x27agentbox-alerts\x27 and title=\x27agentbox: firewall\x27 and message like \x27the firewall was altered at runtime:%\x27 and time >= $t0\").fetchone()[0])")" = 1 ]'
check "after the repair, the agent stand-in starts" 'systemctl start agentbox-agent-stub.service && systemctl is-active agentbox-agent-stub.service'

# for the reboot: a fresh answer, and the stand-in starts at boot like an agent's user manager
sql "UPDATE set_answers SET expires_at = $(nowms) + 600000 WHERE set_name = 'proxy_dst4';"; $A egress refill >>$L 2>&1
ln -sf ../agentbox-agent-stub.service /etc/systemd/system/multi-user.target.wants/agentbox-agent-stub.service
systemctl reset-failed
echo "fails=$fails"
EOF
}

phase2() { cat <<'EOF'
echo "== after reboot" >>$L
check "reboot: firewall, rootd and agent stand-in active; no failed units" '[ "$(systemctl is-system-running --wait)" = running ] && for u in agentbox-firewall.service agentbox-rootd.service agentbox-agent-stub.service; do systemctl is-active -q $u || exit 1; done'
# #218: the input chain is in place before any interface comes up, and a failed reconcile can't keep it out
check "reboot: the firewall was up before network-pre.target and systemd-networkd, and needs nothing from reconcile" 'f=$(systemctl show -P ActiveEnterTimestampMonotonic agentbox-firewall.service) &&
  n=$(systemctl show -P ActiveEnterTimestampMonotonic network-pre.target) && d=$(systemctl show -P ExecMainStartTimestampMonotonic systemd-networkd.service) &&
  echo "active at (us): firewall $f, network-pre.target $n, networkd started $d" && [ "$f" -gt 0 ] && [ "$f" -le "$n" ] && [ "$f" -lt "$d" ] &&
  ! systemctl show -p Requires -p Wants -p After agentbox-firewall.service | grep -q agentbox-reconcile'
check "reboot: the static sets are loaded and rootd's sets are back from rootd.db" 'nft list set inet agentbox confined | grep -qF 70001-70999 && [ "$(elems private4 | wc -l)" = 13 ] && [ "$(pa)" = "$PA" ] && [ "$(elems proxy_dst4)" = "{\"concat\": [\"$IP\", 80]}" ]'
check "reboot: the input chain drops by default and ssh_from4/6 hold the seed's --ssh-from" 'nft list chain inet agentbox input | grep -q "policy drop;" && nft list set inet agentbox ssh_from4 | grep -qF "elements = { 10.0.2.0/24, 192.0.2.0/25 }" && nft list set inet agentbox ssh_from6 | grep -qF "elements = { fd00:ab::/112 }"'
check "reboot: fwcheck passes; agentbox-proxy reaches $IP:80 and nothing else" '$A fwcheck && [ "$(as agentbox-proxy $IP 80)" = ok ] && dropped agentbox-proxy 1.1.1.1 443'
check "reboot: the agent stand-in's own fwcheck ran and passed at boot" 'journalctl -b -u agentbox-agent-stub.service -o cat | grep -q "Started agentbox-agent-stub.service\|Started agentbox agent stand-in" && ! journalctl -b -u agentbox-agent-stub.service -o cat | grep -q "agentbox: fwcheck: "'
echo "fails=$fails"
EOF
}

sc_install() {
  SEED_SSH_FROM=$SSH_FROM hack/gate.sh none "$BOOT" >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-$G.txt"
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
  u="-u agentbox-firewall.service -u agentbox-health.service -u agentbox-agent-stub.service -u agentbox-rootd.service"
  echo "cat /var/tmp/fw-gate.log; for b in -1 0; do journalctl -b \$b --no-pager -o short-iso $u; done" | root >>"$LOG" 2>&1 || :
  # the stand-in goes back off at boot, as shipped: a gate run next on this disk crashes rootd on purpose
  echo 'rm -f /etc/systemd/system/multi-user.target.wants/agentbox-agent-stub.service; systemctl poweroff' | root >/dev/null 2>&1 || :
  while running; do sleep 2; done
}

: >"$LOG"; : >"$OUT"
for s; do
  case "$s" in install|checks) log "== $s"; "sc_$s" ;; *) die "unknown scenario $s" ;; esac
done
if grep -q '^FAIL\|^ABORT' "$OUT" || [ "$(grep -c '^fails=0$' "$OUT")" -ne 2 ]; then log "fw gate failed; see $OUT and $LOG"; exit 1; fi
log "fw gate: all checks passed"

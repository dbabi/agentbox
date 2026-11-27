#!/bin/sh
# Milestone 5 gate for the egress proxy (#17; PLAN.md row 7-8; ARCHITECTURE.md §2, §2.1, §5.6, §6.1, §6.2, §6.3,
# Appendix B) on the local arm64 QEMU VM, none mode.
#   hack/proxy-gate.sh [install|release|checks ...]   default: install checks
# install  hack/gate.sh none: make release, the unattended install and firstboot, so agentbox-proxy, its socket unit,
#          rootd and the task image arrive the real way.
# release  installs this checkout as a new release on the running VM with that release's install.sh (for iterating on
#          a box that install made).
# checks   a fake package registry on the host (hack/proxy-gate/registry: HTTPS with a throwaway CA, synthetic npm and
#          PyPI packages) on 127.0.0.1:7900+ID, which vm.sh forwards to the guest as 10.0.2.2 for this boot only
#          (AGENTBOX_VM_FWD). On the box, resolved asks hack/gate-dns for this boot only, and reg.gate.test answers the
#          public-looking 192.88.96.50, which rootd checks and adds to proxy_dst4. A nat chain in the gate's own table
#          sends 192.88.96.50:443 on to 10.0.2.2: nft NAT runs at the dstnat hook before the agentbox output chain, so
#          an approved allow_private4 tuple in rootd.db lets agentbox-proxy reach that one port. Two agents run tasks
#          as sh scripts (AGENTBOX_TEST_CLI=sh) in the release's task image, through the release's agentbox-proxy,
#          which socket activation starts at the first task.
#          The #17 gate items: rebinding (the allowlisted name moves to the registry's own LAN address, loopback, the
#          metadata address, or a public and a private answer at once), raw IPv4 and IPv6 targets, UDP, IPv6 (raw,
#          ULA, link-local, loopback, IPv4-mapped and NAT64-wrapped private answers), LAN and metadata names
#          (169.254.169.254, fd00:ec2::254): each CONNECT fails with its §5.6 denial and no IP address in it, before any
#          byte reaches an upstream; without the proxy a task reaches nothing (TCP, UDP, IPv6, DNS). As agentbox-proxy,
#          nft drops TCP and UDP to the LAN, the metadata address, DNS and any address rootd did not return, and the
#          unit's own namespace has no DNS. A real fetch from a task against the fake registry: npm install of a
#          package with 24 dependencies (more tunnels at once than §2.1's 8, so the proxy socket serves 64) and pip
#          download, TLS end to end (the client checks the registry's certificate; SNI and Host keep the name). Also:
#          one TAINT per CONNECT, and none for a refused one; auditd down gives 503 AUDIT_UNAVAILABLE and the registry
#          gets no request; the per-agent list; the LLM vendor and deputy hosts; plain HTTP; a proxy restart and a
#          crash mid-task rebind the task's socket; revoke cuts a live tunnel; the socket modes and peer checks; no
#          proxy nft drop from any task's traffic.
# PASS/FAIL lines go to .vm/proxy-gate.txt, command output to .vm/proxy-gate.log, the registry's log to
# .vm/proxy-gate-registry.log; exit 1 on any FAIL. AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh.
# Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/proxy-gate.txt" LOG="$VM/proxy-gate.log"
RP=$((7900 + ${AGENTBOX_VM_ID:-0}))
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
vm_off() { echo 'systemctl poweroff' | root >/dev/null 2>&1 || :; i=0
  while running; do i=$((i+1)); [ $i -lt 60 ] || kill "$(cat "$VM/qemu.pid")"; sleep 2; done; }
# up: a fresh boot with the registry's port forwarded, whatever ran before
up() { ! running || vm_off; { AGENTBOX_VM_FWD=$RP hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"; settle; }
guest() {
  root >"$VM/guest.out" 2>>"$LOG" || :
  while IFS= read -r l; do case $l in PASS*|FAIL*) log "$l" ;; *) echo "$l" >>"$LOG" ;; esac; done <"$VM/guest.out"
  grep -q '^fails=' "$VM/guest.out" || log "FAIL the check block on the VM did not finish (see $LOG)"
}

for s; do case $s in
install)
  hack/gate.sh none >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-none.txt"
  log "PASS install: hack/gate.sh none (install, release pipeline, firstboot, no failed units)" ;;
release)
  running || { { hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH"; settle; }
  V=0.0.2-dev$(date +%s) D=$(mktemp -d "$VM/rel.XXXXXX")
  make -s release VERSION="$V" MINISIGN_KEY="$VM/keys/minisign.key" DIST="$D" >>"$LOG" 2>&1 || die "make release failed"
  hack/vm.sh ssh 'rm -rf /tmp/rel && mkdir /tmp/rel && tar -xz -C /tmp/rel' < "$D/agentbox-$V.tgz"
  # install.sh only enables: the running services keep the old binary until they restart
  echo 'sh /tmp/rel/install.sh --from-firstboot && systemctl restart agentbox-rootd.service agentboxd.service && systemctl try-restart agentbox-proxy.service' |
    root >>"$LOG" 2>&1 || die "install.sh $V failed; see $LOG"
  rm -rf "$D"
  log "PASS release $V installed" ;;
checks)
  K="$VM/proxy-gate"
  rm -rf "$K" && mkdir -p "$K"
  TOKEN=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  go build -o "$K/registry" ./hack/proxy-gate/registry || die "build the fake registry"
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$K/gate-dns" ./hack/gate-dns || die "build gate-dns"
  "$K/registry" -listen "127.0.0.1:$RP" -token "$TOKEN" -ca "$K/ca.pem" -log "$K/registry.log" >>"$LOG" 2>&1 &
  RPID=$!
  trap 'kill $RPID 2>/dev/null; cp "$K/registry.log" "$VM/proxy-gate-registry.log" 2>/dev/null' EXIT
  i=0; until [ -s "$K/ca.pem" ]; do i=$((i+1)); [ $i -lt 50 ] || die "the fake registry did not start"; sleep 0.2; done
  up
  printf 'TOKEN=%s\nRP=%s\n' "$TOKEN" "$RP" > "$K/env"
  tar -C "$K" -cf - env ca.pem gate-dns | hack/vm.sh ssh 'rm -rf /tmp/pg && mkdir /tmp/pg && tar -C /tmp/pg -xf -'
  tar -C image -cf - task | hack/vm.sh ssh 'rm -rf /tmp/pg-image && mkdir /tmp/pg-image && tar -C /tmp/pg-image -xf -'
  guest <<'EOF'
fails=0
cd / # runuser keeps the working dir, and the agent can't enter the admin's home
check() { if (eval "$2") >>/tmp/pg-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
K=/tmp/pg
. $K/env
B=/var/lib/agentbox/current/bin/agentbox
E=/var/lib/agentbox/control/egress
WS=/var/lib/agentbox/data/workspaces
DB=/var/lib/agentbox/rootd.db
RS=/run/systemd/system
G=/var/tmp/proxy-gate
mkdir -p $G && chmod 0755 $G
# a rerun on the same box gets new agents: fresh workspaces, lists and audit subjects
R=$(( $(cat $G/run 2>/dev/null || echo 0) + 1 )); echo $R > $G/run
PA=pa$R PB=pb$R
PUB=192.88.96.50 # reg.gate.test: public by prefix, routed by the default route
IMG=localhost/agentbox-task:proxy-gate
PU=$(id -u agentbox-proxy)
install -m 0755 $K/gate-dns $G/gate-dns && install -m 0644 $K/ca.pem $G/ca.pem

# rlog: the registry's log, read as root (not confined) straight from 10.0.2.2; these reads are not in it
rlog() { curl -sS --cacert $G/ca.pem --resolve ctl.reg.gate.test:$RP:10.0.2.2 "https://ctl.reg.gate.test:$RP/_log/$TOKEN"; }
rmark() { rlog | wc -l; }
# rsince MARK [KIND]: the registry's log lines since rmark, or only those of KIND: conn (a TLS hello), req, done, closed
rsince() { rlog | tail -n +$(( $1 + 1 )) | if [ $# -gt 1 ]; then grep " $2 "; else cat; fi; }
rcount() { rsince "$1" "$2" | wc -l; }
# dns NAME=ADDR,...: gate-dns answers *.gate.test from exactly these records, and resolved forgets what it cached
dns() { systemctl stop pg-dns.service 2>/dev/null; systemctl reset-failed pg-dns.service 2>/dev/null; a=
  for r; do a="$a -a $r"; done
  # shellcheck disable=SC2086 # one -a flag per record
  systemd-run -q --unit=pg-dns $G/gate-dns -listen 127.0.0.153:53 -upstream 10.0.2.3:53 -a ping.gate.test=192.88.96.99 $a || return 1
  for n in $(seq 50); do resolvectl flush-caches; resolvectl query -4 ping.gate.test >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }
BASE="lan.gate.test=192.168.1.10 host.gate.test=10.0.2.2 meta.gate.test=169.254.169.254 meta6.gate.test=fd00:ec2::254
  lo.gate.test=127.0.0.1 lo6.gate.test=::1 ula.gate.test=fd00::1 ll6.gate.test=fe80::1 mapped.gate.test=::ffff:10.0.2.2
  nat64.gate.test=64:ff9b::a00:202 mixed.gate.test=$PUB,10.0.2.2 zero.gate.test=0.0.0.0 cgnat.gate.test=100.64.0.1"
ended() { $B task list | python3 -c 'import json,sys; sys.exit(not [t for t in json.load(sys.stdin)["tasks"] if t["task"]==sys.argv[1] and t.get("end_reason")])' "$1"; }
# task AGENT SCRIPT [ID]: one task through task.start; prints what the script printed and returns its exit code. The
# id goes to $G/last, or $G/ID. Its output file is its own, so a task in the background and the next one don't share it.
# The helpers' loop variables (k, n, w) are their own: sh has no local variables.
task() { o=$WS/$1/.gate-out-${3:-last} rc=$WS/$1/.gate-rc-${3:-last}; rm -f $o $rc; id=$G/${3:-last}; rm -f $id
  printf '(\n%s\n) </dev/null > %s 2>&1; echo $? > %s\n' "$2" "/workspace/${o##*/}" "/workspace/${rc##*/}" |
    $B task new --agent $1 --cli sh --deadline 15m > $G/new-${3:-last}; r=$?
  sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' $G/new-${3:-last} > $id
  [ $r = 0 ] && [ -s $id ] || { cat $G/new-${3:-last}; return 99; }
  k=0; while [ ! -e $rc ]; do k=$((k+1)); [ $k -lt 6000 ] || { echo "task $(cat $id): no result"; cat $o; return 98; }; sleep 0.1; done
  k=0; until ended "$(cat $id)"; do k=$((k+1)); [ $k -lt 300 ] || break; sleep 0.1; done
  cat $o; return "$(cat $rc)"; }
wait_file() { w=0; while [ ! -e "$1" ]; do w=$((w+1)); [ $w -lt $(($2 * 10)) ] || return 1; sleep 0.1; done; }
# arec TYPE [key=value...]: the audit records of TYPE whose body (or producer=) match, as "seq producer body"
cat > $G/arec.py <<'PY'
import glob, json, sys
t, want = sys.argv[1], dict(a.split("=", 1) for a in sys.argv[2:])
recs = []
for p in glob.glob("/var/lib/agentbox/audit/seg-*.jsonl"):
    for l in open(p, errors="replace"):
        try:
            r = json.loads(l)
        except ValueError:
            continue
        b = r.get("body") or {}
        if r.get("type") == t and all((r.get("producer") if k == "producer" else str(b.get(k))) == v for k, v in want.items()):
            recs.append((r["seq"], r["producer"], json.dumps(b, sort_keys=True)))
for r in sorted(recs):
    print(*r)
PY
arec() { python3 $G/arec.py "$@"; }
# pdrops: packets the ruleset dropped in every drop rule that names agentbox-proxy (nft prints its uid as a number; the
# shared private-range and local-address rules count the other brokers and ntfy too)
pdrops() { nft list chain inet agentbox output | grep -E "meta skuid (${PU} |\{[^}]*[{ ]${PU}[ ,}])" |
  sed -n 's/.* counter packets \([0-9]*\) .* drop$/\1/p' | awk '{n += $1} END {print n + 0}'; }
# tunnels TASK: the proxy's journal lines for TASK's tunnels
tunnels() { journalctl -b -u agentbox-proxy.service -o cat | grep " task $1 CONNECT [^ ]*: tunnel to "; }
# indst PATTERN: some element of a dst set (rootd's resolutions) matches PATTERN
indst() { for s in proxy_dst4 keys_dst4 git_dst4 ntfy_dst4 proxy_dst6 keys_dst6 git_dst6 ntfy_dst6; do
  nft list set inet agentbox $s | grep -qE "$1" && return 0; done; return 1; }
# probe.py tcp|udp HOST PORT: one connect or datagram as the caller; prints ok, timeout or the errno name
cat > $G/probe.py <<'PY'
import errno, socket, sys
kind, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.connect((host, port)) if kind == "tcp" else s.sendto(b"x", (host, port))
    print("ok")
except socket.timeout:
    print("timeout")
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e)))
PY
chmod 0644 $G/probe.py $G/arec.py
# svc LINE: one line on svc-proxy.sock as the calling uid; prints the reply, or "closed"
cat > $G/svc.py <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect("/run/agentbox-rootd/svc-proxy.sock")
s.sendall(sys.argv[1].encode() + b"\n")
try:
    print(s.recv(4096).decode().strip() or "closed")
except OSError:
    print("closed")
PY
chmod 0644 $G/svc.py

# --- setup: two agents, the registry's name and route, the test CLI ---
check "at boot agentbox-proxy is not running; agentbox-proxy-svc.socket listens, bound by PID 1 as agentbox-proxy:root 0600" '
  ! systemctl is-active -q agentbox-proxy.service && systemctl is-active -q agentbox-proxy-svc.socket &&
  [ "$(stat -c "%U:%G %a" /run/agentbox-rootd/svc-proxy.sock)" = "agentbox-proxy:root 600" ]'
# image/task (npm, pip, curl): the release's own image runs the host's /usr, which has no npm or pip. Built here before
# resolved moves to gate-dns, with the box's own resolver (--network=host), and once more after a failed first try
build() { podman build -q --network=host -t $IMG /tmp/pg-image/task </dev/null >/dev/null ||
  { sleep 10; podman build -q --network=host -t $IMG /tmp/pg-image/task </dev/null >/dev/null; }; }
for i in $(seq 30); do getent hosts registry-1.docker.io >/dev/null && break; sleep 2; done
check "image/task builds on the box (ubuntu:26.04, curl, python3-pip, nodejs, npm, mise's Go)" '
  build && rm -f $G/image.tar && podman save -o $G/image.tar $IMG && chmod 0644 $G/image.tar'
# podman load runs through the agent's user manager, as rootd's own image load does
for a in $PA $PB; do
  check "agent add $a (rootd's agent.add), and image/task in its podman" '$B agent add --name $a >/dev/null && u=$(id -u ag-$a) &&
    i=0; until systemctl is-active -q user@$u.service; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done &&
    systemd-run --user -M ag-$a@ --wait --quiet --collect /usr/bin/podman load -q -i $G/image.tar </dev/null'
  mkdir -p $WS/$a/.pg && cp $G/ca.pem $WS/$a/.pg/ca.pem
done
mkdir -p /run/systemd/resolved.conf.d
printf '[Resolve]\nDNS=127.0.0.153\nDomains=~.\n' > /run/systemd/resolved.conf.d/90-proxy-gate.conf
systemctl restart systemd-resolved.service
# shellcheck disable=SC2086 # one record per word
check "gate-dns answers reg.gate.test through resolved (this boot only), and the box still resolves public names" '
  dns reg.gate.test=$PUB $BASE && resolvectl query -4 reg.gate.test | grep -q "$PUB" && resolvectl query -4 example.com >/dev/null'
check "the registry's port is approved for agentbox-proxy (allow_private4 in rootd.db), and 192.88.96.50:443 goes to it" '
  python3 -c "import sqlite3; c=sqlite3.connect(\"$DB\"); c.execute(\"insert or ignore into set_elements values (\x27allow_private4\x27, \x27$PU . 10.0.2.2 . $RP\x27, NULL)\"); c.commit()" &&
  $B egress refill >/dev/null && nft list set inet agentbox allow_private4 | grep -q "10.0.2.2 . $RP" &&
  nft -f - <<NFT
table ip proxygate {
  chain out { type nat hook output priority dstnat; policy accept; ip daddr $PUB tcp dport 443 dnat to 10.0.2.2:$RP; }
}
NFT
'
check "the fake registry answers on 10.0.2.2:$RP (as root)" 'curl -sS --cacert $G/ca.pem --resolve reg.gate.test:$RP:10.0.2.2 https://reg.gate.test:$RP/hello | grep -qx "hello from the fake registry"'
# common.list, through rootd-admin.sock (audited): every agent may reach the registry
check "egress allow --svc proxy --entry reg.gate.test:443 (common.list)" '$B egress allow --svc proxy --entry reg.gate.test:443 >/dev/null && grep -qx reg.gate.test:443 $E/common.list'
# PA's own list names every refused name, so rootd's checks refuse them, not the list; PB's names none of them
{ for n in lan meta6:80 meta:80 lo lo6 ula ll6 mapped nat64 mixed zero cgnat nx; do
    case $n in *:*) echo "${n%%:*}.gate.test:${n#*:}" ;; *) echo "$n.gate.test:443" ;; esac; done; echo "host.gate.test:$RP"; } > $E/$PA.list
chmod 0644 $E/$PA.list
mkdir -p $RS/agentboxd.service.d $RS/agentbox-rootd.service.d
printf '[Service]\nEnvironment=AGENTBOX_TEST_CLI=sh\n' > $RS/agentboxd.service.d/50-proxy-gate.conf
printf '[Service]\nEnvironment=AGENTBOX_TEST_TASK_IMAGE=%s\n' $IMG > $RS/agentbox-rootd.service.d/50-proxy-gate.conf
systemctl daemon-reload
check "agentboxd with AGENTBOX_TEST_CLI=sh, and rootd with image/task" 'systemctl restart agentbox-rootd.service agentboxd.service &&
  systemctl is-active -q agentbox-rootd.service agentboxd.service'
d0=$(pdrops)

# --- a real fetch through the proxy, from a task: curl, npm (24 dependencies) and pip ---
cat > $WS/$PA/.pg/fetch.sh <<'SH'
cd /workspace/.pg
curl -sS --cacert ca.pem https://reg.gate.test/hello
rm -rf npmfx whl && mkdir npmfx && cd npmfx
printf '{"name":"fx","version":"1.0.0","dependencies":{"gate-app":"1.0.0"}}\n' > package.json
t0=$(date +%s); npm install --registry https://reg.gate.test/npm/ --cafile ../ca.pem; r=$?; echo "npm rc=$r s=$(( $(date +%s) - t0 ))"
echo "deps $(ls node_modules | grep -c '^gate-dep-') app $(node -p 'require("gate-app")')"
cd .. && pip download -q --no-deps --index-url https://reg.gate.test/simple/ --cert ca.pem -d whl gatepkg==1.0.0; r=$?; echo "pip rc=$r $(ls whl)"
SH
chown -R ag-$PA:ag-$PA $WS/$PA/.pg
m0=$(rmark)
task $PA "sh .pg/fetch.sh" fetch > $G/fetch.out 2>&1; cat $G/fetch.out
rsince $m0 > $G/rlog-fetch
TF=$(cat $G/fetch)
check "socket activation: the first task started agentbox-proxy, as agentbox-proxy, and it bound the task's proxy.sock" '
  systemctl is-active -q agentbox-proxy.service && [ "$(stat -c %U /proc/$(systemctl show -P MainPID agentbox-proxy.service))" = agentbox-proxy ] &&
  journalctl -b -u agentbox-proxy.service -o cat | grep -q "task $TF (agent $PA) registered: /run/agentbox-proxy/t/$TF/proxy.sock"'
check "a task fetches https://reg.gate.test/hello through HTTPS_PROXY and the proxy" 'grep -qx "hello from the fake registry" $G/fetch.out'
check "npm install of gate-app and its 24 dependencies through the proxy, in under 120 s" '
  grep -q "^npm rc=0 " $G/fetch.out && [ "$(sed -n "s/^npm rc=0 s=//p" $G/fetch.out)" -lt 120 ] && grep -qx "deps 24 app gate-app" $G/fetch.out'
check "pip download of gatepkg (its index link's sha256 checked by pip) through the proxy" 'grep -qx "pip rc=0 gatepkg-1.0.0-py3-none-any.whl" $G/fetch.out'
check "npm used more tunnels than 8 (§2.1's per-socket cap): the registry saw more than 8 TLS connections" '[ "$(grep -c " conn " $G/rlog-fetch)" -gt 8 ]'
check "TLS end to end: every connection's SNI and every request's Host is reg.gate.test (the client checked the registry's own certificate)" '
  [ "$(grep " conn " $G/rlog-fetch | grep -vc " sni=reg.gate.test$")" = 0 ] && [ "$(grep " req " $G/rlog-fetch | grep -vc " host=reg.gate.test ")" = 0 ] &&
  [ "$(grep -c " req " $G/rlog-fetch)" -ge 52 ]'
check "the proxy dialed only rootd's answer: every tunnel of the task went to $PUB:443" '
  tunnels $TF > $G/tf && [ "$(wc -l < $G/tf)" -gt 8 ] && [ "$(grep -vc " task $TF CONNECT reg.gate.test:443: tunnel to $PUB:443$" $G/tf)" = 0 ]'
check "rootd added $PUB . 443 to proxy_dst4 (10 min), and no LAN address to any dst set" '
  nft list set inet agentbox proxy_dst4 | grep -q "$PUB . 443 timeout 10m" && ! indst "10\.0\.2\.2"'
check "one TAINT per CONNECT, from producer proxy, on task:$TF, source proxy:reg.gate.test:443" '
  [ "$(arec TAINT producer=proxy subject=task:$TF source=proxy:reg.gate.test:443 | wc -l)" = "$(wc -l < $G/tf)" ] &&
  [ "$(arec TAINT producer=proxy subject=task:$TF | wc -l)" = "$(wc -l < $G/tf)" ]'

# --- every attempt that must fail: rebinding targets, raw IPs, IPv6, LAN, metadata, UDP, DNS ---
cat > $WS/$PA/.pg/pgc.py <<'PY'
# pgc.py OUT ITEM...: ITEM is "CONNECT host:port" or "GET http://..."; one raw request each on the egress forwarder
# (127.0.0.1:8080), printing "TARGET STATUS CODE NEXT" (CODE and NEXT from Agentbox-Denial), and the whole reply to OUT
import socket, sys
out = open(sys.argv[1], "ab")
for item in sys.argv[2:]:
    m, t = item.split(" ", 1)
    host = t if m == "CONNECT" else t.split("/")[2]
    s = socket.create_connection(("127.0.0.1", 8080), timeout=30)
    s.sendall(("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (m, t, host)).encode())
    b = b""
    while not b.startswith(b"HTTP/1.1 200"):
        try:
            d = s.recv(65536)
        except OSError:
            break
        if not d:
            break
        b += d
    s.close()
    head = b.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    f = head[0].split(" ")
    st, code, nxt = f[1] if len(f) > 1 else "000", "-", "-"
    for l in head[1:]:
        k, _, v = l.partition(":")
        if k.strip().lower() == "agentbox-denial":
            kv = dict(x.split("=", 1) for x in v.split()[1:] if "=" in x)
            code, nxt = kv.get("code", "-"), kv.get("next", "-")
    print(t, st, code, nxt)
    out.write(b"== " + item.encode() + b"\n" + b + b"\n")
PY
cat > $WS/$PA/.pg/direct.py <<PY
# direct.py: connects and datagrams with no proxy, as the task; prints "direct KIND HOST PORT RESULT MS"
import errno, socket, time
for kind, host, port in [("tcp", "10.0.2.2", $RP), ("tcp", "169.254.169.254", 80), ("tcp", "$PUB", 443),
                         ("tcp", "fd00:ec2::254", 80), ("tcp", "2606:4700:4700::1111", 443), ("udp", "10.0.2.3", 53),
                         ("udp", "1.1.1.1", 53), ("udp", "2001:4860:4860::8888", 53), ("udp", "169.254.169.254", 53)]:
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
    s.settimeout(5)
    t0 = time.monotonic()
    try:
        s.connect((host, port)) if kind == "tcp" else s.sendto(b"x", (host, port))
        r = "ok"
    except socket.timeout:
        r = "timeout"
    except OSError as e:
        r = errno.errorcode.get(e.errno, str(e))
    print("direct", kind, host, port, r, int((time.monotonic() - t0) * 1000))
PY
cat > $WS/$PA/.pg/attacks.sh <<SH
cd /workspace/.pg && rm -f replies.txt
python3 pgc.py replies.txt "CONNECT lan.gate.test:443" "CONNECT host.gate.test:$RP" "CONNECT meta.gate.test:80" \
  "CONNECT meta6.gate.test:80" "CONNECT lo.gate.test:443" "CONNECT lo6.gate.test:443" "CONNECT ula.gate.test:443" \
  "CONNECT ll6.gate.test:443" "CONNECT mapped.gate.test:443" "CONNECT nat64.gate.test:443" "CONNECT mixed.gate.test:443" \
  "CONNECT zero.gate.test:443" "CONNECT cgnat.gate.test:443" "CONNECT nx.gate.test:443" \
  "CONNECT 10.0.2.2:$RP" "CONNECT 169.254.169.254:80" "CONNECT $PUB:443" "CONNECT 1.1.1.1:443" "CONNECT [fd00:ec2::254]:80" \
  "CONNECT [::1]:443" "CONNECT [::ffff:10.0.2.2]:$RP" "CONNECT [2606:4700:4700::1111]:443" "CONNECT unlisted.gate.test:443" \
  "CONNECT api.anthropic.com:443" "CONNECT proxy.golang.org:443" \
  "GET http://169.254.169.254/latest/meta-data/" "GET http://reg.gate.test/hello"
python3 direct.py
getent hosts reg.gate.test >/dev/null && echo "dns ok" || echo "dns failed"
curl -sS -m 10 --noproxy '*' --cacert ca.pem https://reg.gate.test/hello >/dev/null 2>&1 && echo "noproxy ok" || echo "noproxy failed"
echo "log \$(grep -c EGRESS_NAME_REJECTED ~/.agentbox/denials.jsonl) \$(grep -c EGRESS_NOT_ALLOWLISTED ~/.agentbox/denials.jsonl)"
agentbox why
SH
chown -R ag-$PA:ag-$PA $WS/$PA/.pg
m0=$(rmark)
task $PA "sh .pg/attacks.sh" attacks > $G/attacks.out 2>&1; cat $G/attacks.out
TA=$(cat $G/attacks)
want() { grep -qxF "$*" $G/attacks.out; }
for n in lan.gate.test:443 host.gate.test:$RP meta.gate.test:80 lo.gate.test:443 zero.gate.test:443 cgnat.gate.test:443; do
  check "LAN, metadata, loopback and special-purpose names: CONNECT $n (allowlisted) gets 403 EGRESS_NAME_REJECTED{non_public}" "want $n 403 EGRESS_NAME_REJECTED stop"
done
for n in meta6.gate.test:80 lo6.gate.test:443 ula.gate.test:443 ll6.gate.test:443 mapped.gate.test:443 nat64.gate.test:443; do
  check "IPv6: CONNECT $n (allowlisted; ULA, loopback, link-local, IPv4-mapped or NAT64-wrapped private) gets 403 EGRESS_NAME_REJECTED" "want $n 403 EGRESS_NAME_REJECTED stop"
done
check "rebinding with two answers: mixed.gate.test ($PUB and 10.0.2.2) is refused whole, 403 EGRESS_NAME_REJECTED" 'want mixed.gate.test:443 403 EGRESS_NAME_REJECTED stop'
check "an allowlisted name with no answer: 502 EGRESS_RESOLVE_FAILED{no_such_name}, next fix" 'want nx.gate.test:443 502 EGRESS_RESOLVE_FAILED fix'
for t in 10.0.2.2:$RP 169.254.169.254:80 $PUB:443 1.1.1.1:443 "[fd00:ec2::254]:80" "[::1]:443" "[::ffff:10.0.2.2]:$RP" "[2606:4700:4700::1111]:443"; do
  check "raw IP: CONNECT $t gets 403 EGRESS_NOT_ALLOWLISTED (no list holds an address)" "want '$t' 403 EGRESS_NOT_ALLOWLISTED ask"
done
check "an unlisted name: 403 EGRESS_NOT_ALLOWLISTED, next ask" 'want unlisted.gate.test:443 403 EGRESS_NOT_ALLOWLISTED ask'
check "an LLM vendor host: 400 EGRESS_WRONG_ROUTE{llm_vendor}" 'want api.anthropic.com:443 400 EGRESS_WRONG_ROUTE fix && grep -q "\"what\":\"llm_vendor\"" $WS/$PA/.pg/replies.txt'
check "a deputy host the agent lacks: 403 EGRESS_NOT_ALLOWLISTED{deputy_host}, next human" 'want proxy.golang.org:443 403 EGRESS_NOT_ALLOWLISTED human'
check "plain HTTP through the forwarder, the metadata address and the registry: 400 EGRESS_WRONG_ROUTE{plain_http}" '
  want http://169.254.169.254/latest/meta-data/ 400 EGRESS_WRONG_ROUTE fix && want http://reg.gate.test/hello 400 EGRESS_WRONG_ROUTE fix'
check "every refusal is the §5.6 format: 25 CONNECT replies with the reason phrase, each with Agentbox-Denial, the {error, agentbox} JSON and Connection: close" '
  [ "$(grep -c "^== " $WS/$PA/.pg/replies.txt)" = 27 ] && [ "$(grep -c "^HTTP/1.1 [0-9]* agentbox [A-Z_]* (run: agentbox why)" $WS/$PA/.pg/replies.txt)" = 25 ] &&
  [ "$(grep -ic "^agentbox-denial: v1 code=" $WS/$PA/.pg/replies.txt)" = 27 ] && [ "$(grep -ic "^connection: close" $WS/$PA/.pg/replies.txt)" = 27 ] &&
  [ "$(grep -c "^{\"error\":" $WS/$PA/.pg/replies.txt)" = 27 ]'
# leak rules 1 and 2 (§5.6): a reply names only its own requested name, and never an address
cat > $G/leak.py <<'PY'
import re, sys
blocks = re.split(r"^== ", open(sys.argv[1], errors="replace").read(), flags=re.M)[1:]
bad = 0
for b in blocks:
    item, reply = b.split("\n", 1)
    target = item.split(" ", 1)[1]
    own = re.sub(r"^https?://", "", target).split("/")[0].rsplit(":", 1)[0]
    names = set(re.findall(r"[a-z0-9-]+\.gate\.test", reply))
    if re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}|fd00|fe80|ff9b|::", reply) or not names <= {own}:
        print("leak in the reply to", item)
        bad = 1
print(len(blocks), "replies")
sys.exit(bad or len(blocks) != 27)
PY
check "no refusal names an IP address or any name but the one requested (leak rules 1 and 2)" 'python3 $G/leak.py $WS/$PA/.pg/replies.txt'
check "the registry got no connection and no request from any of them" '[ -z "$(rsince $m0 conn)" ] && [ -z "$(rsince $m0 req)" ]'
check "a refused CONNECT taints nothing and opens no tunnel: no TAINT from the proxy on task:$TA" '[ -z "$(arec TAINT producer=proxy subject=task:$TA)" ] && [ -z "$(tunnels $TA)" ]'
check "without the proxy the task reaches nothing: TCP and UDP, IPv4 and IPv6, each ENETUNREACH in under 1 s" '
  [ "$(grep -c "^direct " $G/attacks.out)" = 9 ] && grep "^direct " $G/attacks.out | awk "\$5 != \"ENETUNREACH\" || \$6 >= 1000 {bad = 1} END {exit bad}"'
check "without the proxy the task has no DNS, and curl --noproxy fails" 'want dns failed && want noproxy failed'
check "the in-task forwarder logged the denials: agentbox why shows them with by=proxy" '
  want log 13 10 && grep -q "^EGRESS_WRONG_ROUTE next=fix by=proxy id=dn_" $G/attacks.out && grep -q "^EGRESS_NOT_ALLOWLISTED next=human by=proxy id=dn_" $G/attacks.out'
cat > $WS/$PB/.pg/other.sh <<'SH'
cd /workspace/.pg
curl -sS --cacert ca.pem https://reg.gate.test/hello
curl -s -o /dev/null -w 'lan %{http_connect}\n' https://lan.gate.test/
SH
chown -R ag-$PB:ag-$PB $WS/$PB/.pg
task $PB "sh .pg/other.sh" other > $G/other.out 2>&1; cat $G/other.out
check "the per-agent list: $PB reaches the registry through common.list, but gets 403 for $PA's own entry" '
  grep -qx "hello from the fake registry" $G/other.out && grep -qx "lan 403" $G/other.out'

# --- rebinding: the allowlisted name moves to the registry's LAN address, loopback, metadata, then two answers ---
cat > $WS/$PA/.pg/rebind.sh <<'SH'
cd /workspace/.pg
for i in 1 2 3 4 5; do
  while [ ! -e go$i ]; do sleep 0.1; done
  python3 pgc.py replies-rebind.txt "CONNECT reg.gate.test:443" | sed "s/^/step$i /"
  curl -sS -m 20 --cacert ca.pem https://reg.gate.test/hello 2>&1 | sed "s/^/step$i /"
  touch done$i
done
SH
rm -f $WS/$PA/.pg/go* $WS/$PA/.pg/done* $WS/$PA/.pg/replies-rebind.txt; chown -R ag-$PA:ag-$PA $WS/$PA/.pg
task $PA "sh .pg/rebind.sh" rebind > $G/rebind.out 2>&1 &
tw=$!
rq=""
# shellcheck disable=SC2086 # one record per word
for i in 1 2 3 4 5; do
  case $i in 1) to=10.0.2.2 ;; 2) to=127.0.0.1 ;; 3) to=169.254.169.254 ;; 4) to=$PUB,10.0.2.2 ;; 5) to=$PUB ;; esac
  dns reg.gate.test=$to $BASE || echo "dns step $i failed"
  m=$(rmark); touch $WS/$PA/.pg/go$i; wait_file $WS/$PA/.pg/done$i 60 || echo "rebind step $i: no answer"
  rq="$rq $(rcount $m req)"
done
wait $tw; cat $G/rebind.out
echo "registry requests per step:$rq"
check "rebinding: reg.gate.test moved to the registry's own LAN address (10.0.2.2) gets 403 EGRESS_NAME_REJECTED, though it was allowed a moment ago" 'grep -qx "step1 reg.gate.test:443 403 EGRESS_NAME_REJECTED stop" $G/rebind.out'
check "  ... moved to 127.0.0.1, and to 169.254.169.254: 403 EGRESS_NAME_REJECTED" 'grep -qx "step2 reg.gate.test:443 403 EGRESS_NAME_REJECTED stop" $G/rebind.out && grep -qx "step3 reg.gate.test:443 403 EGRESS_NAME_REJECTED stop" $G/rebind.out'
check "  ... a public and a private answer at once: refused whole" 'grep -qx "step4 reg.gate.test:443 403 EGRESS_NAME_REJECTED stop" $G/rebind.out'
check "  ... the registry got no request in any of those steps; back on $PUB the fetch works again" '[ "$rq" = " 0 0 0 0 1" ] && grep -qx "step5 hello from the fake registry" $G/rebind.out'
check "  ... and no rebinding answer reached any dst set" '! indst "(10\.0\.2\.2|127\.0\.0\.1|169\.254\.169\.254) \. 443"'
check "  ... rootd's DENY records name the refusal, by proxy, with the address only in detail" 'arec DENY by=proxy code=EGRESS_NAME_REJECTED | grep -q "\"detail\": \"10.0.2.2: "'

# --- taint before bytes: auditd down ---
cat > $WS/$PA/.pg/audit.sh <<'SH'
cd /workspace/.pg
touch ready; while [ ! -e go ]; do sleep 0.1; done
python3 pgc.py replies-audit.txt "CONNECT reg.gate.test:443"
touch done
SH
rm -f $WS/$PA/.pg/ready $WS/$PA/.pg/go $WS/$PA/.pg/done; chown -R ag-$PA:ag-$PA $WS/$PA/.pg
task $PA "sh .pg/audit.sh" audit > $G/audit.out 2>&1 &
tw=$!
wait_file $WS/$PA/.pg/ready 180
m0=$(rmark)
AS="agentbox-auditd-rootd.socket agentbox-auditd-agentboxd.socket agentbox-auditd-proxy.socket agentbox-auditd-keys.socket agentbox-auditd-git.socket"
# shellcheck disable=SC2086 # one unit per word
systemctl stop agentbox-auditd.service $AS
touch $WS/$PA/.pg/go; wait_file $WS/$PA/.pg/done 60
c1=$(rcount $m0 conn) q1=$(rcount $m0 req)
# shellcheck disable=SC2086 # one unit per word
systemctl start $AS agentbox-auditd.service
wait $tw; cat $G/audit.out
check "auditd down: an allowlisted CONNECT gets 503 AUDIT_UNAVAILABLE, and the registry gets no TLS hello and no request" '
  grep -qx "reg.gate.test:443 503 AUDIT_UNAVAILABLE retry" $G/audit.out && [ "$c1" = 0 ] && [ "$q1" = 0 ]'

# --- the proxy restarts and crashes mid-task; peer checks on the live task's socket ---
cat > $WS/$PA/.pg/restart.sh <<'SH'
cd /workspace/.pg
for i in 1 2 3; do
  [ $i = 1 ] || { touch ready$i; while [ ! -e go$i ]; do sleep 0.1; done; }
  curl -sS -m 20 --cacert ca.pem https://reg.gate.test/hello | sed "s/^/fetch$i /"
done
touch ready4; while [ ! -e go4 ]; do sleep 0.1; done
SH
rm -f $WS/$PA/.pg/ready* $WS/$PA/.pg/go*; chown -R ag-$PA:ag-$PA $WS/$PA/.pg
task $PA "sh .pg/restart.sh" restart > $G/restart.out 2>&1 &
tw=$!
wait_file $WS/$PA/.pg/ready2 180
TS=$(cat $G/restart)
systemctl restart agentbox-proxy.service; touch $WS/$PA/.pg/go2
wait_file $WS/$PA/.pg/ready3 60
nr=$(systemctl show -P NRestarts agentbox-proxy.service)
systemctl kill -s KILL agentbox-proxy.service
for i in $(seq 100); do [ "$(systemctl show -P NRestarts agentbox-proxy.service)" -gt "$nr" ] && systemctl is-active -q agentbox-proxy.service && break; sleep 0.1; done
touch $WS/$PA/.pg/go3
wait_file $WS/$PA/.pg/ready4 60
P=/run/agentbox-proxy/t/$TS
check "the task's proxy.sock is agentbox-proxy:ag-$PA 0660 in rootd's setgid dir (2750), and sockets check passes" '
  [ "$(stat -c "%U:%G %a" $P)" = "agentbox-proxy:ag-$PA 2750" ] && [ "$(stat -c "%U:%G %a %F" $P/proxy.sock)" = "agentbox-proxy:ag-$PA 660 socket" ] && $B sockets check'
check "another agent's uid can't reach that socket (EACCES)" '! runuser -u ag-$PB -- python3 -c "import socket; socket.socket(socket.AF_UNIX).connect(\"$P/proxy.sock\")" 2>$G/eacces; grep -q PermissionError $G/eacces'
check "svc-proxy.sock: agentbox-proxy itself gets no answer (uid 0 only), another uid can't open it" '
  [ "$(runuser -u agentbox-proxy -- python3 $G/svc.py "{\"call\":\"list\"}")" = closed ] && ! runuser -u agentbox -- python3 $G/svc.py "{\"call\":\"list\"}" 2>/dev/null'
touch $WS/$PA/.pg/go4; wait $tw; cat $G/restart.out
check "a proxy restart and a crash (SIGKILL) mid-task: each time the task's socket is rebound, and the next fetch works" '
  for i in 1 2 3; do grep -qx "fetch$i hello from the fake registry" $G/restart.out || exit 1; done &&
  [ "$(journalctl -b -u agentbox-proxy.service -o cat | grep -c "task $TS (agent $PA) registered: ")" -ge 3 ]'

# --- revoke cuts a live tunnel ---
cat > $WS/$PA/.pg/revoke.sh <<'SH'
cd /workspace/.pg
t0=$(date +%s); curl -sS -m 90 --cacert ca.pem -o /tmp/slow https://reg.gate.test/slow; r=$?; echo "slow rc=$r s=$(( $(date +%s) - t0 )) bytes=$(wc -c < /tmp/slow)"
curl -s -o /dev/null -m 20 -w 'after %{http_connect}\n' --cacert ca.pem https://reg.gate.test/hello
SH
chown -R ag-$PA:ag-$PA $WS/$PA/.pg
task $PA "sh .pg/revoke.sh" revoke > $G/revoke.out 2>&1 &
tw=$!
for i in $(seq 1800); do rlog | grep -q " req .* /slow$" && break; sleep 0.1; done
TV=$(cat $G/revoke)
sleep 2
rv=$(python3 $G/svc.py "{\"call\":\"revoke\",\"task\":\"$TV\"}")
tr0=$(date +%s)
for i in $(seq 100); do rlog | grep -q " done .* /slow 200$" && break; sleep 0.1; done
tr1=$(date +%s)
wait $tw; cat $G/revoke.out
check "revoke{task} on svc-proxy.sock (rootd's call): the proxy cuts the task's live tunnel within 5 s, and the registry sees it end" '
  [ "$rv" = "{\"ok\":true}" ] && [ $((tr1 - tr0)) -le 5 ] && rlog | grep -q " done .* /slow 200$" &&
  grep -q "^slow rc=[1-9][0-9]* s=[0-9]* " $G/revoke.out && [ "$(sed -n "s/^slow rc=[0-9]* s=\([0-9]*\) .*/\1/p" $G/revoke.out)" -lt 40 ]'
check "  ... its proxy.sock is gone, and its next CONNECT gets the forwarder's 503 BROKER_UNAVAILABLE" 'grep -qx "after 503" $G/revoke.out'

# --- agentbox-proxy itself: nft, DNS and the unit ---
check "no task's traffic made nft drop a packet for agentbox-proxy (it dialed only rootd's answers)" '[ "$(pdrops)" = "$d0" ]'
for p in "tcp 10.0.2.2 $((RP - 300))" "tcp 192.168.1.10 443" "tcp 169.254.169.254 80" "tcp 1.1.1.1 443" "tcp 127.0.0.53 53" "udp 127.0.0.53 53" "udp 10.0.2.3 53" "udp 1.1.1.1 53" "udp 169.254.169.254 53"; do
  check "as agentbox-proxy, nft drops $p" 'd=$(pdrops); r=$(runuser -u agentbox-proxy -- python3 $G/probe.py $p); echo "$p: $r"; case $r in timeout|EPERM) ;; *) exit 1 ;; esac; [ "$(pdrops)" -gt "$d" ]'
done
check "as agentbox-proxy, IPv6 to anywhere rootd did not return fails" 'r=$(runuser -u agentbox-proxy -- python3 $G/probe.py tcp 2606:4700:4700::1111 443); echo "$r"; case $r in timeout|EPERM|ENETUNREACH) ;; *) exit 1 ;; esac'
PP=$(systemctl show -P MainPID agentbox-proxy.service)
check "in the proxy's own mount namespace, resolved's sockets are inaccessible and its uid resolves nothing" '
  [ "$(nsenter -t $PP -m -- stat -c %a /run/systemd/resolve)" = 0 ] && [ "$(nsenter -t $PP -m -- stat -c %a /run/dbus/system_bus_socket)" = 0 ] &&
  ! nsenter -t $PP -m -S $PU -G "$(id -g agentbox-proxy)" -- getent hosts example.com'
check "agentbox-proxy.service: User=agentbox-proxy, AF_UNIX AF_INET AF_INET6, ProtectSystem=strict, NoNewPrivileges, no capabilities, socket-started" '
  [ "$(systemctl show -P User agentbox-proxy.service)" = agentbox-proxy ] && [ "$(systemctl show -P ProtectSystem agentbox-proxy.service)" = strict ] &&
  [ "$(systemctl show -P RestrictAddressFamilies agentbox-proxy.service | tr " " "\n" | sort | paste -sd " ")" = "AF_INET AF_INET6 AF_UNIX" ] &&
  [ "$(systemctl show -P NoNewPrivileges agentbox-proxy.service)" = yes ] && [ -z "$(systemctl show -P CapabilityBoundingSet agentbox-proxy.service)" ] &&
  [ "$(systemctl show -P UnitFileState agentbox-proxy.service)" = static ] && systemctl is-enabled -q agentbox-proxy-svc.socket &&
  systemd-analyze verify agentbox-proxy.service agentbox-proxy-svc.socket'
check "the proxy's environment holds no credential-like variable, and its journal no request header" '
  ! tr "\0" "\n" < /proc/$PP/environ | grep -iE "key|token|secret|passw" && ! journalctl -b -u agentbox-proxy.service -o cat | grep -iE "^(user-agent|authorization|host):"'

# --- cleanup: the gate's name, route and drop-in go; the box's own state stays ---
rm -f /run/systemd/resolved.conf.d/90-proxy-gate.conf; systemctl stop pg-dns.service 2>/dev/null; systemctl restart systemd-resolved.service
nft delete table ip proxygate 2>/dev/null
python3 -c "import sqlite3; c=sqlite3.connect(\"$DB\"); c.execute(\"delete from set_elements where set_name=\x27allow_private4\x27 and element=\x27$PU . 10.0.2.2 . $RP\x27\"); c.commit()"
$B egress refill >/dev/null
$B egress remove --svc proxy --entry reg.gate.test:443 >/dev/null
rm -f $RS/agentboxd.service.d/50-proxy-gate.conf $RS/agentbox-rootd.service.d/50-proxy-gate.conf; systemctl daemon-reload
systemctl restart agentbox-rootd.service agentboxd.service
podman rmi -f $IMG >/dev/null 2>&1
check "no task is left live" '[ "$($B task list | python3 -c "import json,sys; print(sum(1 for t in json.load(sys.stdin)[\"tasks\"] if \"end_reason\" not in t))")" = 0 ]'
check "fwcheck passes, and allow_private4 is empty again" '$B fwcheck && ! nft list set inet agentbox allow_private4 | grep -q "10.0.2.2"'
check "the audit chain verifies" '$B audit verify'
check "no failed units" 'sleep 3; [ -z "$(systemctl --failed --no-legend --plain)" ]'
journalctl -b -u agentbox-proxy.service -o short-precise --no-pager | tail -60
echo "fails=$fails"
EOF
  ;;
*) die "unknown step $s (install, release or checks)" ;;
esac; done
! grep -q '^[0-9:]* FAIL' "$OUT"

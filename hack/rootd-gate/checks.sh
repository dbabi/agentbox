#!/bin/sh
# TEST FIXTURE: hack/rootd-gate.sh copies this into the test VM as /run/rg/checks.sh and runs each phase as root.
#   checks.sh setup | main | after-reboot | cleanup
# Every check prints PASS or FAIL; each phase ends with fails=N. FLOW (host:port, a public HTTP server reached through
# the box's real uplink) comes from the environment.
set -u
A=/var/lib/agentbox/current/bin/agentbox
RG="python3 /run/rg/rg.py"
R=/run/agentbox-rootd
IF=$(ip -o route show default | awk '{print $5; exit}')
FLOW_HOST=${FLOW%:*} FLOW_PORT=${FLOW##*:}
fails=0
# subshell: a check that calls exit must not end the phase
check() { if (eval "$2") >>/run/rg/check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
note() { echo "NOTE $*"; }
# res SVC HOST PORT [AS]: a resolve request on resolve-SVC.sock as uid AS (default agentbox-SVC); prints the reply
res() { runuser -u "${4:-agentbox-$1}" -- $RG req "$R/resolve-$1.sock" "{\"op\":\"resolve\",\"host\":\"$2\",\"port\":$3}"; }
reason() { res "$@" | python3 -c 'import json,sys; r=json.load(sys.stdin); print("ok" if r["ok"] else r["reason"])' 2>/dev/null; }
addrs() { res "$@" | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["addrs"]))'; }
v4() { for a in $1; do case $a in *:*) ;; *) echo "$a"; return ;; esac; done; }
set_has() { nft list set inet agentbox "$1" | grep -qF "$2"; }
sets_have() { nft list table inet agentbox | grep -qF "$1"; }
allow() { $A egress allow --svc "$1" --entry "$2" >/dev/null; }
remove() { $A egress remove --svc "$1" --entry "$2"; }
# as UID CMD...: a broker or test uid runs CMD
as() { u=$1; shift; runuser -u "$u" -- "$@"; }
# chain SEQ [ENTRY]: with ENTRY, exit 0 if auditd's chain has a DENY for it with a seq above SEQ; without, print the
# newest seq (SEQ is ignored)
chain() { python3 - "$@" "${AUDIT_DIR:-/var/lib/agentbox/audit}"/seg-*.jsonl <<'PY'
import json, sys
seq, entry, files = int(sys.argv[1]), sys.argv[2], sys.argv[3:]
top = 0
for f in files:
    for l in open(f, errors="replace"):
        try:
            r = json.loads(l)
        except ValueError:
            continue
        top = max(top, r.get("seq", 0))
        if entry and r.get("seq", 0) > seq and r.get("type") == "DENY" and (r.get("body") or {}).get("entry") == entry:
            sys.exit(0)
if not entry:
    print(top)
sys.exit(1 if entry else 0)
PY
}
dropin=/run/systemd/system/agentbox-rootd.service.d/90-rootd-gate.conf
fast() { # test timings for this boot only (/run): 30 s elements, a 10 s timer
  mkdir -p "${dropin%/*}"
  printf '[Service]\nExecStart=\nExecStart=%s rootd --element-timeout 30s --refill-interval 10s\n' "$A" > "$dropin"
  systemctl daemon-reload && systemctl restart agentbox-rootd.service
}

case $1 in
setup)
  check "the release's firewall is up and fwcheck passes" 'systemctl is-active -q agentbox-firewall.service && $A fwcheck'
  # Addresses that look public but are the box's own, on-link or routed off the default interface (Appendix B check 3).
  ip addr add 192.88.99.15/32 dev "$IF"; ip -6 addr add 2600:ffff::15/128 dev "$IF" nodad
  ip route add 192.88.98.0/24 dev "$IF"
  ip link add rg0 type dummy && ip link set rg0 up && ip route add 192.88.97.0/24 dev rg0
  grep -q hosts.gate.test /etc/hosts || echo '192.88.96.9 hosts.gate.test' >> /etc/hosts
  # gate-dns answers *.gate.test and relays everything else to slirp's DNS; resolved uses only it for this boot
  systemd-run -q --unit=rg-dns /run/rg/gate-dns -listen 127.0.0.153:53 -upstream 10.0.2.3:53 \
    -a pub.gate.test=192.88.96.1,2600:ffff::1 -a priv.gate.test=10.1.2.3 -a mixed.gate.test=192.88.96.2,192.168.1.10 \
    -a cgnat.gate.test=100.64.0.1 -a doc.gate.test=198.51.100.7 -a mapped.gate.test=::ffff:8.8.8.8 \
    -a nat64p.gate.test=64:ff9b::a00:1 -a nat64ok.gate.test=64:ff9b::808:808 -a own.gate.test=192.88.99.15 \
    -a own6.gate.test=2600:ffff::15 -a onlink.gate.test=192.88.98.7 -a tail.gate.test=192.88.97.7 \
    -a lo.gate.test=127.0.0.1 -a ll.gate.test=fe80::1 -a mc.gate.test=224.0.0.251 -a ula.gate.test=fd00::1 \
    -a ipv4only.arpa=192.0.0.170,192.0.0.171,2600:ffff:64::c000:aa,2600:ffff:64::c000:ab \
    -a nsp.gate.test=2600:ffff:64::c0a8:101
  # DNS64 with a network-specific prefix (RFC 7050): ipv4only.arpa's AAAA puts 2600:ffff:64::/96 in front of 192.0.0.170
  mkdir -p /run/systemd/resolved.conf.d
  printf '[Resolve]\nDNS=127.0.0.153\nDomains=~.\n' > /run/systemd/resolved.conf.d/90-rootd-gate.conf
  systemctl restart systemd-resolved.service
  sleep 2
  check "rootd starts (READY) once the firewall is up" 'systemctl start agentbox-rootd.service && systemctl is-active -q agentbox-rootd.service'
  check "gate-dns answers through resolved"       'resolvectl query -4 pub.gate.test | grep -q 192.88.96.1'
  check "the relay still resolves public names"   "resolvectl query $FLOW_HOST >/dev/null"
  ;;

main)
  echo "== install path and units"
  check "service users and groups (sysusers.d/agentbox.conf)" 'for u in agentbox agentbox-audit agentbox-approve agentbox-proxy agentbox-keys agentbox-git; do getent passwd $u >/dev/null || exit 1; done; getent group agentbox-admin >/dev/null'
  check "/run/agentbox-rootd is root 0711 (tmpfiles.d/agentbox.conf)" '[ "$(stat -c %U:%G:%a $R)" = root:root:711 ]'
  check "rootd enabled, active, Type=notify, NotifyAccess=main" 'systemctl is-enabled -q agentbox-rootd.service && systemctl is-active -q agentbox-rootd.service && [ "$(systemctl show -P Type agentbox-rootd.service)" = notify ] && [ "$(systemctl show -P NotifyAccess agentbox-rootd.service)" = main ]'
  check "rootd Requires= and After= reconcile and firewall" 'for p in Requires After; do v=$(systemctl show -P $p agentbox-rootd.service); echo "$v" | grep -qw agentbox-reconcile.service && echo "$v" | grep -qw agentbox-firewall.service || exit 1; done'
  check "rootd sandbox: AF_UNIX AF_NETLINK only, ProtectSystem=strict, ProtectHome, ProtectKernelModules" '[ "$(systemctl show -P RestrictAddressFamilies agentbox-rootd.service | tr " " "\n" | sort | paste -sd " ")" = "AF_NETLINK AF_UNIX" ] && [ "$(systemctl show -P ProtectSystem agentbox-rootd.service)" = strict ] && [ "$(systemctl show -P ProtectHome agentbox-rootd.service)" = yes ] && [ "$(systemctl show -P ProtectKernelModules agentbox-rootd.service)" = yes ]'
  check "systemd-analyze verify: rootd service and sockets" 'systemd-analyze verify agentbox-rootd.service agentbox-rootd-admin.socket agentbox-audit-seal.socket agentbox-rootd-resolve-proxy.socket agentbox-rootd-resolve-keys.socket agentbox-rootd-resolve-git.socket'
  check "sockets bound by PID 1 with the §2.1 owner and mode" '[ "$(stat -c %U:%G:%a $R/rootd-admin.sock)" = root:agentbox-admin:660 ] && [ "$(stat -c %U:%G:%a $R/audit-seal.sock)" = root:agentbox-audit:660 ] && for s in proxy keys git; do [ "$(stat -c %U:%G:%a $R/resolve-$s.sock)" = root:agentbox-$s:660 ] || exit 1; done'
  check "rootd holds no IP socket and listens on nothing but its unix sockets" 'p=$(systemctl show -P MainPID agentbox-rootd.service); [ "$p" -gt 0 ] && [ -z "$(ss -tuwanpH | grep "pid=$p,")" ]'
  check "rootd.db: root 0600, WAL" '[ "$(stat -c %U:%a /var/lib/agentbox/rootd.db)" = root:600 ] && [ "$(python3 -c "import sqlite3; print(sqlite3.connect(\"file:/var/lib/agentbox/rootd.db?mode=ro\", uri=True).execute(\"PRAGMA journal_mode\").fetchone()[0])")" = wal ]'
  check "rootd.db tables are STRICT" '[ "$(python3 -c "import sqlite3; c=sqlite3.connect(\"file:/var/lib/agentbox/rootd.db?mode=ro\", uri=True); print(sum(1 for r in c.execute(\"select sql from sqlite_master where type=\x27table\x27\") if \"STRICT\" in r[0]))")" = 3 ]'

  echo "== peer checks (§2.1)"
  useradd -r -M -s /usr/sbin/nologin -G agentbox-admin rg-admin 2>/dev/null; useradd -r -M -s /usr/sbin/nologin -G agentbox-keys rg-keysgrp 2>/dev/null
  check "root may use rootd-admin.sock"           '$A egress list'
  check "an agentbox-admin member may use rootd-admin.sock" 'as rg-admin $A egress list'
  check "a non-member can't open rootd-admin.sock (mode 0660)" '! as nobody $A egress list'
  check "rootd refuses a uid that has the socket's group but is not agentbox-keys (SO_PEERCRED)" '[ "$(as rg-keysgrp $RG req $R/resolve-keys.sock "{\"op\":\"resolve\",\"host\":\"pub.gate.test\",\"port\":443}")" = closed ]'
  check "root is refused on resolve-keys.sock: keys only"  '[ "$($RG req $R/resolve-keys.sock "{\"op\":\"resolve\",\"host\":\"pub.gate.test\",\"port\":443}")" = closed ]'
  check "agentbox-git can't open resolve-keys.sock" '! as agentbox-git $RG req $R/resolve-keys.sock "{}"'
  check "root is refused on audit-seal.sock: agentbox-audit only" '[ "$($RG req $R/audit-seal.sock "{\"call\":\"audit.create\",\"seg\":1}")" = closed ]'
  check "SCM_RIGHTS on rootd-admin.sock: connection closed, no reply" '$RG sendfd $R/rootd-admin.sock'
  check "an unknown op gets bad_request"          '$RG req $R/rootd-admin.sock "{\"op\":\"nope\"}" | grep -q bad_request'
  usermod -aG agentbox-admin agentbox-approve
  check "rootd refuses to start while agentbox-approve is in agentbox-admin" '! systemctl restart agentbox-rootd.service && journalctl -u agentbox-rootd.service -n 20 -o cat | grep -q "agentbox-approve is a member of agentbox-admin"'
  gpasswd -d agentbox-approve agentbox-admin >/dev/null
  systemctl reset-failed agentbox-rootd.service; systemctl start agentbox-rootd.service
  check "and starts once it is not"                'systemctl is-active -q agentbox-rootd.service'

  echo "== production element timeout (Appendix B: 10 min)"
  allow keys pub.gate.test:443
  check "keys resolves an allowlisted public name"  '[ "$(reason keys pub.gate.test 443)" = ok ]'
  check "its v4 and v6 answers are in keys_dst4/6 with timeout 10m" 'nft list set inet agentbox keys_dst4 | grep -q "192.88.96.1 . 443 timeout 10m expires" && nft list set inet agentbox keys_dst6 | grep -q "2600:ffff::1 . 443 timeout 10m expires"'
  check "rootd.db recorded them first (set_elements)" 'python3 -c "import sqlite3; c=sqlite3.connect(\"file:/var/lib/agentbox/rootd.db?mode=ro\", uri=True); rows=set(c.execute(\"select set_name, element from set_elements\")); exit(0 if {(\"keys_dst4\",\"192.88.96.1 . 443\"),(\"keys_dst6\",\"2600:ffff::1 . 443\")} <= rows else 1)"'
  check "no other set got them"                   '! set_has git_dst4 192.88.96.1 && ! set_has proxy_dst4 192.88.96.1'
  fast
  check "test timings on (30 s elements, 10 s timer)" 'systemctl is-active -q agentbox-rootd.service && systemctl show -P ExecStart agentbox-rootd.service | grep -q "element-timeout 30s"'

  echo "== refused names: private, special-purpose, NAT64-wrapped, the box's own (Appendix B)"
  t_deny=$(date +%s)
  seq0=$(chain 0 "")
  for n in priv mixed cgnat doc mapped nat64p nsp own own6 onlink tail lo ll mc ula; do allow keys $n.gate.test:443; done
  allow keys nat64ok.gate.test:443; allow keys hosts.gate.test:443; allow keys nx.gate.test:443
  before=$(nft list table inet agentbox | grep -c ' \. 443')
  for n in priv mixed cgnat doc mapped nat64p nsp own own6 onlink tail lo ll mc ula; do
    check "$n.gate.test is refused non_public" "[ \"\$(reason keys $n.gate.test 443)\" = non_public ]"
  done
  check "none of their addresses reached any set" '[ "$(nft list table inet agentbox | grep -c " \. 443")" = "$before" ] && for a in 10.1.2.3 192.88.96.2 192.168.1.10 100.64.0.1 198.51.100.7 8.8.8.8 64:ff9b::a00:1 2600:ffff:64::c0a8:101 192.88.99.15 2600:ffff::15 192.88.98.7 192.88.97.7 127.0.0.1 fe80::1 224.0.0.251 fd00::1; do ! sets_have "$a . 443" || exit 1; done'
  check "the refusal's detail names the address and check, in rootd's DENY log only" 'journalctl -u agentbox-rootd.service --since @$t_deny -o cat | grep -q "DENY by=rootd svc=keys entry=own.gate.test:443 code=non_public detail=\"192.88.99.15: route_not_unicast"'
  # rootd sends DENY records from one throttled sender: give it a moment; only records after seq0 count
  check "the refusal is also a DENY record in auditd's chain, after this run's start (seq > $seq0)" 'i=0; until chain $seq0 own.gate.test:443; do i=$((i+1)); [ $i -lt 10 ] || exit 1; sleep 1; done'
  check "an address under the network's own NAT64 prefix (DNS64, RFC 7050) that wraps 192.168.x is refused" 'journalctl -u agentbox-rootd.service --since @$t_deny -o cat | grep -q "entry=nsp.gate.test:443 code=non_public detail=\"2600:ffff:64::c0a8:101: nat64_private"'
  check "an on-link address is refused by the route check" 'journalctl -u agentbox-rootd.service --since @$t_deny -o cat | grep -q "entry=onlink.gate.test:443 code=non_public detail=\"192.88.98.7: route_on_link"'
  check "a tailnet-like interface route is refused by the route check" 'journalctl -u agentbox-rootd.service --since @$t_deny -o cat | grep -q "entry=tail.gate.test:443 code=non_public detail=\"192.88.97.7: route_not_default_interface"'
  check "a NAT64 address wrapping a public IPv4 passes" '[ "$(reason keys nat64ok.gate.test 443)" = ok ] && set_has keys_dst6 "64:ff9b::808:808 . 443"'
  check "/etc/hosts answers nothing (NO_SYNTHESIZE, NO_ZONE): no_such_name" '[ "$(reason keys hosts.gate.test 443)" = no_such_name ] && ! sets_have 192.88.96.9'
  check "NXDOMAIN: no_such_name"                  '[ "$(reason keys nx.gate.test 443)" = no_such_name ]'
  check "a name on no list: not_allowlisted" '[ "$(reason keys pub.gate.test 8443)" = not_allowlisted ] && [ "$(reason keys unlisted.gate.test 443)" = not_allowlisted ]'
  # gate-dns logs every name it is asked; nx.gate.test (looked up just above) shows the log works
  check "and no lookup: gate-dns was asked for nx.gate.test but never for unlisted.gate.test" 'sleep 1; q=$(journalctl -u rg-dns.service -o cat); echo "$q" | grep -q "query nx.gate.test$" && ! echo "$q" | grep -q "query unlisted.gate.test$"'
  check "keys' list is not git's: git gets not_allowlisted" '[ "$(reason git pub.gate.test 443)" = not_allowlisted ]'
  check "the proxy resolves nothing without a live task (no task registry yet)" '[ "$(reason proxy pub.gate.test 443)" = not_allowlisted ]'
  check "a bad host (IP literal, one label) is refused"  '[ "$(reason keys 1.2.3.4 443)" = not_allowlisted ] && [ "$(reason keys localhost 443)" = not_allowlisted ]'
  # §9: an allowlist edit is INTENT, ACK, effect, RESULT; with auditd and its sockets stopped nothing executes
  E=/var/lib/agentbox/control/egress; sum0=$(cat $E/*.list 2>/dev/null | sha256sum)
  systemctl stop agentbox-auditd.service agentbox-auditd-agentboxd.socket agentbox-auditd-git.socket agentbox-auditd-keys.socket agentbox-auditd-proxy.socket agentbox-auditd-rootd.socket
  check "auditd down: egress allow and remove fail, and no list file changes" '! allow keys down.gate.test:443 && ! remove keys pub.gate.test:443 >/dev/null && [ "$(cat $E/*.list 2>/dev/null | sha256sum)" = "$sum0" ]'
  systemctl start agentbox-auditd-agentboxd.socket agentbox-auditd-git.socket agentbox-auditd-keys.socket agentbox-auditd-proxy.socket agentbox-auditd-rootd.socket agentbox-auditd.service
  seqa=$(chain 0 "")
  check "auditd back: egress allow works, its INTENT and RESULT (origin admin) are in the chain" 'allow keys down.gate.test:443 && remove keys down.gate.test:443 >/dev/null && [ "$(cat $E/*.list | sha256sum)" = "$sum0" ] && python3 - $seqa /var/lib/agentbox/audit/seg-*.jsonl <<EOF
import json, sys
seq, ops = int(sys.argv[1]), {}
for f in sys.argv[2:]:
    for l in open(f, errors="replace"):
        try:
            r = json.loads(l)
        except ValueError:
            continue
        b = r.get("body") or {}
        if r.get("seq", 0) > seq and r.get("type") in ("INTENT", "RESULT"):
            ops.setdefault(b.get("opId"), []).append((r["type"], b.get("name"), b.get("origin"), b.get("status")))
want = [[("INTENT", "egress.allow", "admin", None), ("RESULT", None, None, "executed")],
        [("INTENT", "egress.remove", "admin", None), ("RESULT", None, None, "executed")]]
sys.exit(0 if sorted(ops.values()) == sorted(want) else 1)
EOF'
  check "rootd refuses a deputy host in common.list" '! $A egress allow --svc proxy --entry proxy.golang.org:443'

  echo "== a broker reaches only what rootd resolved"
  allow keys "$FLOW"
  # before rootd resolves it: the address is not in keys_dst4 (it may have been, briefly, in another test run)
  FIP=$(v4 "$(resolvectl query -4 "$FLOW_HOST" | awk '/: /{print $2}' | tr '\n' ' ')")
  [ -n "$FIP" ] || FIP=0.0.0.1
  check "before resolution keys can't connect to $FLOW_HOST ($FIP:$FLOW_PORT)" '! set_has keys_dst4 "$FIP . $FLOW_PORT" && ! as agentbox-keys $RG connect $FIP $FLOW_PORT 3'
  check "brokers do no DNS: 127.0.0.53 is unreachable for agentbox-keys" '! as agentbox-keys $RG udpdns 127.0.0.53'
  check "and the system resolver gives the broker nothing" '! as agentbox-keys getent ahosts $FLOW_HOST'
  # resolved's Varlink socket (0666) and its D-Bus API are AF_UNIX, which nft never sees: the broker units hide both
  # (§6.1). The probes work for an unconfined uid, and fail under exactly the units' InaccessiblePaths=.
  BUS="busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResolveHostname isit 0 pub.gate.test 0 0"
  check "the AF_UNIX probes resolve for an unconfined agentbox-keys (Varlink and D-Bus)" 'as agentbox-keys $RG vresolve pub.gate.test && as agentbox-keys $BUS'
  check "with InaccessiblePaths=/run/systemd/resolve /run/dbus/system_bus_socket both fail" "systemd-run -q --wait --pipe -p User=agentbox-keys -p InaccessiblePaths='/run/systemd/resolve /run/dbus/system_bus_socket' sh -c '! $RG vresolve pub.gate.test && ! $BUS'"
  for b in proxy keys git; do
    if systemctl cat agentbox-$b.service >/dev/null 2>&1; then
      check "agentbox-$b.service hides resolved's Varlink and D-Bus sockets" "systemctl show -P InaccessiblePaths agentbox-$b.service | grep -q /run/systemd/resolve && systemctl show -P InaccessiblePaths agentbox-$b.service | grep -q /run/dbus/system_bus_socket"
    else
      note "agentbox-$b.service is not in this release yet (docs/THREAT-MODEL.md residual); its unit check runs once it lands"
    fi
  done
  IPS=$(addrs keys "$FLOW_HOST" "$FLOW_PORT"); IP=$(v4 "$IPS")
  note "rootd resolved $FLOW for keys: $IPS"
  check "after rootd resolved it keys connects to $IP:$FLOW_PORT" '[ -n "$IP" ] && as agentbox-keys $RG connect $IP $FLOW_PORT 5'
  # a port the host does answer on (root, unconfined, reaches it), so only keys_dst4's port match can refuse it
  OP=443; [ "$FLOW_PORT" != 443 ] || OP=80
  # nft may print the uid as a name, quoted or not, or as a number
  kd() { nft list chain inet agentbox output | grep -E "meta skuid (\"?agentbox-keys\"?|$(id -u agentbox-keys)) counter" | grep -o 'packets [0-9]*' | awk '{print $2}'; }
  check "but not to $IP:$OP, which answers root: keys' catch-all drop takes it" '$RG connect $IP $OP 5 && b=$(kd) && ! as agentbox-keys $RG connect $IP $OP 3 && [ "$(kd)" -gt "$b" ]'
  check "git can't use keys' answer"             '! as agentbox-git $RG connect $IP $FLOW_PORT 3'
  check "the proxy can't use keys' answer"       '! as agentbox-proxy $RG connect $IP $FLOW_PORT 3'
  check "a public address nobody resolved stays blocked (1.1.1.1:80)" '! as agentbox-keys $RG connect 1.1.1.1 80 3'
  nft add element inet agentbox keys_dst4 '{ 1.1.1.1 . 80 timeout 30s }'
  check "an element rootd did not add is removed at the next refill (notify)" '$A egress refill >/dev/null && ! set_has keys_dst4 "1.1.1.1 . 80"'

  echo "== refill: READY=1 only after the sets match rootd.db; the timer; notify"
  addrs keys pub.gate.test 443 >/dev/null
  nft flush set inet agentbox keys_dst4
  check "restart: when systemctl returns (READY=1) the flushed element is back" 'systemctl restart agentbox-rootd.service && set_has keys_dst4 "192.88.96.1 . 443"'
  nft flush set inet agentbox keys_dst4
  check "notify (agentbox egress refill) restores it at once" '$A egress refill >/dev/null && set_has keys_dst4 "192.88.96.1 . 443"'
  addrs keys pub.gate.test 443 >/dev/null; nft flush set inet agentbox keys_dst4; sleep 12
  check "the 10 s timer restores it"              'set_has keys_dst4 "192.88.96.1 . 443"'
  check "ntfy_dst is filled by rootd itself (ntfy.sh:443)" 'nft list set inet agentbox ntfy_dst4 | grep -q " . 443 timeout" || nft list set inet agentbox ntfy_dst6 | grep -q " . 443 timeout"'

  echo "== a keys-like flow survives element expiry and is cut when its entry is removed"
  IPS=$(addrs keys "$FLOW_HOST" "$FLOW_PORT"); IP=$(v4 "$IPS"); t0=$(date +%s)
  install -o agentbox-keys -m 0644 /dev/null /run/rg/flow.log # the flow runs as agentbox-keys; /run/rg is root 0755
  as agentbox-keys $RG flow "$IP" "$FLOW_PORT" "$FLOW_HOST" /run/rg/flow.log 600 & FP=$!
  sleep 50 # 30 s timeout, plus a timer refill
  check "the element expired: $IP . $FLOW_PORT is gone from keys_dst4" '! set_has keys_dst4 "$IP . $FLOW_PORT"'
  check "a new keys connection to $IP:$FLOW_PORT is now refused" '! as agentbox-keys $RG connect $IP $FLOW_PORT 3'
  check "the established flow kept working after expiry" 'kill -0 $FP && ! grep -q cut /run/rg/flow.log && [ "$(awk -v t=$((t0 + 32)) "\$1 > t && \$2 == \"ok\"" /run/rg/flow.log | wc -l)" -ge 5 ]'
  tr=$(date +%s); rep=$(remove keys "$FLOW")
  note "egress remove: $rep"
  check "removing the entry deletes its conntrack entries" 'echo "$rep" | grep -q "\"Flows\":[1-9]"'
  check "and cuts the flow within 15 s"           'i=0; while kill -0 $FP 2>/dev/null; do i=$((i+1)); [ $i -lt 15 ] || exit 1; sleep 1; done; grep -q cut /run/rg/flow.log && [ "$(awk "\$2 == \"cut\" {print \$1}" /run/rg/flow.log)" -le $((tr + 15)) ]'
  kill $FP 2>/dev/null
  check "a removed entry no longer resolves"      '[ "$(reason keys "$FLOW_HOST" "$FLOW_PORT")" = not_allowlisted ]'
  cp /run/rg/flow.log /run/rg/flow-kept.log

  echo "== audit segments (§9): rootd creates and seals them for auditd (audit.Files on audit-seal.sock)"
  D=/var/lib/agentbox/audit
  check "audit dir agentbox-audit:agentbox-audit 0750 (tmpfiles.d)" '[ "$(stat -c %U:%G:%a $D)" = agentbox-audit:agentbox-audit:750 ]'
  # agentbox-auditd owns the real dir's chain; these calls run on a scratch dir that rootd seals for this test only
  D=/var/lib/agentbox/rg-audit
  rm -rf $D; install -d -o agentbox-audit -g agentbox-audit -m 0750 $D
  printf '[Service]\nExecStart=\nExecStart=%s rootd --element-timeout 30s --refill-interval 10s --audit-dir %s\n' "$A" "$D" > "$dropin"
  systemctl daemon-reload && systemctl restart agentbox-rootd.service
  S1=$D/seg-000001.jsonl
  call() { as agentbox-audit $RG req $R/audit-seal.sock "$1"; }
  seal() { call "{\"call\":\"audit.seal\",\"seg\":$1,\"last_hash\":\"$2\"}"; }
  check "audit.create refuses any segment but the first" 'call "{\"call\":\"audit.create\",\"seg\":2}" | grep -q "\"ok\":false" && [ ! -e $D/seg-000002.jsonl ]'
  check "audit.create seg 1: agentbox-audit 0640, append-only, not immutable" 'call "{\"call\":\"audit.create\",\"seg\":1}" | grep -q "\"ok\":true" && [ "$(stat -c %U:%G:%a $S1)" = agentbox-audit:agentbox-audit:640 ] && lsattr $S1 | cut -c1-22 | grep -q a && ! lsattr $S1 | cut -c1-22 | grep -q i'
  check "audit.create is idempotent"              'call "{\"call\":\"audit.create\",\"seg\":1}" | grep -q "\"ok\":true"'
  H1=$(as agentbox-audit $RG chain $S1 "" 3 close)
  check "auditd's uid appends records (O_APPEND)"  '[ -n "$H1" ] && [ "$(wc -l < $S1)" = 4 ]'
  check "nobody, root included, can rewrite it (+a)" '! as agentbox-audit sh -c ": > $S1" && ! sh -c ": > $S1" && ! rm -f $S1 && [ "$(wc -l < $S1)" = 4 ]'
  check "audit.seal with the wrong last_hash is refused and seals nothing" 'seal 1 00 | grep -q "\"ok\":false" && ! lsattr $S1 | cut -c1-22 | grep -q i && [ ! -e $D/seg-000002.jsonl ]'
  check "audit.seal checks the chain, sets +i, creates seg-000002 (+a)" 'seal 1 $H1 | grep -q "\"ok\":true" && lsattr $S1 | cut -c1-22 | grep -q i && [ "$(stat -c %U:%a $D/seg-000002.jsonl)" = agentbox-audit:640 ] && lsattr $D/seg-000002.jsonl | cut -c1-22 | grep -q a'
  check "a sealed segment takes no more records, and can't be removed" '! as agentbox-audit sh -c "echo x >> $S1" && ! rm -f $S1 && [ "$(wc -l < $S1)" = 4 ]'
  check "audit.seal is idempotent"                'seal 1 $H1 | grep -q "\"ok\":true"'
  H2=$(as agentbox-audit $RG chain $D/seg-000002.jsonl "$H1" 2 close)
  chattr +i $D/seg-000002.jsonl # a crash mid-seal: +i set, seg-000003 not yet created
  check "crash mid-seal: auditd's repeated audit.seal creates the missing next segment" 'seal 2 $H2 | grep -q "\"ok\":true" && [ -e $D/seg-000003.jsonl ] && lsattr $D/seg-000003.jsonl | cut -c1-22 | grep -q a'
  H3=$(as agentbox-audit $RG chain $D/seg-000003.jsonl "$H2" 2 torn)
  check "a torn tail (declared by a torn record) still seals" 'seal 3 $H3 | grep -q "\"ok\":true" && [ -e $D/seg-000004.jsonl ]'
  H4=$(as agentbox-audit $RG chain $D/seg-000004.jsonl "$H3" 2 broken)
  check "a broken chain (a record whose prev is not the line before it) is refused" 'seal 4 $H4 | grep -q "\"ok\":false" && ! lsattr $D/seg-000004.jsonl | cut -c1-22 | grep -q i && [ ! -e $D/seg-000005.jsonl ]'
  check "only the newest segment, or the one before it, can be sealed" 'seal 2 $H2 | grep -q "\"ok\":false"'

  # for after-reboot: an element with the production timeout that must come back from rootd.db after a reboot
  rm -f "$dropin"; systemctl daemon-reload; systemctl restart agentbox-rootd.service
  addrs keys pub.gate.test 443 >/dev/null
  check "production timings restored before the reboot" 'nft list set inet agentbox keys_dst4 | grep -q "192.88.96.1 . 443 timeout 10m"'
  ;;

after-reboot)
  check "rootd came up at boot after the firewall (READY)" 'systemctl is-active -q agentbox-rootd.service && [ "$(systemctl show -P ActiveEnterTimestampMonotonic agentbox-rootd.service)" -ge "$(systemctl show -P ActiveEnterTimestampMonotonic agentbox-firewall.service)" ]'
  check "the reboot emptied the kernel sets, and rootd refilled keys_dst4 from rootd.db with its remaining time" 'nft list set inet agentbox keys_dst4 | grep -q "192.88.96.1 . 443 timeout 10m expires [0-9]"'
  check "no element outside rootd.db after the refill" 'python3 - <<EOF
import json, sqlite3, subprocess
db = set(sqlite3.connect("file:/var/lib/agentbox/rootd.db?mode=ro", uri=True).execute("select set_name, element from set_elements"))
for s in ["proxy_dst4","proxy_dst6","keys_dst4","keys_dst6","git_dst4","git_dst6","ntfy_dst4","ntfy_dst6"]:
    for e in json.loads(subprocess.check_output(["nft","-j","list","set","inet","agentbox",s]))["nftables"]:
        for el in e.get("set", {}).get("elem", []):
            v = el["elem"]["val"]["concat"] if "elem" in el else el["concat"]
            assert (s, "%s . %d" % tuple(v)) in db, (s, v)
EOF'
  check "audit: the scratch dir's open segment is still seg-000004, sealed ones keep +i" '[ "$(ls /var/lib/agentbox/rg-audit | grep -c seg-)" = 4 ] && lsattr /var/lib/agentbox/rg-audit/seg-000003.jsonl | cut -c1-22 | grep -q i'
  check "auditd's own chain verifies after the reboot" '$A audit verify'
  check "no failed units"                         '[ -z "$(systemctl --failed --no-legend --plain)" ]'
  ;;

cleanup)
  systemctl stop rg-dns.service 2>/dev/null
  rm -f /run/systemd/resolved.conf.d/90-rootd-gate.conf; systemctl restart systemd-resolved.service
  ip addr del 192.88.99.15/32 dev "$IF" 2>/dev/null; ip -6 addr del 2600:ffff::15/128 dev "$IF" 2>/dev/null
  ip route del 192.88.98.0/24 dev "$IF" 2>/dev/null; ip link del rg0 2>/dev/null
  sed -i '/hosts.gate.test/d' /etc/hosts
  chattr -R -ia /var/lib/agentbox/rg-audit 2>/dev/null; rm -rf /var/lib/agentbox/rg-audit
  ;;
esac
echo "fails=$fails"

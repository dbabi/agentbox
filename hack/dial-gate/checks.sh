#!/bin/sh
# TEST FIXTURE: hack/dial-gate.sh copies this into the test VM as /run/dg/checks.sh and runs each phase as root.
#   checks.sh setup | main | cleanup
# Every check prints PASS or FAIL; each phase ends with fails=N.
# The test network lives in the VM: a veth LAN (dgl0 here, dgl1 in the netns dg-up) whose router is the box's default
# route for both families, ahead of the uplink's. dg-up also holds the test upstreams, TLS servers on public-looking
# addresses (/run/dg/probe serve). gate-dns answers the dial.test names for resolved, and is also a resolve hook.
# /run/dg/probe stands in for a broker: it dials through internal/dial on rootd's resolve-keys.sock, as agentbox-keys
# under the broker units' sandbox (no resolved Varlink or D-Bus, ARCHITECTURE.md §6.1).
# shellcheck disable=SC2034 # the check strings read the variables set for them, in eval
set -u
A=/var/lib/agentbox/current/bin/agentbox
D=/run/dg
P=$D/probe
S=/run/agentbox-rootd/resolve-keys.sock
HOOK=/run/systemd/resolve.hook/dial-gate
SLAAC=2600:ffff:200::ff:fe00:201 # EUI-64 of dgl0's MAC 02:00:00:00:02:01 under the LAN prefix 2600:ffff:200::/64
OFFL=2600:ffff:201::ff:fe00:201  # the same under 2600:ffff:201::/64, which the router announces off-link
NAMES="pub pub6 alt two dead drop wrong hook own4 ownif slaac dad lan6 lan4 nat64 sixto4 e hosts offlink nat64own nat64lan"
fails=0
# subshell: a check that calls exit must not end the phase
check() { if (eval "$2") >>$D/check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
note() { echo "NOTE $*"; }
# broker CMD...: CMD as agentbox-keys, with the broker units' InaccessiblePaths=
broker() { systemd-run -q --wait --pipe --collect -p User=agentbox-keys -p 'InaccessiblePaths=/run/systemd/resolve /run/dbus/system_bus_socket' "$@"; }
pdial() { broker $P dial $S "$1"; }
pres() { broker $P resolve $S "$1"; }
pget() { broker $P get $S "$1" $D/ca.pem; }
in_sets() { nft list table inet agentbox | grep -qF "$1"; }
# mark: later checks read only the journal from now on
mark() { t0=$(date +%s.%N); }
# logs UNIT: UNIT's journal since the mark, after a moment for journald to take in what was just written
logs() { sleep 1; journalctl -u "$1" --since "@$t0" -o cat; }
# den NAME DETAIL: rootd's DENY log line for NAME:443 since the mark starts its detail with DETAIL
den() { logs agentbox-rootd.service | grep -qF "entry=$1:443 code=non_public detail=\"$2"; }
up_log() { logs dg-up.service; }
# kd: packets the output chain dropped in the rules that name agentbox-keys (the broker-wide local, private4 and
# private6 drops, and keys' own catch-all). A lookup attempt lands here (§6.3), and so does a dial outside keys_dst.
kd() { u=$(id -u agentbox-keys); nft list chain inet agentbox output | grep -E "agentbox-keys|[ {]${u}[ ,}]" | grep -E 'counter packets [0-9]+ bytes [0-9]+ drop' |
  grep -o 'packets [0-9]*' | awk '{s += $2} END {print s + 0}'; }

case $1 in
setup)
  check "the release's firewall is up and fwcheck passes" 'systemctl is-active -q agentbox-firewall.service && $A fwcheck'
  check "rootd is up" 'systemctl is-active -q agentbox-rootd.service'
  ip -o route show default | awk '{print $5; exit}' > $D/uplink
  ip netns add dg-up
  ip link add dgl0 address 02:00:00:00:02:01 type veth peer name dgl1 netns dg-up
  # kernel SLAAC on dgl0 (no networkd .network names it): EUI-64, no temporary address
  sysctl -qw net.ipv6.conf.dgl0.accept_ra=2 net.ipv6.conf.dgl0.autoconf=1 net.ipv6.conf.dgl0.addr_gen_mode=0 net.ipv6.conf.dgl0.use_tempaddr=0
  ip addr add 100.127.200.1/30 dev dgl0
  ip link set dgl0 up
  ip netns exec dg-up sh -e <<'EOF'
sysctl -qw net.ipv6.conf.dgl1.addr_gen_mode=1
ip link set lo up
ip addr add 100.127.200.2/30 dev dgl1
ip -6 addr add fe80::64:1/64 dev dgl1 nodad
ip -6 addr add 2600:ffff:200::1/64 dev dgl1 nodad
for a in 192.88.96.1 192.88.96.2 192.88.96.3; do ip addr add $a/32 dev lo; done
ip -6 addr add 2600:ffff:96::1/128 dev lo
ip link set dgl1 up
ip route add default via 100.127.200.1
ip -6 route add default via fe80::ff:fe00:201 dev dgl1
EOF
  ip route add default via 100.127.200.2 dev dgl0 metric 1
  ip -6 route add default via fe80::64:1 dev dgl0 metric 1
  check "the LAN router is the default route for both families" 'ip route get 192.88.96.1 | grep -q "via 100.127.200.2 dev dgl0" && ip -6 route get 2600:ffff:96::1 | grep -q "via fe80::64:1 dev dgl0"'
  # SLAAC: the router announces 2600:ffff:200::/64 with router lifetime 0, so it adds no second default route
  check "the box takes its SLAAC address $SLAAC from the router's announcement" 'i=0; until ip -6 -o addr show dev dgl0 | grep " $SLAAC/64 " | grep -qv tentative; do ip netns exec dg-up $P ra dgl1 2600:ffff:200::/64; i=$((i+1)); [ $i -lt 20 ] || exit 1; sleep 1; done'
  check "  ... with an on-link route for the prefix, as a LAN gives" 'ip -6 route get 2600:ffff:200::99 | grep -q "dev dgl0" && ! ip -6 route get 2600:ffff:200::99 | grep -q via'
  # some routers announce their prefix off-link (A=1, L=0): the box takes a SLAAC address but gets no route for the
  # prefix, so the default route carries its neighbors and only rootd's own-prefix check sees them (#314)
  check "the box takes $OFFL from a second prefix the router announces off-link" 'i=0; until ip -6 -o addr show dev dgl0 | grep " $OFFL/64 " | grep -qv tentative; do ip netns exec dg-up $P ra dgl1 2600:ffff:201::/64 offlink; i=$((i+1)); [ $i -lt 20 ] || exit 1; sleep 1; done'
  check "  ... with no route for that prefix: a neighbor in it goes out the default route, through the router" 'ip -6 route get 2600:ffff:201::99 | grep -q "via fe80::64:1 dev dgl0"'
  # a public-looking on-link IPv4 LAN, for a NAT64 answer that wraps a neighbor in it
  ip addr add 192.88.97.1/24 dev dgl0
  # the box's own public-looking IPv4 addresses: one on the default route's interface, one on another
  ip addr add 192.88.95.15/32 dev dgl0
  ip link add dgo0 type dummy && ip link set dgo0 up && ip addr add 192.88.95.16/32 dev dgo0
  grep -q dial.test /etc/hosts || printf '192.168.1.10 hosts.dial.test\n192.88.96.2 pub.dial.test\n' >> /etc/hosts
  mkdir -p /run/systemd/resolve.hook
  # gate-dns answers *.dial.test and relays everything else to slirp's DNS; resolved uses only it for this boot. Its hook
  # answers hook.dial.test with 192.88.96.1, where an upstream listens; DNS has 192.88.96.2 for that name.
  systemd-run -q --unit=dg-dns $D/gate-dns -listen 127.0.0.153:53 -upstream 10.0.2.3:53 -zone dial.test \
    -a pub.dial.test=192.88.96.1,2600:ffff:96::1 -a pub6.dial.test=2600:ffff:96::1 -a alt.dial.test=192.88.96.2 \
    -a two.dial.test=192.88.96.3,192.88.96.1 -a dead.dial.test=192.88.96.3 -a drop.dial.test=192.88.96.4 \
    -a wrong.dial.test=192.88.96.1 -a hook.dial.test=192.88.96.2 -a own4.dial.test=192.88.95.15 \
    -a ownif.dial.test=192.88.95.16 -a slaac.dial.test=$SLAAC -a dad.dial.test=2600:ffff:95::77 \
    -a lan6.dial.test=2600:ffff:200::99 -a lan4.dial.test=192.168.1.10 -a nat64.dial.test=64:ff9b::c0a8:10a \
    -a sixto4.dial.test=2002:c0a8:10a::1 -a e.dial.test=240.0.0.1 -a ipv4only.arpa=192.0.0.170,192.0.0.171 \
    -a offlink.dial.test=2600:ffff:201::99 -a nat64own.dial.test=64:ff9b::c058:5f0f -a nat64lan.dial.test=64:ff9b::c058:6102 \
    -hook $HOOK -hook-a hook.dial.test=192.88.96.1
  mkdir -p /run/systemd/resolved.conf.d
  printf '[Resolve]\nDNS=127.0.0.153\nDomains=~.\n' > /run/systemd/resolved.conf.d/90-dial-gate.conf
  systemctl restart systemd-resolved.service
  # the upstreams, with one certificate for the names that answer 192.88.96.1 or .2 (wrong.dial.test is not among them)
  systemd-run -q --unit=dg-up ip netns exec dg-up $P serve $D pub.dial.test,pub6.dial.test,alt.dial.test,two.dial.test,hook.dial.test \
    192.88.96.1:443 '[2600:ffff:96::1]:443' 192.88.96.2:443
  sleep 2
  check "gate-dns answers through resolved" 'resolvectl query -4 alt.dial.test | grep -q 192.88.96.2'
  check "the upstreams answer root over IPv4 and IPv6 (curl, unconfined)" 'curl -fsSk https://192.88.96.1/ | grep -qx "pinned 192.88.96.1:443" && curl -fsSk "https://[2600:ffff:96::1]/" | grep -qxF "pinned [2600:ffff:96::1]:443"'
  for n in $NAMES; do $A egress allow --svc keys --entry $n.dial.test:443 >/dev/null; done
  check "the 21 dial.test names are on keys' allowlist" '[ "$(grep -c "^keys .*\.dial\.test:443$" /var/lib/agentbox/control/egress/service.list)" = 21 ]'
  nft list chain inet agentbox output > $D/output-chain.txt
  ;;

main)
  echo "== refused answers (Appendix B): the box's own addresses and networks, LAN, private, NAT64- and 6to4-wrapped, 240/4, /etc/hosts"
  mark
  check "a public answer resolves for keys" '[ "$(pres alt.dial.test:443)" = "addrs 192.88.96.2" ] && nft list set inet agentbox keys_dst4 | grep -qF "192.88.96.2 . 443"'
  # an address in DAD has no local route yet, and with no prefix route (as SLAAC gives under a prefix the router marks
  # off-link) the default route carries it: only rootd's own-address check sees it
  sysctl -qw net.ipv6.conf.dgl0.dad_transmits=300
  ip -6 addr add 2600:ffff:95::77/128 dev dgl0 noprefixroute
  check "2600:ffff:95::77 is the box's, still in DAD (tentative), with no prefix route" 'ip -6 -o addr show dev dgl0 | grep " 2600:ffff:95::77/128 " | grep -q tentative'
  check "  ... and the kernel routes it out the default route, through the router" 'ip -6 route get 2600:ffff:95::77 | grep -q "via fe80::64:1 dev dgl0"'
  before=$(nft list table inet agentbox | grep -c ' \. 443')
  for n in own4 ownif slaac dad lan6 offlink lan4 nat64 sixto4 nat64own nat64lan e; do
    check "$n.dial.test is refused non_public before any dial" "[ \"\$(pdial $n.dial.test:443)\" = 'refused non_public' ]"
  done
  check "hosts.dial.test, which only /etc/hosts names, is refused no_such_name" '[ "$(pdial hosts.dial.test:443)" = "refused no_such_name" ]'
  check "none of their addresses reached any set" '[ "$(nft list table inet agentbox | grep -c " \. 443")" = "$before" ] && for a in 192.88.95.15 192.88.95.16 $SLAAC 2600:ffff:95::77 2600:ffff:200::99 2600:ffff:201::99 192.168.1.10 64:ff9b::c0a8:10a 2002:c0a8:10a::1 64:ff9b::c058:5f0f 64:ff9b::c058:6102 240.0.0.1; do ! in_sets "$a . 443" || exit 1; done'
  check "the box's own IPv4 on the default route's interface: the route check (local)" 'den own4.dial.test "192.88.95.15: route_not_unicast"'
  check "the box's own IPv4 on another interface: the route check (local)" 'den ownif.dial.test "192.88.95.16: route_not_unicast"'
  check "the box's own SLAAC IPv6: the route check (local)" 'den slaac.dial.test "$SLAAC: route_not_unicast"'
  check "the box's own IPv6 in DAD: the own-address check" 'den dad.dial.test "2600:ffff:95::77: own_address"'
  check "a LAN host's global IPv6: the route check (on-link, no gateway)" 'den lan6.dial.test "2600:ffff:200::99: route_on_link"'
  check "a LAN host's global IPv6 under the off-link prefix, which the route check passes: the own-prefix check" 'den offlink.dial.test "2600:ffff:201::99: own_prefix"'
  check "192.168.1.10: private4" 'den lan4.dial.test "192.168.1.10: private4"'
  check "NAT64-wrapped 192.168.1.10: nat64_private" 'den nat64.dial.test "64:ff9b::c0a8:10a: nat64_private"'
  check "6to4-wrapped 192.168.1.10: 6to4_private" 'den sixto4.dial.test "2002:c0a8:10a::1: 6to4_private"'
  check "NAT64-wrapped 192.88.95.15, the box's own IPv4: the route check on the IPv4 it carries (local)" 'den nat64own.dial.test "64:ff9b::c058:5f0f: wraps 192.88.95.15 route_not_unicast"'
  check "NAT64-wrapped 192.88.97.2, an on-link IPv4 neighbor: the route check on the IPv4 it carries" 'den nat64lan.dial.test "64:ff9b::c058:6102: wraps 192.88.97.2 route_on_link"'
  check "240.0.0.1: private4" 'den e.dial.test "240.0.0.1: private4"'
  check "resolved never read /etc/hosts for rootd: gate-dns was asked for hosts.dial.test" 'logs dg-dns.service | grep -q "query hosts.dial.test$"'
  ip -6 addr del 2600:ffff:95::77/128 dev dgl0
  check "with that address gone, dad.dial.test resolves: rootd reads the box's addresses at each resolution" '[ "$(pres dad.dial.test:443)" = "addrs 2600:ffff:95::77" ]'

  echo "== a resolve hook's answer (systemd 259, #145)"
  mark
  check "hook.dial.test, which the hook answers with 192.88.96.1, is refused non_public before any dial" '[ "$(pdial hook.dial.test:443)" = "refused non_public" ]'
  check "  ... rootd's detail names the hook" 'den hook.dial.test "from_hook (answers [192.88.96.1])"'
  check "  ... resolved asked the hook, and never asked DNS" 'q=$(logs dg-dns.service); echo "$q" | grep -q " hook hook.dial.test$" && ! echo "$q" | grep -q "query hook.dial.test$"'
  check "  ... and no upstream saw a connection" '! up_log | grep -q "^accept"'
  rm -f $HOOK
  check "with the hook gone, the same name resolves over DNS, and a GET reaches DNS's 192.88.96.2" '[ "$(pget https://hook.dial.test/)" = "status 200 pinned 192.88.96.2:443" ]'

  echo "== pinned dialing: rootd's addresses, in order, and nothing else"
  mark
  check "/etc/hosts gives the system resolver 192.88.96.2 for pub.dial.test, which keys_dst4 lets keys reach" '[ "$(getent hosts pub.dial.test | awk "{print \$1}")" = 192.88.96.2 ] && nft list set inet agentbox keys_dst4 | grep -qF "192.88.96.2 . 443"'
  note "rootd's answer for pub.dial.test: $(pres pub.dial.test:443)"
  k0=$(kd)
  out=$(pget https://pub.dial.test/); at=${out#status 200 pinned }
  check "a GET of https://pub.dial.test/ through the dialer reaches one of rootd's addresses ($at)" 'case $out in "status 200 pinned 192.88.96.1:443"|"status 200 pinned [2600:ffff:96::1]:443") ;; *) exit 1 ;; esac'
  check "  ... with SNI and Host pub.dial.test" 'up_log | grep -qxF "get $at sni=pub.dial.test host=pub.dial.test"'
  check "  ... and nothing reached 192.88.96.2, the /etc/hosts answer" '! up_log | grep -q "192.88.96.2:443"'
  check "  ... and no drop counter that names keys moved: no lookup, no dial outside keys_dst" '[ "$(kd)" = "$k0" ]'
  check "a lookup attempt would show there: the system resolver gives the sandboxed keys user nothing, and the counter moves" '! broker getent ahosts nope.dial.test && [ "$(kd)" -gt "$k0" ]'
  check "an IPv6-only name: the GET goes over IPv6, through keys_dst6" '[ "$(pget https://pub6.dial.test/)" = "status 200 pinned [2600:ffff:96::1]:443" ] && nft list set inet agentbox keys_dst6 | grep -qF "2600:ffff:96::1 . 443"'
  check "two.dial.test: rootd answers 192.88.96.3 (it resets) before 192.88.96.1, and the dialer goes on to 192.88.96.1" '[ "$(pres two.dial.test:443)" = "addrs 192.88.96.3 192.88.96.1" ] && [ "$(pdial two.dial.test:443)" = "connected 192.88.96.1:443" ]'
  check "dead.dial.test (192.88.96.3 resets): failed refused, in under 2 s" 'set -- $(pdial dead.dial.test:443); [ "$1 $2" = "failed refused" ] && [ "$3" -lt 2000 ]'
  check "drop.dial.test (192.88.96.4 drops the SYN): failed timeout, after the 10 s budget and within 11 s" 'set -- $(pdial drop.dial.test:443); [ "$1 $2" = "failed timeout" ] && [ "$3" -ge 9500 ] && [ "$3" -le 11000 ]'
  check "wrong.dial.test answers 192.88.96.1, whose certificate does not name it: the TLS check fails" 'pget https://wrong.dial.test/ | grep -q "certificate is valid for .*, not wrong.dial.test"'
  check "a redirect is not followed: rootd is never asked for its target" '[ "$(pget https://pub.dial.test/moved)" = redirect ] && ! logs agentbox-rootd.service | grep -q "entry=moved.dial.test"'
  check "the port is part of the entry: pub.dial.test:8443 is refused not_allowlisted" '[ "$(pdial pub.dial.test:8443)" = "refused not_allowlisted" ]'
  ;;

cleanup)
  for n in $NAMES; do $A egress remove --svc keys --entry $n.dial.test:443 >/dev/null 2>&1; done
  systemctl stop dg-dns.service dg-up.service 2>/dev/null; systemctl reset-failed dg-dns.service dg-up.service 2>/dev/null
  rm -f $HOOK /run/systemd/resolved.conf.d/90-dial-gate.conf; systemctl restart systemd-resolved.service
  ip route del default via 100.127.200.2 dev dgl0 metric 1 2>/dev/null; ip -6 route del default via fe80::64:1 dev dgl0 metric 1 2>/dev/null
  ip link del dgl0 2>/dev/null; ip link del dgo0 2>/dev/null; ip netns del dg-up 2>/dev/null
  sed -i '/dial.test/d' /etc/hosts
  check "the uplink is the default route again" '[ "$(ip -o route show default | awk "{print \$5; exit}")" = "$(cat $D/uplink)" ]'
  check "no failed units"                         '[ -z "$(systemctl --failed --no-legend --plain)" ]'
  ;;
esac
echo "fails=$fails"

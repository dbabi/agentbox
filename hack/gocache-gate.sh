#!/bin/sh
# Weeks 7-8 gate for the v5.3 additions (PLAN.md row 7-8; PROPOSALS-v5.3 A-G3 to A-G13, A-G14's short run is go test;
# C-G4's budget.set; ARCHITECTURE.md §2, §4.1, §6.2, §6.3) on the local arm64 QEMU VM, none mode.
#   hack/gocache-gate.sh [install|checks ...]   default: both, in order
# install  hack/gate.sh none: the unattended install and the release pipeline, so rootd, agentboxd, taskrun and the
#          units arrive the real way.
# checks   a fake proxy.golang.org on the host (hack/gocache-gate/upstream: synthetic modules and a checksum database
#          signed with a test key, TLS from a test CA) on 127.0.0.1:7800+ID, which vm.sh forwards to the guest as
#          10.0.2.2 for this boot only (AGENTBOX_VM_FWD). On the box: image/task with the test CA, agents ga to ge
#          (gc without proxy.golang.org:443), and a proxy stand-in (hack/gocache-gate/standin, the real
#          internal/proxy/gocache behind each task's proxy.sock) as agentbox-proxy.service, since the proxy itself is
#          not built yet (#17). Every task is `agentbox task new` run as a sh script (AGENTBOX_TEST_CLI=sh) by taskrun,
#          which starts the Go module filter because rootd set the cache GOPROXY.
#          A-G3: the go command facts behind the filter, in the image's Go source. A-G4: a 64-module fixture twice: the
#          second task opens one CONNECT (the live-check tunnel, under 2 MiB down), and its go mod download takes under
#          6 s and at most a third of the first; one fill record per file; no proxy nft drops. A-G5: no cache mount in a
#          task; the filter's and the proxy's grammar refusals, with no proxy request, taint, upstream request or store
#          change; +incompatible and pseudo-versions served. A-G6: a clean task's first cache use gets one TAINT per
#          producer (agentboxd, proxy) before its first fill, also for 20 parallel first requests; a proxy that writes
#          none still leaves the task tainted first; auditd down gives 503 with no body; agentboxd down leaves go to
#          CONNECT; a vendored build makes no cache request and ends clean. A-G7: GOPROXY=off and a 404 with no taint for
#          an agent without the entry; the same go test output and taint without the filter entry. A-G8: an altered
#          upstream zip is refused (sum_mismatch); a blob altered with its row makes go stop with or without a go.sum
#          line; a flipped byte is refilled; a hostile proxy's forged lists, @latest and .info never reach go; a
#          withdrawn version gets 404. A-G9: another agent's miss is its own upstream fetch and touches nothing of the
#          first agent's store. A-G10: the task file cap, the day cap and the disk reserve stop fills while go still
#          works; eviction keeps the store under its limit and the newest entries; a write past the kernel limit as
#          agentbox-proxy gets EDQUOT. A-G11: no request naming a GOPRIVATE path reaches the cache path, the checksum
#          client or the upstream. A-G12: agent.remove deletes the store; cache.purge empties one agent's only; a proxy
#          killed mid-fill leaves no temp file, orphan blob or row without blob; a revoked task's fill inserts no row.
#          A-G13: agentboxd and auditd run one more seccomp filter than their units give; BTRFS_IOC_SUBVOL_CREATE gets
#          EOPNOTSUPP under it as agentbox-proxy, agentbox-git and agentbox (also with 0xdead00000000 in cmd); a nested
#          subvolume in a cache store raises the sweep's alert. C-G4: budget.set refuses day shares above the box cap
#          and writes the day shares rootd recomputes at agent.add.
# Stand-ins until their areas land: the proxy (#17) and its pinned dialer (#20): the stand-in dials the fake upstream
# straight, through a rootd.db allow_private4 tuple for agentbox-proxy, not through rootd's resolver.
# PASS/FAIL lines go to .vm/gocache-gate.txt, command output to .vm/gocache-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/gocache-gate.txt" LOG="$VM/gocache-gate.log"
UP_PORT=$((7800 + ${AGENTBOX_VM_ID:-0}))
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
vm_off() { echo 'systemctl poweroff' | root >/dev/null 2>&1 || :; i=0
  while running; do i=$((i+1)); [ $i -lt 60 ] || kill "$(cat "$VM/qemu.pid")"; sleep 2; done; }
# up: a fresh boot with the upstream's port forwarded, whatever ran before
up() { ! running || vm_off; { AGENTBOX_VM_FWD=$UP_PORT hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"
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
  K="$VM/gocache"
  mkdir -p "$K"
  TOKEN=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  go build -o "$K/upstream" ./hack/gocache-gate/upstream || die "build the fake upstream"
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$K/standin" ./hack/gocache-gate/standin || die "build the proxy stand-in"
  "$K/upstream" -listen "127.0.0.1:$UP_PORT" -token "$TOKEN" -out "$K" >>"$LOG" 2>&1 &
  UPID=$!
  trap 'kill $UPID 2>/dev/null' EXIT
  i=0; until [ -s "$K/vkey" ]; do i=$((i+1)); [ $i -lt 50 ] || die "the fake upstream did not start"; sleep 0.2; done
  up
  printf 'TOKEN=%s\nUP_PORT=%s\n' "$TOKEN" "$UP_PORT" > "$K/env"
  tar -C "$K" -cf - env ca.pem vkey gosum fixture standin | hack/vm.sh ssh 'rm -rf /tmp/gate-cache && mkdir /tmp/gate-cache && tar -C /tmp/gate-cache -xf -'
  tar -C image -cf - task | hack/vm.sh ssh 'rm -rf /tmp/gate-image && mkdir /tmp/gate-image && tar -C /tmp/gate-image -xf -'
  guest <<'EOF'
fails=0
cd / # runuser keeps the working dir, and the agent can't enter the admin's home
check() { if (eval "$2") >>/tmp/gate-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
K=/tmp/gate-cache
. $K/env
# a rerun on the same box gets new agents: fresh workspaces, stores and audit trails for every check
R=$(( $(cat /var/tmp/gate-cache-run 2>/dev/null || echo 0) + 1 )); echo $R > /var/tmp/gate-cache-run
A1=ga$R A2=gb$R A3=gc$R A4=gd$R A5=ge$R A6=gf$R A7=gg$R
chmod 0700 $K && chmod 0644 $K/ca.pem $K/vkey && chmod 0755 $K/standin $K/fixture
B=/var/lib/agentbox/current/bin/agentbox
E=/var/lib/agentbox/control/egress
WS=/var/lib/agentbox/data/workspaces
C=/var/lib/agentbox/data/cache
DB=/var/lib/agentbox/rootd.db
IMG=localhost/agentbox-task:gate
RS=/run/systemd/system
G=/var/tmp/gate
P=$G/proxy.log
mkdir -p $G && chmod 0755 $G
cp $K/standin $K/ca.pem $K/vkey $G/ && chmod 0755 $G/standin
UP=https://proxy.golang.org:$UP_PORT
up() { curl -sS --cacert $K/ca.pem --resolve proxy.golang.org:$UP_PORT:10.0.2.2 "$@"; } # the fake upstream, as root
ctl() { up -X POST "$UP/_ctl/$TOKEN/$1" >/dev/null; }
uplog() { up "$UP/_ctl/$TOKEN/log"; }
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
# store AGENT: "<rows> <blobs> <tmp files>" of the agent's cache store
store() { echo "$(python3 -c "import sqlite3,sys; print(sqlite3.connect('file:$C/$1/index.db?mode=ro', uri=True).execute('select count(*) from entries').fetchone()[0])" 2>/dev/null || echo 0) $(ls $C/$1/blobs 2>/dev/null | wc -l) $(ls -A $C/$1/tmp 2>/dev/null | wc -l)"; }
# consistent AGENT: every row has its blob and every blob a row
consistent() { python3 - "$C/$1" <<'PY'
import os, sqlite3, sys
d = sys.argv[1]
rows = {r[0] for r in sqlite3.connect("file:%s/index.db?mode=ro" % d, uri=True).execute("select sha256 from entries")}
blobs = set(os.listdir(d + "/blobs"))
print(len(rows), len(blobs), os.listdir(d + "/tmp"))
sys.exit(not (rows == blobs and not os.listdir(d + "/tmp")))
PY
}
reqs() { grep -c " REQ $1 " $P || :; } # requests a task sent on its proxy.sock
ended() { $B task list | python3 -c 'import json,sys; sys.exit(not [t for t in json.load(sys.stdin)["tasks"] if t["task"]==sys.argv[1] and t.get("end_reason")])' "$1"; }
# task AGENT SCRIPT: one task through task.start; prints what the script printed and returns its exit code; the id goes
# to $G/last
task() { o=$WS/$1/.gate-out; rm -f $o $WS/$1/.gate-rc
  printf '(\n%s\n) </dev/null > /workspace/.gate-out 2>&1; echo $? > /workspace/.gate-rc\n' "$2" |
    $B task new --agent $1 --cli sh --deadline 15m > $G/new; r=$?
  sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' $G/new > $G/last
  [ $r = 0 ] && [ -s $G/last ] || { cat $G/new; return 99; }
  i=0; while [ ! -e $WS/$1/.gate-rc ]; do i=$((i+1)); [ $i -lt 6000 ] || { echo "task $(cat $G/last): no result"; return 98; }; sleep 0.1; done
  i=0; until ended "$(cat $G/last)"; do i=$((i+1)); [ $i -lt 300 ] || break; sleep 0.1; done
  cat $o; return "$(cat $WS/$1/.gate-rc)"; }
# stand OPTS: (re)start the proxy stand-in as agentbox-proxy.service, svc-proxy.sock from systemd
stand() { systemctl stop agentbox-proxy.service agentbox-proxy.socket 2>/dev/null; systemctl reset-failed agentbox-proxy.service agentbox-proxy.socket 2>/dev/null
  systemd-run -q --unit=agentbox-proxy --socket-property=ListenStream=/run/agentbox-rootd/svc-proxy.sock --socket-property=SocketMode=0600 \
    -p User=agentbox-proxy -p Group=agentbox-proxy -p NoNewPrivileges=yes \
    $G/standin serve -upstream 10.0.2.2:$UP_PORT -vkey $G/vkey -ca $G/ca.pem -log $P "$@" &&
  systemctl start agentbox-proxy.service && for i in $(seq 50); do systemctl is-active -q agentbox-proxy.service && return 0; sleep 0.1; done; }
# pdrops: packets the ruleset dropped for agentbox-proxy, every drop rule that names it summed
pdrops() { nft list chain inet agentbox output | grep '"agentbox-proxy"' | sed -n 's/.* counter packets \([0-9]*\) .* drop$/\1/p' | awk '{n += $1} END {print n + 0}'; }

# --- setup: the image with the test CA, five agents, the proxy stand-in ---
check "image/task builds on the box, with the gate's CA in its trust store" 'podman build -q -t $IMG /tmp/gate-image/task </dev/null >/dev/null &&
  cp $K/ca.pem $G/gate-ca.crt && printf "FROM %s\nCOPY gate-ca.crt /usr/local/share/ca-certificates/gate-ca.crt\nRUN update-ca-certificates >/dev/null\n" $IMG > $G/Containerfile &&
  podman build -q -t $IMG-ca -f $G/Containerfile $G </dev/null >/dev/null && podman save -o $G/image.tar $IMG-ca && chmod 0644 $G/image.tar'
for a in $A1 $A2 $A3 $A4 $A5; do
  check "agent add $a, and the task image in its podman" '{ $B agent add --name $a || $B agent list | grep -q "\"name\":\"$a\""; } && u=$(id -u ag-$a) &&
    i=0; until systemctl is-active -q user@$u.service; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done &&
    systemd-run --user -M ag-$a@ --wait --quiet --collect /usr/bin/podman load -q -i $G/image.tar </dev/null'
  find $WS/$a -mindepth 1 -delete 2>/dev/null || :
done
mkdir -p $E && for a in $A1 $A2 $A4 $A5; do printf '# gate: the human-added deputy host\nproxy.golang.org:443\n' > $E/$a.list; done
mkdir -p $RS/agentboxd.service.d $RS/agentbox-rootd.service.d
printf '[Service]\nEnvironment=AGENTBOX_TEST_CLI=sh\n' > $RS/agentboxd.service.d/50-gocache.conf
printf '[Service]\nEnvironment=AGENTBOX_TEST_TASK_IMAGE=%s-ca\nExecStart=\nExecStart=%s rootd --sweep-interval 10s\n' $IMG $B > $RS/agentbox-rootd.service.d/50-gocache.conf
systemctl daemon-reload
check "agentboxd with AGENTBOX_TEST_CLI=sh, rootd with the gate's image and a 10 s cache sweep" 'systemctl restart agentbox-rootd.service agentboxd.service &&
  systemctl is-active -q agentbox-rootd agentboxd && systemctl show -P ExecStart agentbox-rootd.service | grep -q "sweep-interval 10s"'
# the stand-in dials the fake upstream at 10.0.2.2 straight: an approved private tuple for agentbox-proxy (§6.1)
PU=$(id -u agentbox-proxy)
python3 -c "import sqlite3; c=sqlite3.connect('$DB'); c.execute(\"insert or ignore into set_elements values ('allow_private4', '$PU . 10.0.2.2 . $UP_PORT', NULL)\"); c.commit()"
: > $P && chown agentbox-proxy:agentbox-proxy $P
check "the proxy stand-in runs as agentbox-proxy behind svc-proxy.sock, and reaches the fake upstream through its allow_private4 tuple" '
  $B egress refill >/dev/null && nft list set inet agentbox allow_private4 | grep -q "10.0.2.2 . $UP_PORT" && stand &&
  [ "$(stat -c %U /proc/$(systemctl show -P MainPID agentbox-proxy.service))" = agentbox-proxy ] && up -o /dev/null -w "%{http_code}" $UP/example.com/m/@v/list | grep -qx 200'
uplog > /dev/null
cp -r $K/fixture $WS/$A1/fx && cp $K/vkey $WS/$A1/.vkey && chown -R ag-$A1:ag-$A1 $WS/$A1

# --- A-G13: the service btrfs filter, and data/cache/<agent> ---
for u in agentboxd agentbox-auditd; do
  check "A-G13 $u runs one more seccomp filter than its unit gives (logged at start, in /proc)" '
    pid=$(systemctl show -P MainPID $u.service) && l=$(journalctl -b -u $u.service -o cat | grep "service filter installed: Seccomp_filters" | tail -1) && echo "$l" &&
    b=$(echo "$l" | sed -n "s/.*Seccomp_filters \([0-9]*\) -> \([0-9]*\).*/\1/p") && a=$(echo "$l" | sed -n "s/.*-> \([0-9]*\).*/\1/p") &&
    [ "$a" = $((b + 1)) ] && grep -qx "Seccomp_filters:	$a" /proc/$pid/status'
done
check "A-G13 data/cache is root 0711; data/cache/$A1 is a subvolume in $A1's 1/N with its own limit, agentbox-proxy 0700" '
  [ "$(stat -c "%U %a" $C)" = "root 711" ] && [ "$(stat -c "%U %a %i" $C/$A1)" = "agentbox-proxy 700 256" ] &&
  id=$(btrfs inspect-internal rootid $C/$A1) && n=$(( $(id -u ag-$A1) - 70000 )) && btrfs --format=json qgroup show -p -e /var/lib/agentbox > $G/qg &&
  python3 -c "import json,sys; q={r[\"qgroupid\"]: r for r in json.load(open(\"$G/qg\"))[\"qgroup-show\"]}[\"0/$id\"]; print(q); sys.exit(not (\"1/$n\" in q[\"parents\"] and str(q[\"max_exclusive\"]) == str(8 << 30)))"'
for c in "agentbox-proxy $C/$A1" "agentbox-git /var/lib/agentbox/git" "agentbox /var/lib/agentbox/state"; do
  set -- $c
  check "A-G13 under the service filter, BTRFS_IOC_SUBVOL_CREATE as $1 on $2 gets EOPNOTSUPP, also with 0xdead00000000 in cmd" '
    setpriv --reuid $1 --regid $1 --clear-groups $G/standin btrfs-probe $2 > $G/probe && cat $G/probe && [ "$(grep -c ": EOPNOTSUPP$" $G/probe)" = 2 ]'
done
check "  ... and the kernel, with no filter, answers that uid on state/ otherwise (the EOPNOTSUPP is the filter's)" '
  setpriv --reuid agentbox --regid agentbox --clear-groups $G/standin btrfs-probe -no-filter /var/lib/agentbox/state > $G/probe0; cat $G/probe0
  [ "$(grep -c ": E" $G/probe0)" = 2 ] && ! grep -q EOPNOTSUPP $G/probe0 && [ -z "$(btrfs subvolume list -o /var/lib/agentbox/state)" ]' 
check "A-G13 a nested subvolume made as root in data/cache/$A1 raises the sweep's alert" 'btrfs subvolume create -q $C/$A1/nest &&
  for i in $(seq 40); do arec ALERT source=cache_sweep agent=$A1 | grep -q nested_subvolume && break; sleep 1; done; btrfs subvolume delete -q $C/$A1/nest;
  arec ALERT source=cache_sweep agent=$A1 | grep -q nested_subvolume'

# --- A-G3: the go command's behavior the filter rests on, in the image's Go source ---
check "A-G3 in the image's Go source: GOPROXY falls back only on 404/410, the sumdb probe, checkModSum, loopback proxies skipped, -mod ignores vendor, the pinned key, GONOSUMDB from GOPRIVATE" '
  task $A1 "G=\$(go env GOROOT)/src/cmd/go/internal; V=\$(go env GOROOT)/src/vendor/golang.org/x
    grep -q \"isNotExistErr := errors.Is(err, fs.ErrNotExist)\" \$G/modfetch/proxy.go && echo fallback
    grep -q \"sumdb/\\\"+c.name+\\\"/supported\" \$G/modfetch/sumdb.go && echo supported
    grep -q \"^func checkModSum(\" \$G/modfetch/fetch.go && grep -q \"useSumDB(mod)\" \$G/modfetch/fetch.go && echo checkModSum
    grep -q \"Proxy: *http.ProxyFromEnvironment\" \$G/web/http.go && grep -q \"IsLoopback()\" \$V/net/http/httpproxy/proxy.go && echo loopback
    grep -q \"if cfg.BuildModExplicit {\" \$G/modload/init.go && echo explicit-mod
    grep -q \"sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8\" \$G/modfetch/key.go && echo key
    grep -q \"GONOSUMDB, GONOSUMDBChanged = EnvOrAndChanged(\\\"GONOSUMDB\\\", GOPRIVATE)\" \$G/cfg/cfg.go && echo gonosumdb
    go version" > $G/facts; cat $G/facts; [ "$(grep -cx "fallback\|supported\|checkModSum\|loopback\|explicit-mod\|key\|gonosumdb" $G/facts)" = 7 ]'

# --- A-G4: warm start ---
ctl "slow?ms=300&rate=2000000" # about a 20 Mbit/s path with 300 ms per file, as a far upstream
d0=$(pdrops)
task $A1 "cd fx && t0=\$(date +%s%N); go mod download; r=\$?; echo dl_ms=\$(( (\$(date +%s%N)-t0)/1000000 )); go test ./...; echo rc=\$r" > $G/w1 2>&1; T1=$(cat $G/last)
task $A1 "cd fx && t0=\$(date +%s%N); go mod download; r=\$?; echo dl_ms=\$(( (\$(date +%s%N)-t0)/1000000 )); go test ./...; echo rc=\$r" > $G/w2 2>&1; T2=$(cat $G/last)
cat $G/w1 $G/w2
d1=$(sed -n 's/^dl_ms=//p' $G/w1) d2=$(sed -n 's/^dl_ms=//p' $G/w2)
echo "warm start: first go mod download $d1 ms, second $d2 ms"
check "A-G4 a 64-module fixture: both tasks pass go test" 'grep -q "^ok  *example.com/fx" $G/w1 && grep -q "^ok  *example.com/fx" $G/w2'
check "A-G4 the first task's fills: one ACKed fill record per file (64 .mod, 64 .zip)" '
  [ "$(arec CACHE event=fill task=$T1 | grep -c "\"key\": \"go:example.com/w/m[0-9]*@v1.0.0.mod\"")" = 64 ] &&
  [ "$(arec CACHE event=fill task=$T1 | grep -c "\"key\": \"go:example.com/w/m[0-9]*@v1.0.0.zip\"")" = 64 ]'
check "A-G4 the second task opens exactly one CONNECT to proxy.golang.org (the live-check tunnel), under 2 MiB down, and fills nothing" '
  [ "$(grep -c " REQ $T2 $A1 CONNECT proxy.golang.org:443" $P)" = 1 ] && down=$(sed -n "s/.* TUNNEL $T2 proxy.golang.org:443 down=//p" $P) &&
  echo "down $down" && [ "$down" -lt 2097152 ] && [ -z "$(arec CACHE event=fill task=$T2)" ]'
check "A-G4 the second go mod download takes under 6 s and at most a third of the first" '[ "$d2" -lt 6000 ] && [ $((d2 * 3)) -le "$d1" ]'
check "A-G4 the proxy's nft drop counters stay at 0" '[ "$d0" = 0 ] && [ "$(pdrops)" = 0 ]'
ctl "slow?ms=0&rate=0"

# --- A-G5: no write path, two grammars ---
$B goprivate set --agent $A1 --patterns 'corp.example/*' >/dev/null
check "A-G5 a task has no mount under /var/lib/agentbox/data/cache" 'task $A1 "cat /proc/self/mountinfo" > $G/mi && grep -q " /workspace " $G/mi && ! grep -q "data/cache" $G/mi'
uplog > /dev/null; s0=$(store $A1)
task $A1 'for p in example.com/m/@v/list example.com/m/@latest sumdb/sum.golang.org/supported example.com/m/@v/master.info \
  example.com/m/@v/v1.2.info example.com/m/@v/0123456789ab.info "example.com/m/@v/v1.0.0.info?x=1" Example.com/m/@v/v1.0.0.info \
  corp.example/x/@v/v1.0.0.info; do curl -s -o /dev/null -w "%{http_code} $p\n" "http://127.0.0.1:8083/$p"; done' > $G/g1; T=$(cat $G/last); cat $G/g1
check "A-G5 the filter answers @v/list, @latest, the sumdb, a branch, a partial version, a commit hash, a query, a bad escape and a GOPRIVATE path with its own 404, and sends nothing on the proxy socket" '
  [ "$(grep -c "^404 " $G/g1)" = 9 ] && [ "$(reqs $T)" = 0 ]'
S=/run/agentbox/egress/proxy.sock
task $A1 "cu() { curl -s -o /dev/null -w \"%{http_code} \$*\n\" --unix-socket $S \"\$@\"; }
  cu -X POST http://proxy/_cache/go/example.com/m/@v/v1.0.0.mod
  cu --request-target http://proxy/_cache/go/example.com/m/@v/v1.0.0.mod http://proxy/
  cu -X GET -d x http://proxy/_cache/go/example.com/m/@v/v1.0.0.mod
  cu --path-as-is http://proxy/_cache/go/example.com/../m/@v/v1.0.0.mod
  cu http://proxy/_cache/go/example.com/%2e%2e/@v/v1.0.0.mod
  for p in @v/v1.0.0.info @latest @v/list '@v/v1.0.0.mod?v=1'; do cu \"http://proxy/_cache/go/example.com/m/\$p\"; done
  cu http://proxy/_cache/go/Example.com/m/@v/v1.0.0.mod
  cu http://proxy/_cache/go/corp.example/x/@v/v1.0.0.mod" > $G/g2; T=$(cat $G/last); cat $G/g2
check "A-G5 straight to the proxy socket, a non-GET, absolute form, a body, ../, %2e, .info, @latest, @v/list, a version query, a bad escape and a GOPRIVATE path get 404, 405 (or 400 plain_http for absolute form), with no taint, no upstream request and no store change" '
  [ "$(grep -c "^40[045] " $G/g2)" = 12 ] && head -1 $G/g2 | grep -q "^405 " && [ -z "$(arec TAINT subject=task:$T producer=proxy)" ] &&
  [ -z "$(uplog)" ] && [ "$(store $A1)" = "$s0" ]'
check "A-G5 a +incompatible version and a pseudo-version are both served through the filter" '
  task $A1 "curl -sf http://127.0.0.1:8083/example.com/inc/@v/v2.0.0+incompatible.mod && curl -sf http://127.0.0.1:8083/example.com/pseudo/@v/v0.0.0-20260101000000-abcdefabcdef.mod" > $G/g3 &&
  grep -qx "module example.com/inc" $G/g3 && grep -qx "module example.com/pseudo" $G/g3'

# --- A-G6: taint first, two producers ---
cp $K/vkey $WS/$A4/.vkey && chown ag-$A4:ag-$A4 $WS/$A4/.vkey
task $A4 'for i in $(seq -w 1 20); do curl -s -o /dev/null http://127.0.0.1:8083/example.com/w/m$i/@v/v1.0.0.mod & done; wait; echo done' > /dev/null; T=$(cat $G/last)
arec TAINT subject=task:$T; arec CACHE event=fill task=$T | head -2
check "A-G6 a clean task's first cache use (20 parallel first requests, misses): one cache:go TAINT from agentboxd and one from the proxy, both before its first fill" '
  [ "$(arec TAINT subject=task:$T source=cache:go producer=agentboxd | wc -l)" = 1 ] && [ "$(arec TAINT subject=task:$T source=cache:go producer=proxy | wc -l)" = 1 ] &&
  first=$(arec CACHE event=fill task=$T | head -1 | cut -d" " -f1) && [ -n "$first" ] &&
  for s in $(arec TAINT subject=task:$T source=cache:go | cut -d" " -f1); do [ "$s" -lt "$first" ] || exit 1; done'
task $A4 'curl -sf -o /dev/null http://127.0.0.1:8083/example.com/w/m01/@v/v1.0.0.mod && echo hit' > $G/h; T=$(cat $G/last)
check "A-G6 a hit gets the same two taint records, before it is served" 'grep -qx hit $G/h && [ -z "$(arec CACHE event=fill task=$T)" ] &&
  [ "$(arec TAINT subject=task:$T source=cache:go | wc -l)" = 2 ]'
mkdir -p $WS/$A5/vend/vendor/example.com/w/m01 && cp $K/fixture/go.sum $WS/$A5/vend/ &&
  printf 'module example.com/vend\n\ngo 1.21\n\nrequire example.com/w/m01 v1.0.0\n' > $WS/$A5/vend/go.mod &&
  printf '# example.com/w/m01 v1.0.0\n## explicit; go 1.21\nexample.com/w/m01\n' > $WS/$A5/vend/vendor/modules.txt &&
  printf 'package m01\n\nfunc F() int { return 1 }\n' > $WS/$A5/vend/vendor/example.com/w/m01/m.go &&
  printf 'package vend\n\nimport "example.com/w/m01"\n\nvar X = m01.F()\n' > $WS/$A5/vend/v.go && chown -R ag-$A5:ag-$A5 $WS/$A5/vend
check "A-G6 a clean Go task with vendor/ makes no cache request and ends clean" '
  task $A5 "cd vend && go build ./... && echo built" > $G/vd && grep -qx built $G/vd && T=$(cat $G/last) && [ "$(reqs $T)" = 0 ] &&
  [ -z "$(arec TAINT subject=task:$T)" ] && [ -z "$(arec TAINT subject=workspace:$A5#$(( $(id -u ag-$A5) - 70000 )))" ]'
stand -no-taint
task $A5 'curl -sf -o /dev/null http://127.0.0.1:8083/example.com/w/m30/@v/v1.0.0.mod && echo served' > $G/nt; T=$(cat $G/last)
check "A-G6 a test proxy that writes no taint record: the filter's record still taints the task before its first fill" 'grep -qx served $G/nt &&
  [ -z "$(arec TAINT subject=task:$T producer=proxy)" ] && g=$(arec TAINT subject=task:$T source=cache:go producer=agentboxd | cut -d" " -f1) && [ -n "$g" ] &&
  f=$(arec CACHE event=fill task=$T | head -1 | cut -d" " -f1) && [ "$g" -lt "$f" ]'
stand
rm -f $WS/$A1/go1 $WS/$A1/done1 $G/last
task $A1 'while [ ! -e /workspace/go1 ]; do sleep 0.1; done; curl -s -D - -o /tmp/b --unix-socket /run/agentbox/egress/proxy.sock http://proxy/_cache/go/example.com/m/@v/v1.1.0.mod; echo body=$(wc -c < /tmp/b); touch /workspace/done1' > $G/ad 2>&1 &
tp=$!; for i in $(seq 600); do [ -s $G/last ] && [ -d /run/agentbox-proxy/t/$(cat $G/last) ] && break; sleep 0.1; done
systemctl stop agentbox-auditd.service "agentbox-auditd-*.socket"; touch $WS/$A1/go1
for i in $(seq 300); do [ -e $WS/$A1/done1 ] && break; sleep 0.1; done
systemctl start "agentbox-auditd-*.socket" agentbox-auditd.service; wait $tp; cat $G/ad
check "A-G6 with auditd stopped, a proxy cache request gets 503 and 0 body bytes" 'grep -q "^HTTP/1.1 503" $G/ad && grep -qx "body=0" $G/ad'
rm -f $WS/$A1/go2 $WS/$A1/done2 $G/last
task $A1 'while [ ! -e /workspace/go2 ]; do sleep 0.1; done; cd fx && go clean -modcache; go mod download -x 2>&1 | grep -c "^# get https://proxy.golang.org/" ; go test ./...; touch /workspace/done2' > $G/ab 2>&1 &
tp=$!; for i in $(seq 600); do [ -s $G/last ] && [ -d /run/agentbox-proxy/t/$(cat $G/last) ] && break; sleep 0.1; done; T=$(cat $G/last)
systemctl stop agentboxd.service; touch $WS/$A1/go2
for i in $(seq 1200); do [ -e $WS/$A1/done2 ] && break; sleep 0.1; done
systemctl start agentboxd.service; wait $tp; cat $G/ab
check "A-G6 with agentboxd stopped, the filter serves nothing and go falls back to CONNECT: go test passes, with no cache request" '
  grep -q "^ok  *example.com/fx" $G/ab && [ "$(grep -c " REQ $T $A1 GET /_cache/" $P)" = 0 ] && grep -q " REQ $T $A1 CONNECT proxy.golang.org:443" $P'
# --- A-G7: parity ---
task $A3 'env | grep ^GOPROXY=; curl -s -o /dev/null -w "%{http_code}\n" --unix-socket /run/agentbox/egress/proxy.sock http://proxy/_cache/go/example.com/w/m01/@v/v1.0.0.mod' > $G/p7; T=$(cat $G/last); cat $G/p7
check "A-G7 off the allowlist: GOPROXY=off, and a direct /_cache/ request gets 404 with no taint and no lookup" '
  grep -qx GOPROXY=off $G/p7 && grep -qx 404 $G/p7 && [ -z "$(arec TAINT subject=task:$T)" ] && [ "$(store $A3)" = "0 0 0" ]'
task $A1 'cd fx && go clean -modcache && GOPROXY=https://proxy.golang.org,direct go test ./... 2>&1' > $G/p8; T=$(cat $G/last)
check "A-G7 without the filter entry, go test gives the same result and the task is tainted all the same" '
  grep -q "^ok  *example.com/fx" $G/p8 && grep "^ok" $G/w2 | cut -f1-2 > $G/ok2 && grep "^ok" $G/p8 | cut -f1-2 | cmp -s - $G/ok2 &&
  arec TAINT subject=task:$T source=proxy:proxy.golang.org:443 | grep -q .'

# --- A-G8: poisoning and a hostile proxy ---
uplog > /dev/null
ctl "alter?mod=example.com/m&v=v1.2.0&ext=zip&on=1"
task $A1 'curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8083/example.com/m/@v/v1.2.0.zip' > $G/a8; T=$(cat $G/last)
check "A-G8 (a) an upstream zip that differs from the signed record is refused: sum_mismatch, no row, no blob" '
  grep -qx 404 $G/a8 && arec CACHE event=sum_mismatch agent=$A1 | grep -q "example.com/m@v1.2.0.zip" &&
  ! python3 -c "import sqlite3,sys; sys.exit(not sqlite3.connect(\"file:$C/$A1/index.db?mode=ro\", uri=True).execute(\"select 1 from entries where key like \x27%example.com/m@v1.2.0%\x27\").fetchone())" &&
  arec ALERT source=cache agent=$A1 reason=sum_mismatch | grep -q .'
ctl "alter?mod=example.com/m&v=v1.2.0&ext=zip&on=0"
# (b): a blob and its row changed together, for example.com/w/m05's zip
python3 - "$C/$A1" <<'PY'
import hashlib, os, sqlite3, sys
d = sys.argv[1]
c = sqlite3.connect(d + "/index.db")
old, = c.execute("select sha256 from entries where key='go:example.com/w/m05@v1.0.0.zip'").fetchone()
import io, zipfile
zin, out = zipfile.ZipFile(d + "/blobs/" + old), io.BytesIO()
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for n in zin.namelist():
        z.writestr(n, zin.read(n).replace(b"return 5", b"return 6") if n.endswith("/m.go") else zin.read(n))
b = out.getvalue()
new = hashlib.sha256(b).hexdigest()
open(d + "/blobs/" + new, "wb").write(b)
os.chown(d + "/blobs/" + new, os.stat(d).st_uid, os.stat(d).st_gid)
c.execute("update entries set sha256=?, size=? where key='go:example.com/w/m05@v1.0.0.zip'", (new, len(b)))
c.commit()
PY
task $A1 'cd fx && go clean -modcache; go build ./... > /tmp/o 2>&1; echo with_sum=$?; grep -m1 -i "checksum\|security" /tmp/o
  mkdir -p /tmp/ns && cp go.mod fx.go /tmp/ns/ && grep -v "^example.com/w/m05 " go.sum > /tmp/ns/go.sum && cd /tmp/ns && go clean -modcache
  GOSUMDB=$(cat /workspace/.vkey) go build ./... > /tmp/o2 2>&1; echo no_sum=$?; grep -m1 -i "checksum\|security\|verifying" /tmp/o2' > $G/b8 2>&1; cat $G/b8
check "A-G8 (b) a blob altered with its row: go stops with a checksum error and builds nothing, with and without a go.sum line" '
  grep -q "^with_sum=[1-9]" $G/b8 && grep -q "^no_sum=[1-9]" $G/b8 && [ "$(grep -ci "checksum mismatch\|security error\|verifying" $G/b8)" -ge 2 ]'
$B cache purge --agent $A1 >/dev/null
# (c): one byte of a blob alone
task $A1 'cd fx && go mod download && echo filled' >/dev/null
python3 - "$C/$A1" <<'PY'
import sqlite3, sys
d = sys.argv[1]
h, = sqlite3.connect("file:%s/index.db?mode=ro" % d, uri=True).execute("select sha256 from entries where key='go:example.com/w/m07@v1.0.0.zip'").fetchone()
p = d + "/blobs/" + h
b = bytearray(open(p, "rb").read()); b[100] ^= 1
import os; os.chmod(p, 0o644); open(p, "wb").write(b); os.chmod(p, 0o444)
PY
task $A1 'cd fx && go clean -modcache && go test ./... 2>&1' > $G/c8; T=$(cat $G/last)
check "A-G8 (c) one flipped byte in a blob: the entry is deleted and filled again, and the task passes" '
  grep -q "^ok  *example.com/fx" $G/c8 && arec CACHE event=blob_corrupt agent=$A1 | grep -q "example.com/w/m07@v1.0.0.zip" &&
  arec CACHE event=fill task=$T | grep -q "example.com/w/m07@v1.0.0.zip"'
mkdir -p $WS/$A1/mg && printf 'module example.com/mg\n\ngo 1.21\n' > $WS/$A1/mg/go.mod && printf 'package mg\n\nimport _ "example.com/m"\n' > $WS/$A1/mg/mg.go && chown -R ag-$A1:ag-$A1 $WS/$A1/mg
task $A1 'cp -r /workspace/mg /tmp/mg && cd /tmp/mg && export GOSUMDB=$(cat /workspace/.vkey) GOPROXY=https://proxy.golang.org,direct; go list -m -json example.com/m@v1.1.0 | grep -E "\"(Version|Time)\""; go get example.com/m 2>&1 | tail -1' > $G/d0
stand -hostile
: > $G/hostile.mark; hl=$(wc -l < $P)
task $A1 'cp -r /workspace/mg /tmp/mg && cd /tmp/mg && export GOSUMDB=$(cat /workspace/.vkey); go list -m -json example.com/m@v1.1.0 | grep -E "\"(Version|Time)\""; go get example.com/m 2>&1 | tail -1' > $G/d1
cat $G/d0 $G/d1
check "A-G8 (d) a hostile proxy that forges every /_cache/ list, @latest, .info and sumdb reply: it sees only .mod and .zip GETs, and go list and go get give the same version and time as with no cache" '
  [ -s $G/d0 ] && diff $G/d0 $G/d1 >/dev/null && tail -n +$((hl + 1)) $P | grep " GET /_cache/" > $G/hreq; cat $G/hreq; [ -s $G/hreq ] && ! grep -v "\.\(mod\|zip\)$" $G/hreq'
task $A1 'for e in mod zip; do curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8083/example.com/m/@v/v1.0.0.$e; done' > $G/e0
ctl "gone?mod=example.com/m&v=v1.0.0&on=1"
task $A1 'for e in mod zip; do curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8083/example.com/m/@v/v1.0.0.$e; curl -s -o /dev/null -w "proxy %{http_code}\n" --unix-socket /run/agentbox/egress/proxy.sock http://proxy/_cache/go/example.com/m/@v/v1.0.0.$e; done' > $G/e8; cat $G/e0 $G/e8
check "A-G8 (e) a version upstream answers 410 for, which the hostile proxy still serves: the filter gives 404 for its .mod and .zip" '
  [ "$(grep -cx 200 $G/e0)" = 2 ] && [ "$(grep -cx 404 $G/e8)" = 2 ] && [ "$(grep -cx "proxy 200" $G/e8)" = 2 ]'
ctl "gone?mod=example.com/m&v=v1.0.0&on=0"
stand

# --- A-G9: isolation ---
ctl "slow?ms=300&rate=0"
uplog > /dev/null
( setpriv --reuid agentbox-proxy --regid agentbox-proxy --clear-groups $G/standin watch $C/$A1 25 > $G/watch ) &
wp=$!; sleep 1
task $A2 't0=$(date +%s%N); curl -sf -o /dev/null http://127.0.0.1:8083/example.com/w/m01/@v/v1.0.0.zip; echo ms=$(( ($(date +%s%N)-t0)/1000000 ))' > $G/i9; T=$(cat $G/last)
wait $wp; cat $G/watch $G/i9
check "A-G9 agent $A2's miss of a module only $A1 holds is a real upstream fetch under $A2, as slow as a cold fill, and touches nothing of $A1's store" '
  arec CACHE event=fill agent=$A2 task=$T | grep -q "example.com/w/m01@v1.0.0.zip" && uplog | grep -qx "GET /example.com/w/m01/@v/v1.0.0.zip" &&
  grep -qx "events 0" $G/watch && [ "$(sed -n "s/^ms=//p" $G/i9)" -ge 300 ]'
ctl "slow?ms=0&rate=0"

# --- A-G11: private paths ---
mkdir -p $WS/$A1/pv && printf 'module example.com/pv\n\ngo 1.21\n\nrequire corp.example/x v1.0.0\n' > $WS/$A1/pv/go.mod && chown -R ag-$A1:ag-$A1 $WS/$A1/pv
uplog > /dev/null; pl=$(wc -l < $P)
task $A1 'cd pv && env | grep ^GOPRIVATE=; go mod download 2>&1 | tail -2; curl -s -o /dev/null -w "%{http_code}\n" --unix-socket /run/agentbox/egress/proxy.sock http://proxy/_cache/go/corp.example/x/@v/v1.0.0.mod' > $G/pv; cat $G/pv
check "A-G11 after go.private.set{$A1, corp.example/*}: no request naming corp.example reaches the cache path, the checksum client or the upstream, and a direct /_cache/ request for it gets 404" '
  grep -qx "GOPRIVATE=corp.example/\*" $G/pv && tail -1 $G/pv | grep -qx 404 && ! tail -n +$((pl + 1)) $P | grep "/_cache/" | grep -q corp.example &&
  ! uplog | grep -q corp.example && ! arec CACHE | grep -q corp.example'

# --- A-G12: lifecycle ---
check "A-G12 agent.remove deletes data/cache/<agent>; agent.add made it" '$B agent add --name $A6 >/dev/null && [ -d $C/$A6 ] && $B agent remove --name $A6 >/dev/null && [ ! -e $C/$A6 ]'
task $A2 'curl -sf -o /dev/null http://127.0.0.1:8083/example.com/w/m02/@v/v1.0.0.zip' >/dev/null
task $A1 'curl -sf -o /dev/null http://127.0.0.1:8083/example.com/w/m03/@v/v1.0.0.zip' >/dev/null
check "A-G12 cache.purge{$A2} empties $A2's store, audited, while $A1 keeps its hits" '$B cache purge --agent $A2 >/dev/null && [ "$(store $A2)" = "0 0 0" ] &&
  arec INTENT name=cache.purge | grep -q $A2 && task $A1 "curl -sf -o /dev/null http://127.0.0.1:8083/example.com/w/m03/@v/v1.0.0.zip" && T=$(cat $G/last) &&
  [ -z "$(arec CACHE event=fill task=$T)" ]'
ctl "slow?ms=4000&rate=0"
rm -f $G/last
task $A1 'curl -s -o /dev/null -m 30 http://127.0.0.1:8083/example.com/pseudo/@v/v0.0.0-20260101000000-abcdefabcdef.zip; true' >/dev/null &
tp=$!; for i in $(seq 100); do ls $C/$A1/tmp 2>/dev/null | grep -q . && break; sleep 0.1; done
systemctl kill -s KILL agentbox-proxy.service; sleep 1; systemctl start agentbox-proxy.service || stand; wait $tp
check "A-G12 the proxy killed mid-fill: after its restart no temp file, no orphan blob and no row without a blob" 'sleep 1 && consistent $A1'
rm -f $WS/$A2/started $G/last
task $A2 'touch /workspace/started; curl -s -o /dev/null -m 30 http://127.0.0.1:8083/example.com/w/m41/@v/v1.0.0.zip; true' >/dev/null &
tp=$!; for i in $(seq 100); do ls $C/$A2/tmp 2>/dev/null | grep -q . && break; sleep 0.1; done; T=$(cat $G/last)
$B task stop --task $T >/dev/null; wait $tp
check "A-G12 a fill whose task is revoked mid-download inserts no row" 'sleep 5 && ! python3 -c "import sqlite3,sys; sys.exit(not sqlite3.connect(\"file:$C/$A2/index.db?mode=ro\", uri=True).execute(\"select 1 from entries where key like \x27%m41%\x27\").fetchone())" && consistent $A2'
ctl "slow?ms=0&rate=0"

# --- C-G4 and A-G10: budget.set, day shares, caps ---
check "C-G4 budget.set refuses day shares that sum above the box cap, and changes nothing" '
  ! printf "keys.day_cap_cents = 1000\nkeys.agent_day_share.$A1 = 600\nkeys.agent_day_share.$A2 = 500\n" | $B budget set > $G/bs && grep -q "above keys.day_cap_cents" $G/bs &&
  [ ! -e /var/lib/agentbox/control/budgets.toml ]'
check "C-G4 budget.set with a box cap: the day shares split it equally, an explicit one first, and agent.add recomputes them" '
  printf "keys.day_cap_cents = 1000\nkeys.agent_day_share.$A1 = 600\n" | $B budget set >/dev/null && cat /var/lib/agentbox/control/day-shares.json &&
  python3 -c "import json,sys; s=json.load(open(\"/var/lib/agentbox/control/day-shares.json\")); sys.exit(not (s[\"capCents\"] == 1000 and s[\"agents\"][\"$A1\"] == 600 and s[\"agents\"][\"$A2\"] == 100))" &&
  arec INTENT name=budget.set | grep -q day_cap_cents && $B agent add --name $A7 >/dev/null &&
  python3 -c "import json,sys; s=json.load(open(\"/var/lib/agentbox/control/day-shares.json\")); sys.exit(not (s[\"agents\"][\"$A2\"] == 80 and s[\"agents\"][\"$A7\"] == 80 and s[\"agents\"][\"$A1\"] == 600))" &&
  $B agent remove --name $A7 >/dev/null'
printf 'cache.task_fill_max_files = 3\n' | $B budget set >/dev/null; stand
task $A5 'for i in $(seq -w 41 46); do curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8083/example.com/w/m$i/@v/v1.0.0.mod; done' > $G/c10; T=$(cat $G/last); cat $G/c10
check "A-G10 past cache.task_fill_max_files (3) new misses get 404" '[ "$(head -3 $G/c10 | grep -cx 200)" = 3 ] && [ "$(tail -3 $G/c10 | grep -cx 404)" = 3 ] &&
  [ "$(arec CACHE event=fill task=$T | wc -l)" = 3 ]'
cp -r $K/fixture $WS/$A5/fx && chown -R ag-$A5:ag-$A5 $WS/$A5/fx
check "  ... and go test still passes, over CONNECT" 'task $A5 "cd fx && go test ./... 2>&1" | grep -q "^ok  *example.com/fx"'
printf 'cache.agent_fill_day_bytes = 1\n' | $B budget set >/dev/null; stand
check "A-G10 past the agent's cache.agent_fill_day_bytes, a miss gets 404" 'task $A5 "curl -s -o /dev/null -w \"%{http_code}\n\" http://127.0.0.1:8083/example.com/w/m50/@v/v1.0.0.zip" | grep -qx 404'
printf 'disk.reserve_bytes = 1125899906842624\n' | $B budget set >/dev/null; stand
check "A-G10 below disk.reserve_bytes, nothing fills" 'task $A4 "curl -s -o /dev/null -w \"%{http_code}\n\" http://127.0.0.1:8083/example.com/w/m51/@v/v1.0.0.zip" | grep -qx 404'
printf 'cache.agent_max_bytes = 4194304\n' | $B budget set >/dev/null; stand
check "A-G10 budget.set re-applies cache.agent_max_bytes to each store's qgroup" 'id=$(btrfs inspect-internal rootid $C/$A4) &&
  btrfs --format=json qgroup show -e /var/lib/agentbox | python3 -c "import json,sys; q={r[\"qgroupid\"]: r for r in json.load(sys.stdin)[\"qgroup-show\"]}[\"0/$id\"]; sys.exit(str(q[\"max_exclusive\"]) != \"4194304\")"'
task $A4 'for i in $(seq -w 1 64); do curl -s -o /dev/null http://127.0.0.1:8083/example.com/w/m$i/@v/v1.0.0.zip; done; echo done' >/dev/null
check "A-G10 the store never passes cache.agent_max_bytes, and LRU keeps the newest entries" '
  python3 -c "
import sqlite3,sys; c=sqlite3.connect(\"file:$C/$A4/index.db?mode=ro\", uri=True)
u=c.execute(\"select sum(size) from (select max(size) size from entries group by sha256)\").fetchone()[0] or 0
k={r[0] for r in c.execute(\"select key from entries\")}; print(u, len(k))
sys.exit(not (u <= 4194304 and \"go:example.com/w/m64@v1.0.0.zip\" in k and \"go:example.com/w/m01@v1.0.0.zip\" not in k))"'
check "A-G10 a direct write past the kernel limit as agentbox-proxy gets EDQUOT" '
  ! setpriv --reuid agentbox-proxy --regid agentbox-proxy --clear-groups dd if=/dev/urandom of=$C/$A4/tmp/big bs=1M count=8 conv=fsync 2> $G/dq; cat $G/dq; grep -q "Disk quota exceeded" $G/dq; rm -f $C/$A4/tmp/big'
: | $B budget set >/dev/null; stand

# --- cleanup: the stand-in and the drop-ins go; the box's own state stays ---
systemctl stop agentbox-proxy.service agentbox-proxy.socket
rm -f $RS/agentboxd.service.d/50-gocache.conf $RS/agentbox-rootd.service.d/50-gocache.conf; systemctl daemon-reload
systemctl restart agentbox-rootd.service agentboxd.service
podman rmi -f $IMG-ca $IMG >/dev/null 2>&1
echo "fails=$fails"
EOF
  ;;
*) die "unknown step $s (install or checks)" ;;
esac; done
! grep -q '^[0-9:]* FAIL' "$OUT"

#!/bin/sh
# Weeks 5-6 gate for the v5.3 task additions (PLAN.md row 5-6; PROPOSALS-v5.3 A-G1, A-G2, C-G2; ARCHITECTURE.md §4.2,
# §5.6, §8 Exports, Appendix C) on the local arm64 QEMU VM, none mode.
#   hack/taskenv-gate.sh [install|checks ...]   default: both, in order
# install  hack/gate.sh none: the unattended install and the release pipeline, so rootd, the CLI and the units arrive
#          the real way.
# checks   builds image/task on the box and loads it into two agents' podman (`agentbox agent add`, rootd's agent.add);
#          rootd launches it for them instead of the stub image (AGENTBOX_TEST_TASK_IMAGE). Every task is started with
#          `agentbox task new`, dispatched by agentboxd, launched by rootd's task.start with the task env, and run as a
#          sh script (AGENTBOX_TEST_CLI=sh) by taskrun after it starts the in-task forwarders. No --dns=none: podman
#          refuses it with --network=none, and leaves the image's resolv.conf as it is (taskenv).
#          A-G1: the Go, proxy and quiet npm/pip env for an agent with and without proxy.golang.org:443; GOPROXY=off
#          fails at once with 0 CONNECTs; with it, go asks taskrun's Go module filter first and, when the filter answers
#          404, proxy.golang.org over the egress forwarder; GOPRIVATE from go.private.set; the image's GOFLAGS, GONOSUMDB, GONOPROXY,
#          GOINSECURE, HTTP_PROXY and ALL_PROXY never reach the task; the pinned Go; no cache survives into the next
#          task; npm test and pip list open 0 CONNECTs. A-G2: a go.mod that needs a newer Go fails with go's own
#          toolchain error and 0 CONNECTs. C-G2: direct lookups fail in under 1 s; resolv.conf names only 127.0.0.1; the
#          proxy env; a broker down 3 s is reconnected, down for good gives 503 BROKER_UNAVAILABLE within 6 s, which
#          agentbox why prints; the 64-entry log, gone in the next task; the task's result carries the newest 20, and
#          its witness END is the sha256 of the result agentboxd got (#223); why --errno EOPNOTSUPP; a rootd crash mid-task
#          restarts rootd alone, so the task completes (#218); the eight fixed lines,
#          the same for two agents and in the CLIs' HOME files; the witness FIFO from task.start to task.stop
#          (write-only for the task, closed to uid agentbox, 1 MiB kept at 64 KiB, and 1 MiB of END lines or with no
#          newline counted the same (#222), removed at stop, incomplete after a rootd restart, with no alert).
# Stand-in until its area lands: stub brokers (python3, until the proxy and keys brokers of milestone 5) on
# svc-proxy.sock and svc-keys.sock, which bind each task's proxy.sock and keys.sock on rootd's register.
# PASS/FAIL lines go to .vm/taskenv-gate.txt, command output to .vm/taskenv-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/taskenv-gate.txt" LOG="$VM/taskenv-gate.log"
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
  # the image's build context, and the eight fixed lines as ARCHITECTURE.md §8 states them
  tar -C image -cf - task | hack/vm.sh ssh 'rm -rf /tmp/gate-image && mkdir /tmp/gate-image && tar -C /tmp/gate-image -xf -'
  sed -n 's/^  [1-8]\. `\(.*\)`$/\1/p' docs/design/ARCHITECTURE.md | hack/vm.sh ssh 'cat > /tmp/gate-fixed'
  guest <<'EOF'
fails=0
cd / # runuser keeps the working dir, and the agent can't enter the admin's home
check() { if (eval "$2") >>/tmp/gate-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
B=/var/lib/agentbox/current/bin/agentbox
A=/var/lib/agentbox/audit
E=/var/lib/agentbox/control/egress
X=/var/lib/agentbox/control/exports
WS=/var/lib/agentbox/data/workspaces
IMG=localhost/agentbox-task:gate
W=/run/agentbox-witness/t
RS=/run/systemd/system
G=/var/tmp/gate
mkdir -p $G && chmod 0755 $G

# --- setup: the task image, two agents, the test CLI and image, stub brokers ---
# the build's RUN steps use the box's own resolver (--network=host): on some host networks slirp answers DNS over
# IPv6 only, and a build container gets the IPv4 server
check "image/task builds on the box (ubuntu:26.04, apt tools, mise with the pinned Go)" 'podman build -q --network=host -t $IMG /tmp/gate-image/task </dev/null'
# the image sets what taskrun must unset, so the env checks see them removed, not merely absent
printf 'FROM %s\nENV GOFLAGS=-mod=mod GONOSUMDB=corp.example GONOPROXY=corp.example GOINSECURE=corp.example HTTP_PROXY=http://10.9.9.9:3128 http_proxy=http://10.9.9.9:3128 ALL_PROXY=socks5://10.9.9.9:1080 all_proxy=socks5://10.9.9.9:1080\n' $IMG > $G/Containerfile
# podman save won't write over the archive an earlier run on this box left
podman build -q -t $IMG-env -f $G/Containerfile $G </dev/null >/dev/null && rm -f $G/image.tar && podman save -o $G/image.tar $IMG-env && chmod 0644 $G/image.tar
# podman load runs through the agent's user manager, as rootd's ensureImage does, so podman's pause process gets its
# own scope there, not a root session's
for a in ga gb; do
  check "agent add $a (rootd's agent.add), and the task image in its podman" '{ $B agent add --name $a || $B agent list | grep -q "\"name\":\"$a\""; } && u=$(id -u ag-$a) &&
    i=0; until systemctl is-active -q user@$u.service; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done &&
    systemd-run --user -M ag-$a@ --wait --quiet --collect /usr/bin/podman load -q -i $G/image.tar </dev/null'
  find $WS/$a -mindepth 1 -delete 2>/dev/null || : # a rerun on the same box starts from an empty workspace
done
mkdir -p $E && printf '# gate: the human-added deputy host for ga\nproxy.golang.org:443\n' > $E/ga.list
mkdir -p $RS/agentboxd.service.d $RS/agentbox-rootd.service.d
printf '[Service]\nEnvironment=AGENTBOX_TEST_CLI=sh\n' > $RS/agentboxd.service.d/50-taskenv.conf
printf '[Service]\nEnvironment=AGENTBOX_TEST_TASK_IMAGE=%s-env\n' $IMG > $RS/agentbox-rootd.service.d/50-taskenv.conf
cat > $G/broker.py <<'PY'
# stub broker (test VMs only): logs each request line; CONNECT ok.example is tunneled, any other CONNECT gets the
# proxy's denial head; any other request gets a 200 JSON reply.
import json, os, secrets, socket, sys, threading
sock, log = sys.argv[1], sys.argv[2]
C = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
def head(f):
    hs = []
    while True:
        h = f.readline()
        if h in (b"\r\n", b"\n", b""):
            return hs
        hs.append(h)
def serve(c):
    f = c.makefile("rwb")
    line = f.readline().decode()
    hs = head(f)
    with open(log, "a") as l:
        l.write(line)
    m, target = (line.split() + ["", ""])[:2]
    if m == "CONNECT" and target.startswith("ok.example"):
        f.write(b"HTTP/1.1 200 Connection established\r\n\r\n"); f.flush()
        head(f)
        f.write(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
    elif m == "CONNECT":
        i = "dn_" + C[secrets.randbelow(8)] + "".join(C[secrets.randbelow(32)] for _ in range(25))
        body = json.dumps({"error": "stub", "agentbox": {"id": i}}).encode()
        f.write(("HTTP/1.1 403 agentbox EGRESS_NOT_ALLOWLISTED (run: agentbox why)\r\nAgentbox-Denial: v1 code=EGRESS_NOT_ALLOWLISTED next=ask id=%s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (i, len(body))).encode() + body)
    else:
        n = next((int(h.split(b":")[1]) for h in hs if h.lower().startswith(b"content-length:")), 0)
        f.read(n)
        f.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"ok\":true}\n")
    f.flush(); c.close()
try:
    os.unlink(sock)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX); s.bind(sock); os.chmod(sock, 0o666); s.listen(64)
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
# rootd's side of a stub broker: svc-<svc>.sock takes register and revoke (§2.1); register starts broker.py on the
# task's <svc>.sock unless $G/down-<svc> exists, revoke stops it
cat > $G/svc.py <<'PY'
import json, os, socket, subprocess, sys, threading, time
svc, g = sys.argv[1], sys.argv[2]
ctl = "/run/agentbox-rootd/svc-%s.sock" % svc
def serve(c):
    f = c.makefile("rwb")
    req = json.loads(f.readline() or "{}")
    t, sock = req.get("task", ""), "/run/agentbox-%s/t/%s/%s.sock" % (svc, req.get("task", ""), svc)
    pid = "%s/%s-%s.pid" % (g, svc, t)
    if req.get("call") == "register" and not os.path.exists("%s/down-%s" % (g, svc)):
        p = subprocess.Popen(["python3", g + "/broker.py", sock, "%s/%s.log" % (g, svc)], stdin=subprocess.DEVNULL,
                             stdout=open(g + "/broker.err", "a"), stderr=subprocess.STDOUT)
        open(pid, "w").write(str(p.pid))
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
    elif req.get("call") == "revoke" and os.path.exists(pid):
        subprocess.run(["kill", open(pid).read()])
    f.write(b'{"ok":true}\n'); f.flush(); c.close()
try:
    os.unlink(ctl)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX); s.bind(ctl); os.chmod(ctl, 0o600); s.listen(16)
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
# the release's proxy and keys broker own svc-proxy.sock and svc-keys.sock: they stop while the stand-ins run, and start
# again at cleanup
systemctl stop agentbox-proxy.service agentbox-proxy-svc.socket agentbox-keys.service agentbox-keys-svc.socket
for v in proxy keys; do python3 $G/svc.py $v $G </dev/null >>$G/broker.err 2>&1 & echo $! > $G/svc-$v.pid; done
systemctl daemon-reload
check "agentboxd with AGENTBOX_TEST_CLI=sh, rootd with the gate's task image, and the stub brokers' svc sockets" '
  systemctl restart agentbox-rootd.service agentboxd.service && systemctl is-active -q agentbox-rootd agentboxd &&
  sleep 1 && [ -S /run/agentbox-rootd/svc-proxy.sock ] && [ -S /run/agentbox-rootd/svc-keys.sock ]'
broker_up() { python3 $G/broker.py /run/agentbox-$1/t/$2/$1.sock $G/$1.log </dev/null >>$G/broker.err 2>&1 & echo $! > $G/$1-$2.pid
  for i in $(seq 50); do [ -S /run/agentbox-$1/t/$2/$1.sock ] && return 0; sleep 0.1; done; return 1; }
connects() { touch $G/proxy.log; grep -c '^CONNECT' $G/proxy.log || :; }
ended() { $B task list | python3 -c 'import json,sys; sys.exit(not [t for t in json.load(sys.stdin)["tasks"] if t["task"]==sys.argv[1] and t.get("end_reason")])' "$1"; }
# wrec TASK: the task's WITNESS record from the audit segments
wrec() { for i in $(seq 50); do cat $A/seg-*.jsonl | grep "\"type\":\"WITNESS\"" | grep "\"task\":\"$1\"" | tail -1 | grep . && return 0; sleep 0.2; done; return 1; }
# task AGENT SCRIPT: one task through task.start; prints what the script printed and returns its exit code. The id goes
# to $G/last. After `down SVC...`, the next task starts with those brokers down.
down() { for v; do touch $G/down-$v; done; }
task() { o=$WS/$1/.gate-out; rm -f $o $WS/$1/.gate-rc
  printf '(\n%s\n) </dev/null > /workspace/.gate-out 2>&1; echo $? > /workspace/.gate-rc\n' "$2" |
    $B task new --agent $1 --cli sh --deadline 5m > $G/new; r=$?
  rm -f $G/down-*
  sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' $G/new > $G/last
  [ $r = 0 ] && [ -s $G/last ] || { cat $G/new; return 99; }
  i=0; while [ ! -e $WS/$1/.gate-rc ]; do i=$((i+1)); [ $i -lt 1200 ] || { echo "task $(cat $G/last): no result"; return 98; }; sleep 0.1; done
  i=0; until ended "$(cat $G/last)"; do i=$((i+1)); [ $i -lt 300 ] || break; sleep 0.1; done
  cat $o; return "$(cat $WS/$1/.gate-rc)"; }
check "the task container runs the gate's image, with taskrun's forwarders on 127.0.0.1:8080-8082" '
  task ga "for p in 1F90 1F91 1F92; do grep -q \" 0100007F:\$p 00000000:0000 0A \" /proc/net/tcp || exit 1; done; command -v go"'
# #218: a crash restarts rootd alone (RestartMode=direct). In the default mode, systemd's automatic restart also
# restarts every user@ that Requires= rootd, which ends the agent's task. NRestarts counts only automatic restarts.
# It runs early: the explicit restart near the end restarts the user managers mid-task, and after it the agent's next
# launch failed with "task image: exit status 1".
rm -f $WS/ga/wready $WS/ga/wgo $G/last
task ga "touch /workspace/wready; while [ ! -e /workspace/wgo ]; do sleep 0.1; done; echo outlived" > $G/r7 2>&1 &
wt=$!
for i in $(seq 600); do [ -e $WS/ga/wready ] && [ -s $G/last ] && break; sleep 0.1; done
T7=$(cat $G/last) UM=user@$(id -u ag-ga).service
um=$(systemctl show -P MainPID $UM) nr=$(systemctl show -P NRestarts agentbox-rootd.service)
t7=$(date +%s); systemctl kill -s KILL agentbox-rootd.service
for i in $(seq 300); do [ "$(systemctl show -P NRestarts agentbox-rootd.service)" -gt "$nr" ] && systemctl is-active -q agentbox-rootd.service && break; sleep 0.1; done
touch $WS/ga/wgo; wait $wt
# to the host's log: what the check below compares, and the journal around the crash
echo "rootd crash: NRestarts $nr -> $(systemctl show -P NRestarts agentbox-rootd.service); $UM MainPID $um -> $(systemctl show -P MainPID $UM); task $T7: $(tr '\n' ' ' < $G/r7)"
$B task list | python3 -c 'import json,sys; print(*[t for t in json.load(sys.stdin)["tasks"] if t["task"]==sys.argv[1]])' "$T7"
journalctl -b -o short-monotonic -u agentbox-rootd.service -u "$UM" --since @$t7 | grep -v -E "agentbox: (witness|audit)" | tail -25
check "a rootd crash mid-task (SIGKILL): systemd restarts rootd alone, the agent's user manager keeps its PID, and the task completes" '
  [ "$(systemctl show -P NRestarts agentbox-rootd.service)" -gt "$nr" ] && [ -n "$um" ] && [ "$um" != 0 ] && [ "$(systemctl show -P MainPID $UM)" = "$um" ] &&
  grep -qx outlived $G/r7 && [ "$($B task list | python3 -c "import json,sys; print(*[t.get(\"end_reason\") for t in json.load(sys.stdin)[\"tasks\"] if t[\"task\"]==sys.argv[1]])" $T7)" = completed ]'

# --- A-G1: the task env ---
check "go.private.set{ga, corp.example/*} through rootd-admin.sock, audited" '$B goprivate set --agent ga --patterns "corp.example/*" &&
  [ "$(cat $E/ga.goprivate)" = "corp.example/*" ] && cat $A/seg-*.jsonl | grep "\"type\":\"INTENT\"" | grep -q "\"name\":\"go.private.set\""'
check "  ... a pattern with a space is refused" '! $B goprivate set --agent ga --patterns "a b" && [ "$(cat $E/ga.goprivate)" = "corp.example/*" ]'
task ga env > $G/env-ga; task gb env > $G/env-gb
check "A-G1 ga (proxy.golang.org:443 allowlisted): GOPROXY is the Go module filter, then proxy.golang.org, then direct" 'grep -qx "GOPROXY=http://127.0.0.1:8083,https://proxy.golang.org,direct" $G/env-ga'
check "  ... GOSUMDB=sum.golang.org, GOTOOLCHAIN=local, GOPRIVATE=corp.example/*" 'grep -qx GOSUMDB=sum.golang.org $G/env-ga && grep -qx GOTOOLCHAIN=local $G/env-ga && grep -qx "GOPRIVATE=corp.example/\*" $G/env-ga'
check "  ... the npm and pip flags and NO_UPDATE_NOTIFIER=1" 'for v in npm_config_audit=false npm_config_fund=false npm_config_update_notifier=false NO_UPDATE_NOTIFIER=1 PIP_DISABLE_PIP_VERSION_CHECK=1; do grep -qx $v $G/env-ga && grep -qx $v $G/env-gb || exit 1; done'
check "A-G1 gb (no proxy.golang.org): GOPROXY=off, GOTOOLCHAIN=local, no GOSUMDB and no GOPRIVATE" 'grep -qx GOPROXY=off $G/env-gb && grep -qx GOTOOLCHAIN=local $G/env-gb && ! grep -q "^GOSUMDB=\|^GOPRIVATE=" $G/env-gb'
check "A-G1 none of GOFLAGS, GONOSUMDB, GONOPROXY, GOINSECURE (nor HTTP_PROXY, ALL_PROXY), though the image sets them" '
  podman image inspect $IMG-env --format "{{.Config.Env}}" | grep -q GOFLAGS= && ! grep -qi "^\(GOFLAGS\|GONOSUMDB\|GONOPROXY\|GOINSECURE\|HTTP_PROXY\|ALL_PROXY\)=" $G/env-ga $G/env-gb'
printf 'module example.com/fx\n\ngo 1.27\n\nrequire rsc.io/quote v1.5.2\n' > $WS/gb/go.mod && chown -R ag-gb:ag-gb $WS/gb
c=$(connects)
check "A-G1 gb: go mod download fails at once with go's own GOPROXY=off error and 0 CONNECTs" '
  ! task gb "t0=\$(date +%s%N); go mod download; r=\$?; echo ms=\$(( (\$(date +%s%N)-t0)/1000000 )); exit \$r" > $G/gmd 2>&1 &&
  grep -q "module lookup disabled by GOPROXY=off" $G/gmd && [ "$(sed -n "s/^ms=//p" $G/gmd)" -lt 2000 ] && [ "$(connects)" = "$c" ]'
# the stub proxy refuses every CONNECT but ok.example, so the fetch fails: the filter's live check is refused and it
# answers 404, and go's own CONNECT to proxy.golang.org is refused too
mkdir -p $WS/ga/gofx && cp $WS/gb/go.mod $WS/ga/gofx/go.mod && chown -R ag-ga:ag-ga $WS/ga
c=$(connects)
check "A-G1 ga: go mod download asks the Go module filter, then proxy.golang.org through the egress forwarder" '
  task ga "cd gofx && go mod download -x" > $G/gma 2>&1; cat $G/gma; grep -q "^# get http://127.0.0.1:8083/" $G/gma &&
  grep -q "^# get https://proxy.golang.org/" $G/gma && [ "$(connects)" -gt "$c" ] && grep -q "^CONNECT proxy.golang.org:443 " $G/proxy.log'
check "A-G1 go version is the image's pinned Go ($(sed -n "s/^go = \"\(.*\)\"/\1/p" /tmp/gate-image/task/mise.toml))" '
  task ga "go version" | grep -qx "go version go$(sed -n "s/^go = \"\(.*\)\"/\1/p" /tmp/gate-image/task/mise.toml) linux/arm64"'
# taskrun's own HOME files include the task's canary decoys (#105): ~/.config/gh/hosts.yml and ~/.netrc
check "A-G1 a task writes \$GOCACHE, ~/go/pkg/mod and ~/.npm; the next task sees none of it, only taskrun's own HOME files" '
  task ga "for d in \$(go env GOCACHE) \$(go env GOMODCACHE) ~/.npm; do mkdir -p \$d && touch \$d/gate-mark; done; ls \$(go env GOCACHE)/gate-mark ~/go/pkg/mod/gate-mark ~/.npm/gate-mark" &&
  task ga "[ \"\$(ls -A ~ | sort | tr \"\n\" \" \")\" = \".agentbox .claude .codex .config .netrc \" ] && ! ls \$(go env GOCACHE)/gate-mark ~/go/pkg/mod/gate-mark ~/.npm/gate-mark 2>/dev/null || { ls -la ~; false; }"'
mkdir -p $WS/ga/js/node_modules/left-pad
printf '{"name":"fx","version":"1.0.0","scripts":{"test":"node -e \\"process.exit(0)\\""}}\n' > $WS/ga/js/package.json
echo 'module.exports = s => s' > $WS/ga/js/node_modules/left-pad/index.js
chown -R ag-ga:ag-ga $WS/ga
c=$(connects)
check "A-G1 npm test in a JS fixture with node_modules opens 0 CONNECTs" 'task ga "cd js && npm test && sleep 3" && [ "$(connects)" = "$c" ]'
check "A-G1 pip list in a fresh task opens 0 CONNECTs" 'task ga "pip list && sleep 3" | grep -q "^pip " && [ "$(connects)" = "$c" ]'
c=$(connects)
check "  ... the CONNECT count does see a task's request (control: curl through HTTPS_PROXY)" 'task ga "curl -s -o /dev/null https://example.com; true" && [ "$(connects)" -gt "$c" ]'

# --- A-G2: the toolchain ---
mkdir -p $WS/ga/newgo && printf 'module example.com/newgo\n\ngo 1.99\n' > $WS/ga/newgo/go.mod && printf 'package newgo\n' > $WS/ga/newgo/a.go && chown -R ag-ga:ag-ga $WS/ga
c=$(connects)
check "A-G2 a go.mod that needs go 1.99 fails with go's own toolchain error (GOTOOLCHAIN=local) and 0 CONNECTs" '
  ! task ga "cd newgo && go build ./..." > $G/newgo 2>&1 && grep -q "requires go >= 1.99 (running go .*; GOTOOLCHAIN=local)" $G/newgo && [ "$(connects)" = "$c" ]'

# --- C-G2: DNS, the proxy env, forwarders and the log ---
check "C-G2 with the proxy env removed, getent hosts and curl https://example.com each fail in under 1 s" '
  task ga "unset HTTPS_PROXY https_proxy; for c in \"getent hosts example.com\" \"curl -sS https://example.com\"; do t0=\$(date +%s%N); \$c && exit 1; ms=\$(( (\$(date +%s%N)-t0)/1000000 )); echo \"\$c: \$ms ms\"; [ \$ms -lt 1000 ] || exit 1; done"'
check "C-G2 podman refuses --dns=none with --network=none, so taskenv leaves it out" '! podman run --rm --network=none --dns=none $IMG true > $G/dns 2>&1 && grep -q "conflicting options: dns and the network mode: none" $G/dns'
check "C-G2 resolv.conf (the image's, left in place under --network=none) names only 127.0.0.1, with timeout:1 attempts:1" '
  task ga "cat /etc/resolv.conf" > $G/resolv && [ "$(grep -c . $G/resolv)" = 2 ] && grep -qx "nameserver 127.0.0.1" $G/resolv && grep -qx "options timeout:1 attempts:1" $G/resolv'
check "C-G2 HTTPS_PROXY, https_proxy, NO_PROXY and no_proxy are set; HTTP_PROXY and ALL_PROXY are not" '
  grep -qx HTTPS_PROXY=http://127.0.0.1:8080 $G/env-ga && grep -qx https_proxy=http://127.0.0.1:8080 $G/env-ga &&
  grep -qx NO_PROXY=127.0.0.1,localhost,::1 $G/env-ga && grep -qx no_proxy=127.0.0.1,localhost,::1 $G/env-ga && ! grep -qi "^\(http_proxy\|all_proxy\)=" $G/env-ga'
check "  ... the egress forwarder relays a CONNECT tunnel, and the LLM forwarder a POST" '
  task ga "curl -sS -p -x http://127.0.0.1:8080 http://ok.example/ && curl -sS -X POST -d {} http://127.0.0.1:8081/v1/messages" | tr "\n" " " | grep -qx "ok {\"ok\":true} "'
rm -f $WS/ga/ready
( for i in $(seq 300); do [ -e $WS/ga/ready ] && break; sleep 0.1; done; sleep 3; broker_up keys "$(cat $G/last)" ) </dev/null >/dev/null 2>&1 &
up3=$!
check "C-G2 the keys broker down for the task's first 3 s: the request succeeds after the reconnect" '
  down keys && task ga "touch ready; curl -sS -o /tmp/b -w \"%{http_code} %{time_total}\n\" -X POST -d {} http://127.0.0.1:8081/v1/messages; cat /tmp/b" > $G/r3 &&
  head -1 $G/r3 | awk "{exit !(\$1 == 200 && \$2 >= 2.5)}" && grep -qx "{\"ok\":true}" $G/r3'
wait $up3
check "C-G2 agentbox why --errno EOPNOTSUPP prints the seccomp guidance" 'task ga "agentbox why --errno EOPNOTSUPP" | grep -q "seccomp profile refuses btrfs ioctls"'
check "C-G2 70 proxy denials: the log keeps 64, agentbox why shows the newest 10 with host and remedy" '
  task ga "for i in \$(seq 70); do curl -s -p -x http://127.0.0.1:8080 http://deny\$i.example/ >/dev/null; done; wc -l < ~/.agentbox/denials.jsonl; agentbox why" > $G/ring &&
  [ "$(head -1 $G/ring)" = 64 ] && [ "$(grep -c "^EGRESS_NOT_ALLOWLISTED next=ask by=proxy id=dn_" $G/ring)" = 10 ] &&
  grep -q "host=deny70.example:80$" $G/ring && grep -q "remedy: op net.allow_domain{host: deny70.example, port: 80} (cli)" $G/ring'
TR=$(cat $G/last)
check "  ... its result carries the newest 20, and its witness ends with the sha256 of the result agentboxd got (#223)" '
  journalctl -b -u agentboxd -o cat | grep "task $TR result: " > $G/res-ring; cat $G/res-ring
  h=$(sed -n "s/.* 20 denials, sha256 \([0-9a-f]\{64\}\), .*/\1/p" $G/res-ring) && [ -n "$h" ] && wrec $TR | grep -qF "\"end\":\"$h\""'
check "  ... and the next task starts with no log" 'task ga "[ ! -e ~/.agentbox/denials.jsonl ] && agentbox why" | grep -q "^No denials logged"'

# --- C-G2: the fixed lines ---
check "C-G2 task.start gives ga and gb the same CLAUDE.md and AGENTS.md" 'cmp $X/ga/CLAUDE.md $X/gb/CLAUDE.md && cmp $X/ga/AGENTS.md $X/gb/AGENTS.md'
check "  ... each carries exactly the eight fixed lines of §8, verbatim" '[ "$(wc -l < /tmp/gate-fixed)" = 8 ] && tail -8 $X/ga/AGENTS.md | cmp - /tmp/gate-fixed && tail -8 $X/ga/CLAUDE.md | cmp - /tmp/gate-fixed &&
  [ "$(grep -cxFf /tmp/gate-fixed $X/ga/AGENTS.md)" = 8 ] && [ "$(grep -cxFf /tmp/gate-fixed $X/ga/CLAUDE.md)" = 8 ]'
check "  ... and taskrun puts them where Claude and Codex read them" '
  task ga "cat ~/.claude/CLAUDE.md; echo ===; cat ~/.codex/AGENTS.md" > $G/home-md &&
  sed "/^===\$/,\$d" $G/home-md | cmp - $X/ga/CLAUDE.md && sed "1,/^===\$/d" $G/home-md | cmp - $X/ga/AGENTS.md'

# --- C-G2: the witness, from task.start to task.stop; brokers down for good ---
rm -f $WS/ga/wready $WS/ga/wgo $G/last
{ down keys proxy; task ga "curl -s -o /tmp/b -D /tmp/h -w \"%{http_code} %{time_total}\n\" -X POST -d {} http://127.0.0.1:8081/v1/messages; cat /tmp/h /tmp/b; echo;
  t0=\$(date +%s%N); curl -sS -p -x http://127.0.0.1:8080 http://ok.example/; echo egress_ms=\$(( (\$(date +%s%N)-t0)/1000000 )); agentbox why
  printf \"junk\n\" > /run/agentbox/witness/witness && ! timeout 2 cat /run/agentbox/witness/witness && ! touch /run/agentbox/witness/new && [ ! -e /run/agentbox/witness/new ] && echo witness-write-only
  yes \"dn_00000000000000000000000000 - BROKER_UNAVAILABLE forwarder\" | head -c 1048576 > /run/agentbox/witness/witness && echo witness-1mib
  touch /workspace/wready; while [ ! -e /workspace/wgo ]; do sleep 0.1; done"; } > $G/r10 2>&1 &
wt=$!
for i in $(seq 600); do [ -e $WS/ga/wready ] && [ -s $G/last ] && break; sleep 0.1; done
T2=$(cat $G/last)
check "C-G2 witness: task.start made the task's dir root:ag-ga 0750 and its FIFO root:ag-ga 0620" '[ "$(stat -c "%U:%G %a" $W/$T2)" = "root:ag-ga 750" ] && [ "$(stat -c "%U:%G %a %F" $W/$T2/witness)" = "root:ag-ga 620 fifo" ]'
check "  ... uid agentbox can't open it" '! runuser -u agentbox -- sh -c ": > $W/$T2/witness" && ! runuser -u agentbox -- timeout 2 cat $W/$T2/witness'
touch $WS/ga/wgo; wait $wt
check "  ... under rootless podman with keep-id the task writes it through the read-only mount, can't read it and can't create files there" 'grep -qx witness-write-only $G/r10'
check "  ... a task writes 1 MiB of lines" 'grep -qx witness-1mib $G/r10'
check "C-G2 brokers down for good: 503 BROKER_UNAVAILABLE within 6 s on the LLM and egress forwarders, and agentbox why prints both" '
  head -1 $G/r10 | awk "{exit !(\$1 == 503 && \$2 <= 6)}" && grep -qi "^agentbox-denial: v1 code=BROKER_UNAVAILABLE next=retry id=dn_" $G/r10 &&
  grep -q "\"message\":\"agentbox BROKER_UNAVAILABLE:" $G/r10 && grep -q "CONNECT tunnel failed, response 503" $G/r10 &&
  [ "$(sed -n "s/^egress_ms=//p" $G/r10)" -le 6000 ] && grep -q "^BROKER_UNAVAILABLE{llm} next=retry by=forwarder id=dn_" $G/r10 &&
  grep -q "^BROKER_UNAVAILABLE{egress} next=retry by=forwarder id=dn_" $G/r10'
check "  ... task.stop: rootd kept at most 64 KiB, counted the rest, kept the forwarders' lines, removed the dir, and sent WITNESS" '
  wrec $T2 > $G/w2 && python3 -c "
import json,sys; w=json.loads(open(sys.argv[1]).read())[\"body\"]; kept=sum(len(l)+1 for l in w[\"lines\"])
fw=[l for l in w[\"lines\"] if l.endswith(\" - BROKER_UNAVAILABLE forwarder\") and not l.startswith(\"dn_0000\")]
print(kept, w[\"dropped\"], w[\"bad\"], len(fw), w[\"incomplete\"]); sys.exit(not (kept <= 65536 and w[\"dropped\"] > 0 and len(fw) >= 2 and not w[\"incomplete\"]))" $G/w2 && [ ! -e $W/$T2 ]'
# #222: END lines after the first, and bytes with no newline, count against the 64 KiB like any line
EA="END $(printf %064d 0 | tr 0 a)"
task ga "yes '$EA' | head -c 1048576 > /run/agentbox/witness/witness" > /dev/null || :; T5=$(cat $G/last)
task ga "yes x | tr -d '\n' | head -c 1048576 > /run/agentbox/witness/witness" > /dev/null || :; T6=$(cat $G/last)
check "  ... #222: 1 MiB of END lines, and 1 MiB with no newline, each raise dropped; the END line is kept" '[ -n "$T5" ] && [ -n "$T6" ] &&
  for t in $T5 $T6; do wrec $t > $G/w5 && python3 -c "
import json,sys; w=json.loads(open(sys.argv[1]).read())[\"body\"]; print(w[\"dropped\"], w[\"bad\"], w[\"end\"][:8])
sys.exit(not (w[\"dropped\"] > 0 and (sys.argv[2] != \"end\" or w[\"end\"] == \"a\" * 64)))" $G/w5 $([ $t = $T5 ] && echo end || echo raw) || exit 1; done'
rm -f $WS/ga/wready $WS/ga/wgo $G/last
task ga "touch /workspace/wready; while [ ! -e /workspace/wgo ]; do sleep 0.1; done
  echo dn_00000000000000000000000000 - BROKER_UNAVAILABLE forwarder > /run/agentbox/witness/witness" > $G/r4 2>&1 &
wt=$!
for i in $(seq 600); do [ -e $WS/ga/wready ] && [ -s $G/last ] && break; sleep 0.1; done
T4=$(cat $G/last)
# rootd alone: a plain restart also restarts the agent's user manager (its Requires=), which ends the task. Until #222
# that check passed only because rootd died in the middle of stopping it.
systemctl restart --job-mode=ignore-dependencies agentbox-rootd.service; sleep 1; touch $WS/ga/wgo; wait $wt
check "C-G2 a rootd restart mid-task marks that witness incomplete; the task outlives it and its line after it is kept" '
  wrec $T4 > $G/w4 && grep -q "\"incomplete\":true" $G/w4 && grep -qF "dn_00000000000000000000000000 - BROKER_UNAVAILABLE forwarder" $G/w4 &&
  journalctl -b -u agentbox-rootd.service -o cat | grep -q "witness $T4: reopened after a restart, marked incomplete"'
check "  ... and raises no alert: no GATE_MISMATCH record and no ALERT for that task" '! cat $A/seg-*.jsonl | grep "\"task\":\"$T4\"" | grep -q "\"type\":\"\(GATE_MISMATCH\|ALERT\)\""'

# --- cleanup: the stand-ins go; the box's own state stays ---
for v in proxy keys; do kill "$(cat $G/svc-$v.pid)" 2>/dev/null; rm -f /run/agentbox-rootd/svc-$v.sock; done
systemctl start agentbox-proxy-svc.socket agentbox-proxy.service agentbox-keys-svc.socket agentbox-keys.service
rm -f $RS/agentboxd.service.d/50-taskenv.conf $RS/agentbox-rootd.service.d/50-taskenv.conf; systemctl daemon-reload
systemctl restart agentbox-rootd.service agentboxd.service
podman rmi -f $IMG-env $IMG >/dev/null 2>&1
echo "fails=$fails"
EOF
  ;;
*) die "unknown step $s (install or checks)" ;;
esac; done
! grep -q '^[0-9:]* FAIL' "$OUT"

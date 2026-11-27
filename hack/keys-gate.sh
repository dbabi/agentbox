#!/bin/sh
# Milestone 5 gate for the keys broker (issues #18, #108, #115; PLAN.md row 7-8; PROPOSALS-v5.3 C-G4's keys half, A-G13
# for agentbox-keys; ARCHITECTURE.md §4.3, §6.3) on the local arm64 QEMU VM, none mode (AGENTBOX_KEYS_MODE=tpm2: tpm2).
#   hack/keys-gate.sh [install|checks|apply ...]   default: install checks
# install  hack/gate.sh none (or tpm2): the unattended install and the release pipeline.
# checks   installs this checkout's release on the box (make release, install.sh, a reboot), so agentbox-keys, its
#          socket unit, the credential store and rootd arrive the real way. A stand-in for the vendors on the host
#          (hack/keys-gate/upstream: api.anthropic.com and api.openai.com over TLS from a test CA, on 127.0.0.1:7900+ID,
#          which vm.sh forwards to the guest as 10.0.2.2 for this boot, AGENTBOX_VM_FWD) checks the injected key on
#          every request and logs a fingerprint of it, never the key. On the box: gate-dns answers the vendor names
#          with 192.88.96.10 and .11, which rootd resolves, checks and puts in keys_dst4 like any public answer; a test
#          nat table sends that address and port to 10.0.2.2, and one allow_private4 tuple lets agentbox-keys reach it
#          (§6.1), so keys dials only rootd's answer and the gate counts its dials; keys trusts the test CA through
#          SSL_CERT_FILE. Tasks are `agentbox task new`: sh scripts (AGENTBOX_TEST_CLI=sh) with curl and python3, and
#          the real pinned Claude Code and Codex CLIs (hack/cli-gate.sh's pins) in /usr/bin, which the stub task image
#          mounts. Each gate item:
#          #108  secret.set stores ciphertext only, root 0600, under control/credstore.encrypted/keys, and restarts
#                agentbox-keys; PID 1 decrypts it into that unit's /run/credentials, which agentbox-keys alone reads
#                (not agentbox-proxy, agentbox-git, agentbox, agentbox-llm, the agent uid or nobody); the key never
#                reaches audit or journald; it loads again after a reboot (apply: and after an os.apply clone, trial
#                boot and commit, and a prune of an old generation).
#          #18   a POST /v1/messages from a task succeeds with the injected key, and the keys nft drop counters stay
#                at 0 for the whole run; no credential in a task (env, HOME, /tmp, the workspace, its socket dirs, no
#                /run/credentials); URL images, URL PDFs, mcp_servers and an http image_url each get 403 in the
#                vendor envelope and reach no vendor; Claude Code and Codex tasks run with 0 rejections and their
#                requests reach the vendor with the key (their bodies go to the replay corpus, TestReplay), and with
#                HTTPS_PROXY and NO_PROXY set they send the proxy no request (C-G3: none for 127.0.0.1); a beta
#                that keys refuses (AGENTBOX_TEST_KEYS_DENY_BETA) gets capability_rejected, Claude Code retries
#                without it and the task completes; the key echoed in a 400, an SSE event, split across chunks,
#                base64, percent-encoded or in a header reaches no task (KEYS_UPSTREAM{reflect} or a cut stream, and
#                an ALERT); a normal 1 MiB stream passes byte for byte; a key rotated mid-task (secret.set, the unit
#                restarts, the old key revoked upstream) fails the request in flight with a typed error and the
#                task's next request works with the new key; the local LLM (a stand-in agentbox-llm@task) never
#                answers a clean task from an instance that served a tainted one, and its dropped fields are named.
#          C-G4  an upstream 401 is 502 KEYS_UPSTREAM{auth} with no upstream byte; an upstream Agentbox-Denial header
#                and agentbox member are stripped; an agent at its own day share gets 429 KEYS_BUDGET{agent} with
#                x-should-retry: false, while another agent's reply doesn't change (the first idle, at its share, or
#                holding reservations up to its share); Claude Code and Codex each stop within their own retries and
#                the task result carries the denial.
#          #115  on keys.sock from a task: a 33 MiB body, a zip bomb, a slow head and a 17th connection each get
#                CAP_REACHED with its what.
#          #291  a model request with the task's canary in its body, raw or base64, reaches the vendor and raises one
#                alert and taint for the task; a clean one, with the canary in its auth header as every task sends it,
#                raises none.
#          A-G13 agentbox-keys runs one more seccomp filter than its unit gives.
# apply    #108's os.apply half: three applies that each re-install one package (clone, trial boot, health commit)
#          and load the key, and the third commit's prune of the oldest generation, after which a restarted
#          agentbox-keys still loads the key (run after checks, on the same box).
# Stand-ins until their areas land: the vendors (the real POST /v1/messages needs a real key: needs_human), the local
# LLM (llama-server is not packaged yet).
# PASS/FAIL lines go to .vm/keys-gate.txt, command output to .vm/keys-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x"; fake keys).
# AGENTBOX_KEYS_MODE=tpm2 installs in tpm2 mode, where rootd encrypts the keys with the TPM: checks then also loads
# them with the host key moved away.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/keys-gate.txt" LOG="$VM/keys-gate.log"
UP_PORT=$((7900 + ${AGENTBOX_VM_ID:-0}))
MODE=${AGENTBOX_KEYS_MODE:-none}
case $MODE in none|tpm2) ;; *) echo "AGENTBOX_KEYS_MODE is none or tpm2" >&2; exit 2 ;; esac
CC=anthropic-ai-claude-code-linux-arm64-2.1.330.tgz CX=openai-codex-0.171.0-linux-arm64.tgz
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
# up: a fresh boot with the upstream's port forwarded, whatever ran before
up() { ! running || vm_off; { AGENTBOX_VM_FWD=$UP_PORT hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"; settle; }
# reboot_vm: a reboot of the running VM (the forward stays: QEMU runs on)
reboot_vm() { b=$(bootid); echo 'systemctl reboot' | root >/dev/null 2>&1 || :; wait_boot "$b" 900 || die "no SSH after the reboot"; settle; }
guest() { # stdin: the check block; args: more NAME=value lines for it
  { cat "$K/env"; printf '%s\n' "$@"; cat; } | root >"$VM/guest.out" 2>>"$LOG" || :
  while IFS= read -r l; do case $l in PASS*|FAIL*) log "$l" ;; *) echo "$l" >>"$LOG" ;; esac; done <"$VM/guest.out"
  grep -q '^fails=' "$VM/guest.out" || log "FAIL the check block on the VM did not finish (see $LOG)"
}
pinned() { [ -f "$1" ] && [ "$(shasum -a 256 < "$1" | cut -d' ' -f1)" = "$(awk -v f="${1##*/}" '$2 == f {print $1}' hack/SHA256SUMS)" ]; }
pkg() { # pkg FILE NPM-SPEC, as hack/cli-gate.sh fetches them
  pinned "$VM/cli/$1" && return 0
  mkdir -p "$VM/cli" && (cd "$VM/cli" && npm pack --silent "$2") >>"$LOG" 2>&1 || die "npm pack $2 failed"
  pinned "$VM/cli/$1" || die "$1 does not match hack/SHA256SUMS"
}
K="$VM/keysgate" # the stand-in's files; .vm/keys holds gate.sh's test signing keys
key() { printf '%s%s' "$1" "$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"; }
# start_upstream: the vendors' stand-in on the host, recording every body for the replay corpus
start_upstream() {
  mkdir -p "$K"
  [ -s "$K/env" ] || printf 'TOKEN=%s\nUP_PORT=%s\nKEY1=%s\nKEY2=%s\nOKEY=%s\nMODE=%s\n' "$(key '')" "$UP_PORT" "$(key sk-ant-api03-GATE)" \
    "$(key sk-ant-api03-GATE)" "$(key sk-proj-GATE)" "$MODE" > "$K/env"
  . "$K/env"
  go build -o "$K/upstream" ./hack/keys-gate/upstream || die "build the upstream"
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$K/llama" ./hack/keys-gate/upstream || die "build the local-LLM stand-in"
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$K/gate-dns" ./hack/gate-dns || die "build gate-dns"
  "$K/upstream" -listen "127.0.0.1:$UP_PORT" -token "$TOKEN" -out "$K" -keys "anthropic=$KEY1,openai=$OKEY" -record "$K/requests.jsonl" >>"$LOG" 2>&1 &
  UPID=$!
  trap 'kill $UPID 2>/dev/null' EXIT
  i=0; until [ -s "$K/ca.pem" ]; do i=$((i+1)); [ $i -lt 50 ] || die "the upstream did not start"; sleep 0.2; done
}
release() { # this checkout's release, by its own install.sh, then a reboot so the units start in order
  V=0.0.2-keys$(date +%s) R=$(mktemp -d "$VM/rel.XXXXXX")
  make -s release VERSION="$V" MINISIGN_KEY="$VM/keys/minisign.key" DIST="$R" >/dev/null || die "make release"
  hack/vm.sh ssh 'rm -rf /tmp/rel && mkdir /tmp/rel && tar -xz -C /tmp/rel' < "$R/agentbox-$V.tgz"
  echo 'sh /tmp/rel/install.sh --from-firstboot' | root >>"$LOG" 2>&1 || die "install.sh $V failed; see $LOG"
  rm -rf "$R"
  reboot_vm
  log "PASS release $V installed by its own install.sh, and the box rebooted into it"
}

for s; do case $s in
install)
  hack/gate.sh "$MODE" >>"$LOG" 2>&1 || die "hack/gate.sh $MODE failed; see $VM/gate-$MODE.txt"
  log "PASS install: hack/gate.sh $MODE (install, release pipeline, firstboot, no failed units)" ;;
checks)
  pkg "$CC" @anthropic-ai/claude-code-linux-arm64@2.1.330
  pkg "$CX" @openai/codex@0.171.0-linux-arm64
  rm -f "$K/env" "$K/requests.jsonl"
  start_upstream
  up
  release
  tar -C "$K" -cf - ca.pem llama gate-dns | hack/vm.sh ssh 'rm -rf /tmp/kg && mkdir /tmp/kg && tar -C /tmp/kg -xf -'
  hack/vm.sh ssh 'cat > /tmp/kg/claude.tgz' < "$VM/cli/$CC" && hack/vm.sh ssh 'cat > /tmp/kg/codex.tgz' < "$VM/cli/$CX" || die "copying the CLIs"
  guest <<'EOF'
fails=0
cd / # runuser keeps the working dir, and the agent can't enter the admin's home
# a failed check's output goes to the host's log too
check() { if (eval "$2") >/var/tmp/kg-out 2>&1; then echo "PASS $1"; else echo "FAIL $1"; sed 's/^/  | /' /var/tmp/kg-out | tail -40; fails=$((fails+1)); fi
  cat /var/tmp/kg-out >> /var/tmp/kg-check.log; }
B=/var/lib/agentbox/current/bin/agentbox
A=/var/lib/agentbox/audit
CS=/var/lib/agentbox/control/credstore.encrypted
CRED=/run/credentials/agentbox-keys.service
WS=/var/lib/agentbox/data/workspaces
RS=/run/systemd/system
DB=/var/lib/agentbox/rootd.db
G=/run/keys-gate
mkdir -p $G && chmod 0755 $G && cp /tmp/kg/ca.pem /tmp/kg/llama /tmp/kg/gate-dns $G/ && chmod 0644 $G/ca.pem && chmod 0755 $G/llama $G/gate-dns
fp() { printf %s "$1" | sha256sum | cut -c1-8; }
F1=$(fp "$KEY1") F2=$(fp "$KEY2") FO=$(fp "$OKEY")
up() { curl -sS --cacert $G/ca.pem --resolve api.anthropic.com:$UP_PORT:10.0.2.2 "$@"; } # the stand-in, as root
UP=https://api.anthropic.com:$UP_PORT
uplog() { up "$UP/_ctl/$TOKEN/log"; }
upkeys() { printf '%s\n' "$@" | up -X POST --data-binary @- "$UP/_ctl/$TOKEN/keys?vendor=anthropic" >/dev/null; }
kdrops() { nft list chain inet agentbox output | grep '"agentbox-keys"' | sed -n 's/.* counter packets \([0-9]*\) .* drop$/\1/p' | awk '{n += $1} END {print n + 0}'; }
dnat() { nft list table ip keysgate 2>/dev/null | sed -n 's/.*counter packets \([0-9]*\) .*dnat.*/\1/p' | awk '{n += $1} END {print n + 0}'; }
deny() { journalctl -b -u agentbox-keys -o cat | grep -c "DENY by=keys task=$1" || :; }
ended() { $B task list | python3 -c 'import json,sys; sys.exit(not [t for t in json.load(sys.stdin)["tasks"] if t["task"]==sys.argv[1] and t.get("end_reason")])' "$1"; }
field() { $B task list | python3 -c 'import json,sys; t=[x for x in json.load(sys.stdin)["tasks"] if x["task"]==sys.argv[1]]; print(t[0].get(sys.argv[2],"") if t else "")' "$1" "$2"; }
# task AGENT SCRIPT: one sh task through task.start; prints what the script printed and returns its exit code; the id
# goes to $G/last
task() { o=$WS/$1/.gate-out; rm -f $o $WS/$1/.gate-rc
  printf '(\n%s\n) </dev/null > /workspace/.gate-out 2>&1; echo $? > /workspace/.gate-rc\n' "$2" |
    $B task new --agent $1 --cli sh --deadline 15m > $G/new; r=$?
  sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' $G/new > $G/last
  [ $r = 0 ] && [ -s $G/last ] || { cat $G/new; return 99; }
  i=0; while [ ! -e $WS/$1/.gate-rc ]; do i=$((i+1)); [ $i -lt 6000 ] || { echo "task $(cat $G/last): no result"; return 98; }; sleep 0.1; done
  i=0; until ended "$(cat $G/last)"; do i=$((i+1)); [ $i -lt 300 ] || break; sleep 0.1; done
  cat $o; return "$(cat $WS/$1/.gate-rc)"; }
# cli AGENT CLI < prompt: a real CLI task, to its end; the id goes to $G/last
cli() { $B task new --agent $1 --cli $2 --deadline 5m > $G/new || { cat $G/new; return 1; }
  t=$(sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' $G/new); echo $t > $G/last
  i=0; while [ -z "$(field $t end_reason)" ]; do i=$((i+1)); [ $i -lt 1500 ] || return 1; sleep 0.2; done; }
# m BODY [HEADER...]: the curl a task runs for one Anthropic request through the in-task LLM forwarder
M='curl -s -o /tmp/b -D /tmp/h -w "%{http_code}\n" -H "x-api-key: agentbox-placeholder" -H "anthropic-version: 2023-06-01" -H "content-type: application/json"'
msg() { printf '{"model":"claude-haiku-5-5","max_tokens":64,%s"messages":[{"role":"user","content":%s}]}' "$2" "$1"; }
# body NAME JSON: a request body both agents' tasks read as /workspace/NAME.json
body() { for a in ka kb; do printf '%s' "$2" > $WS/$a/$1.json && chown ag-$a:ag-$a $WS/$a/$1.json; done; }
# ask NAME [PATH]: the task's curl of body NAME through the LLM forwarder, then the reply head and body
ask() { echo "$M -d @/workspace/$1.json \"http://127.0.0.1:8081/${2:-anthropic/v1/messages}\"; cat /tmp/h /tmp/b"; }

# --- setup: the CLIs, the vendors' DNS, NAT and CA, the agents ---
mkdir -p /tmp/cx && tar -xzf /tmp/kg/claude.tgz -C /tmp/cx package/claude && install -m 0755 /tmp/cx/package/claude /usr/bin/claude &&
  tar -xzf /tmp/kg/codex.tgz -C /tmp/cx && for b in codex codex-code-mode-host; do install -m 0755 /tmp/cx/package/vendor/aarch64-unknown-linux-musl/bin/$b /usr/bin/$b; done
rm -rf /tmp/cx
check "the pinned Claude Code and Codex CLIs in /usr/bin" 'claude --version | grep -q "^2.1.330 " && codex --version | grep -qx "codex-cli 0.171.0"'
check "agentbox-keys runs as agentbox-keys from its socket unit, enabled, Type=notify, and loads exactly the two vendor credentials" '
  systemctl is-active -q agentbox-keys.service agentbox-keys-svc.socket && systemctl is-enabled -q agentbox-keys.service agentbox-keys-svc.socket &&
  [ "$(stat -c %U /proc/$(systemctl show -P MainPID agentbox-keys.service))" = agentbox-keys ] && [ "$(systemctl show -P Type agentbox-keys.service)" = notify ] &&
  [ "$(stat -c "%U:%G %a" /run/agentbox-rootd/svc-keys.sock)" = "agentbox-keys:root 600" ] &&
  [ "$(systemctl cat agentbox-keys.service | grep -c "^LoadCredentialEncrypted=")" = 2 ] && systemd-analyze verify agentbox-keys.service agentbox-keys-svc.socket'
check "A-G13 agentbox-keys runs one more seccomp filter than its unit gives (logged at start, in /proc)" '
  pid=$(systemctl show -P MainPID agentbox-keys.service) && l=$(journalctl -b -u agentbox-keys.service -o cat | grep "service filter installed: Seccomp_filters" | tail -1) && echo "$l" &&
  b=$(echo "$l" | sed -n "s/.*Seccomp_filters \([0-9]*\) -> \([0-9]*\).*/\1/p") && a=$(echo "$l" | sed -n "s/.*-> \([0-9]*\).*/\1/p") &&
  [ "$a" = $((b + 1)) ] && grep -qx "Seccomp_filters:	$a" /proc/$pid/status'
check "#108 install.sh made the host key (systemd-creds setup), and rootd gave each credential a placeholder" '
  [ "$(stat -c "%U %a" /var/lib/systemd/credential.secret)" = "root 400" ] && [ "$(stat -c "%U:%G %a" $CS $CS/keys)" = "root:root 700
root:root 700" ] && [ "$(stat -c "%U %a" $CS/keys/anthropic-api-key $CS/keys/openai-api-key $CS/git/github-token)" = "root 600
root 600
root 600" ]'
# on a box this gate has not set a key on, keys starts with the placeholders
if [ ! -e /var/tmp/kg-keys-set ]; then
  check "  ... with no key set, keys says so at start" 'journalctl -b -u agentbox-keys -o cat | grep -q "anthropic key not set (agentbox secret set --name anthropic-api-key)"'
fi
touch /var/tmp/kg-keys-set
# the vendors' names answer a public-looking address that a nat rule sends to the host's stand-in (see the header)
systemd-run -q --unit=kg-dns $G/gate-dns -listen 127.0.0.153:53 -upstream 10.0.2.3:53 -a api.anthropic.com=192.88.96.10 -a api.openai.com=192.88.96.11
mkdir -p /run/systemd/resolved.conf.d && printf '[Resolve]\nDNS=127.0.0.153\nDomains=~.\n' > /run/systemd/resolved.conf.d/90-keys-gate.conf
systemctl restart systemd-resolved.service; sleep 2
nft -f - <<NFT
table ip keysgate {
  chain out { type nat hook output priority -100; policy accept;
    ip daddr 192.88.96.10 tcp dport 443 counter dnat to 10.0.2.2:$UP_PORT
    ip daddr 192.88.96.11 tcp dport 443 counter dnat to 10.0.2.2:$UP_PORT
  }
}
NFT
KU=$(id -u agentbox-keys)
python3 -c "import sqlite3; c=sqlite3.connect('$DB'); c.execute(\"insert or ignore into set_elements values ('allow_private4', '$KU . 10.0.2.2 . $UP_PORT', NULL)\"); c.commit()"
mkdir -p $RS/agentbox-keys.service.d $RS/agentboxd.service.d
printf '[Service]\nEnvironment=SSL_CERT_FILE=%s/ca.pem\n' $G > $RS/agentbox-keys.service.d/50-gate.conf
printf '[Service]\nEnvironment=AGENTBOX_TEST_CLI=sh\n' > $RS/agentboxd.service.d/50-keys-gate.conf
systemctl daemon-reload
check "the vendors' names resolve through rootd's resolver only to the gate's addresses, and keys reaches the stand-in through its allow_private4 tuple" '
  resolvectl query -4 api.anthropic.com | grep -q 192.88.96.10 && $B egress refill >/dev/null && nft list set inet agentbox allow_private4 | grep -q "10.0.2.2 . $UP_PORT" &&
  for e in api.anthropic.com:443 api.openai.com:443; do $B egress allow --svc keys --entry $e >/dev/null || $B egress list | grep -q "$e" || exit 1; done &&
  systemctl restart agentboxd.service agentbox-keys.service && systemctl is-active -q agentboxd agentbox-keys'
D0=$(kdrops)
P0=$(systemctl show -P MainPID agentbox-keys.service)
check "#108 secret set (value on stdin) for both vendors; each restarts agentbox-keys" '
  printf "%s\n" "$KEY1" | $B secret set --name anthropic-api-key > $G/ss && cat $G/ss && grep -q "\"restarted\":true" $G/ss &&
  printf "%s\n" "$OKEY" | $B secret set --name openai-api-key >/dev/null && i=0; until systemctl is-active -q agentbox-keys; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done;
  [ "$(systemctl show -P MainPID agentbox-keys.service)" != "$P0" ] && journalctl -b -u agentbox-keys -o cat | grep -q "keys: anthropic key set"'
check "#108 the store holds ciphertext only, root 0600; no key byte in it" '
  [ "$(stat -c "%U %a" $CS/keys/anthropic-api-key)" = "root 600" ] && ! grep -rqF "$KEY1" $CS && ! grep -rqF "$OKEY" $CS && ! grep -rqF "${KEY1#sk-ant-api03-}" $CS'
check "#108 PID 1 decrypted it into agentbox-keys' own credentials dir: a read-only, non-swappable tmpfs that agentbox-keys reads" '
  findmnt -no FSTYPE,OPTIONS $CRED | grep -q "^tmpfs ro,.*noswap" && [ "$(stat -c "%U %a" $CRED/anthropic-api-key)" = "root 440" ] &&
  [ "$(runuser -u agentbox-keys -- cat $CRED/anthropic-api-key)" = "$KEY1" ]'
if [ "$MODE" = tpm2 ]; then # the LUKS root's crypttab line makes rootd encrypt with the TPM, which alone decrypts
  check "#108 tpm2 mode: agentbox-keys restarts and loads both keys with the host key moved away" '
    grep -q "^[^#[:space:]]" /etc/crypttab && mv /var/lib/systemd/credential.secret /var/tmp/kg-host-key &&
    { systemctl restart agentbox-keys; r=$?; mv /var/tmp/kg-host-key /var/lib/systemd/credential.secret; [ $r = 0 ]; } &&
    [ "$(runuser -u agentbox-keys -- cat $CRED/anthropic-api-key)" = "$KEY1" ] && [ "$(runuser -u agentbox-keys -- cat $CRED/openai-api-key)" = "$OKEY" ]'
fi
check "#108 no other uid reads the plaintext: agentbox-proxy, agentbox-git, agentbox, agentbox-audit, agentbox-llm, nobody" '
  for u in agentbox-proxy agentbox-git agentbox agentbox-audit agentbox-llm nobody; do runuser -u $u -- cat $CRED/anthropic-api-key 2>/dev/null && exit 1; runuser -u $u -- cat $CS/keys/anthropic-api-key 2>/dev/null && exit 1; done; true'
for a in ka kb; do
  check "agent add $a" '{ $B agent add --name $a || $B agent list | grep -q "\"name\":\"$a\""; } && u=$(id -u ag-$a) &&
    i=0; until systemctl is-active -q user@$u.service; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done'
  find $WS/$a -mindepth 1 -delete 2>/dev/null || :
done
check "#108 ... nor the agent uid" '! runuser -u ag-ka -- cat $CRED/anthropic-api-key 2>/dev/null'
uplog > /dev/null

# --- #18: a request, the key, the drop counters ---
n0=$(dnat)
body hello "$(msg '"hello"')"
check "#18 a task's POST /v1/messages?beta=true goes through keys to the vendor with the injected key: 200 and its reply" '
  task ka "$(ask hello "anthropic/v1/messages?beta=true")" > $G/r1; cat $G/r1
  head -1 $G/r1 | grep -qx 200 && grep -q "agentbox keys gate reply" $G/r1 && uplog > $G/l1 && cat $G/l1 &&
  grep -q "\"auth\":\"ok:$F1\"" $G/l1 && grep -q "\"path\":\"/v1/messages\"" $G/l1 && grep -q "\"query\":\"beta=true\"" $G/l1 && ! grep -q "\"authorization\":true" $G/l1'
T1=$(cat $G/last)
check "  ... rootd resolved it: 192.88.96.10 . 443 is in keys_dst4, and keys dialed exactly that address (the gate's nat counter)" '
  nft list set inet agentbox keys_dst4 | grep -q "192.88.96.10 . 443" && [ "$(dnat)" -gt "$n0" ]'
check "  ... an LLM record for the task was ACKed first, with the trace rootd registered and no request text" '
  cat $A/seg-*.jsonl | grep "\"type\":\"LLM\"" | grep "\"task\":\"$T1\"" | grep -q "\"trace\":\"trace_" && ! cat $A/seg-*.jsonl | grep "\"type\":\"LLM\"" | grep -q hello'
cat > $WS/ka/scan.sh <<'S'
tr '\0' '\n' < /proc/self/environ > /tmp/env0; tr '\0' '\n' < /proc/1/environ > /tmp/env1; cat /tmp/env0 /tmp/env1 > /tmp/env
# podman starts taskrun with the placeholder; taskrun hands the CLI the task's canary in its place (#105)
grep -x 'ANTHROPIC_API_KEY=agentbox-placeholder' /tmp/env1 >/dev/null || echo "no placeholder key"
grep -Ex 'ANTHROPIC_API_KEY=sk-ant-api03-[A-Za-z0-9_-]{93}AA' /tmp/env0 >/dev/null || echo "no canary in the key slot"
[ ! -e /run/credentials ] || echo "/run/credentials visible"
grep -rlF -D skip "$1" /tmp/env $HOME /tmp /workspace /run/agentbox 2>/dev/null | sed 's/^/hit /'
grep -rlF -D skip "$2" /tmp/env $HOME /tmp /workspace /run/agentbox 2>/dev/null | sed 's/^/hit /'
echo scanned
S
chown ag-ka:ag-ka $WS/ka/scan.sh
check "#18 no credential of any kind inside a task: the placeholder key, and the task's canary in its slot; no key in env, HOME, /tmp, the workspace or its socket dirs; no /run/credentials" '
  task ka "sh /workspace/scan.sh $(printf %s "$KEY1" | cut -c14-40) $(printf %s "$OKEY" | cut -c10-40)" > $G/scan; cat $G/scan; [ "$(cat $G/scan)" = scanned ]'

# --- #291: a model request that carries the task's canary goes through, and keys alerts once for the task ---
cat > $WS/ka/canary.sh <<'S'
case $1 in
raw) v="debug: ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" ;;
b64) v="debug: $(printf 'key=%s' "$ANTHROPIC_API_KEY" | base64 -w0)" ;;
*) v="nothing secret here" ;;
esac
printf '{"model":"claude-haiku-5-5","max_tokens":64,"messages":[{"role":"user","content":"%s"}]}' "$v" > /tmp/c.json
for i in 1 2; do # the second request carries it again: one alert for the task
  curl -s -o /tmp/b -w "%{http_code}\n" -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
    -d @/tmp/c.json http://127.0.0.1:8081/anthropic/v1/messages
done
S
chown ag-ka:ag-ka $WS/ka/canary.sh
calerts() { cat $A/seg-*.jsonl | grep "\"type\":\"ALERT\"" | grep "\"reason\":\"exfil_canary\"" | grep -c "\"task\":\"$1\"" || :; }
ctaint() { cat $A/seg-*.jsonl | grep "\"type\":\"TAINT\"" | grep "\"subject\":\"task:$1\"" | grep -c "\"source\":\"canary:llm\"" || :; }
for m in raw b64 clean; do
  n=1; [ $m != clean ] || n=0
  uplog > /dev/null
  check "#291 a model request with the canary in its body ($m) reaches the vendor; keys raises $n alert and taint for the task, never for its auth header" '
    task ka "sh /workspace/canary.sh '$m'" > $G/rc; T=$(cat $G/last); cat $G/rc; uplog > $G/lc
    i=0; until [ "$(calerts $T)" = '$n' ] || [ $i -ge 25 ]; do i=$((i+1)); sleep 0.2; done; sleep 1
    [ "$(cat $G/rc)" = "200
200" ] && [ "$(grep -c "\"path\":\"/v1/messages\"" $G/lc)" = 2 ] && [ "$(calerts $T)" = '$n' ] && [ "$(ctaint $T)" = '$n' ] &&
    [ "$(journalctl -b -u agentbox-keys -o cat | grep -c "ALERT keys: task $T: a model request carried the task.s canary")" = '$n' ]'
done
body urlimage "$(msg '[{"type":"image","source":{"type":"url","url":"https://example.com/a.png"}}]')"
body urlpdf "$(msg '[{"type":"document","source":{"type":"url","url":"https://example.com/a.pdf"}}]')"
body mcp "$(msg '"x"' '"mcp_servers":[{"type":"url","url":"https://mcp.example.com/sse","name":"m"}],')"
body imageurl '{"model":"gpt-5.4-mini","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://example.com/a.png"}}]}]}'
for c in "a URL image|urlimage|anthropic/v1/messages" "a URL PDF|urlpdf|anthropic/v1/messages" "mcp_servers|mcp|anthropic/v1/messages" \
         "an http image_url|imageurl|openai/v1/chat/completions"; do
  what=${c%%|*} rest=${c#*|} name=${rest%|*} ep=${rest##*|}
  check "#18 $what sent to keys gets 403 KEYS_REQUEST_REJECTED in the vendor envelope, and reaches no vendor" '
    task ka "$(ask $name $ep)" > $G/r403; cat $G/r403
    head -1 $G/r403 | grep -qx 403 && grep -qi "^agentbox-denial: v1 code=KEYS_REQUEST_REJECTED" $G/r403 && grep -q "\"type\":\"error\"" $G/r403 &&
    grep -q "\"message\":\"agentbox KEYS_REQUEST_REJECTED:" $G/r403 && grep -qi "^x-should-retry: false" $G/r403 && ! grep -q "example.com" $G/r403 &&
    [ -z "$(uplog)" ]'
done

# --- #18: a vendor web tool, refused until the policy names it; then it taints the task before the request leaves ---
body websearch "$(msg '"hi"' '"tools":[{"type":"web_search_20260209","name":"web_search","max_uses":1}],')"
check "#18 a vendor web tool with no policy for it gets 403 KEYS_REQUEST_REJECTED{server_tool}" '
  task ka "$(ask websearch)" > $G/rws; cat $G/rws; head -1 $G/rws | grep -qx 403 && grep -q "\"what\":\"server_tool\"" $G/rws && [ -z "$(uplog)" ]'
mkdir -p /var/lib/agentbox/control/keys && echo web_search > /var/lib/agentbox/control/keys/server-tools && chmod 0644 /var/lib/agentbox/control/keys/server-tools
check "#18 with the policy naming web_search, it goes through, and the task is tainted (keys:web_search) before it leaves" '
  task ka "$(ask websearch)" > $G/rws; cat $G/rws; T=$(cat $G/last); head -1 $G/rws | grep -qx 200 &&
  cat $A/seg-*.jsonl | grep "\"type\":\"TAINT\"" | grep "\"subject\":\"task:$T\"" | grep -q "\"source\":\"keys:web_search\"" && uplog | grep -q "\"path\":\"/v1/messages\""'
rm -f /var/lib/agentbox/control/keys/server-tools

# --- C-G4 and #18: what comes back ---
body s401 "$(msg '"GATE-MODE:status-401"')"
body agentbox "$(msg '"GATE-MODE:agentbox"')"
check "C-G4 an upstream 401 is 502 KEYS_UPSTREAM{auth}, with no upstream byte" '
  task ka "$(ask s401)" > $G/r401; cat $G/r401
  head -1 $G/r401 | grep -qx 502 && grep -qi "^agentbox-denial: v1 code=KEYS_UPSTREAM" $G/r401 && grep -q "\"what\":\"auth\"" $G/r401 && ! grep -q "upstream says" $G/r401'
check "C-G4 an upstream Agentbox-Denial header and agentbox member are stripped; the vendor's own 400 passes" '
  task ka "$(ask agentbox)" > $G/rab; cat $G/rab
  head -1 $G/rab | grep -qx 400 && ! grep -qi "^agentbox-denial" $G/rab && grep -q "prompt is too long" $G/rab && ! grep -q "\"agentbox\"" $G/rab'
for m in echo-400 echo-sse echo-split echo-b64 echo-url echo-header; do
  body $m "$(msg "\"GATE-MODE:$m\"" '"stream":true,')"
  check "#18 the vendor echoes the key ($m): no byte of it reaches the task; KEYS_UPSTREAM{reflect} or a cut stream, and an ALERT" '
    a0=$(cat $A/seg-*.jsonl | grep -c "\"reason\":\"reflect\"" || :)
    task ka "$(ask $m)" > $G/rr; cat $G/rr
    ! grep -qF "$(printf %s "$KEY1" | cut -c14-50)" $G/rr && ! grep -q "message_stop" $G/rr &&
    { grep -qi "^agentbox-denial: v1 code=KEYS_UPSTREAM" $G/rr && grep -q "\"what\":\"reflect\"" $G/rr || head -1 $G/rr | grep -qx 200; } &&
    sleep 1 && [ "$(cat $A/seg-*.jsonl | grep -c "\"reason\":\"reflect\"")" -gt "$a0" ]'
done
body big "$(msg '"GATE-MODE:big"' '"stream":true,')"
check "#18 a normal 1 MiB streamed reply passes byte for byte" '
  up -s -o $G/direct -H "x-api-key: $KEY1" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" --data-binary @$WS/ka/big.json $UP/v1/messages &&
  task ka "$M -d @/workspace/big.json http://127.0.0.1:8081/anthropic/v1/messages >/dev/null; sha256sum < /tmp/b; wc -c < /tmp/b" > $G/rbig; cat $G/rbig
  [ "$(head -1 $G/rbig)" = "$(sha256sum < $G/direct)" ] && [ "$(sed -n 2p $G/rbig)" -gt 1000000 ]'
uplog > /dev/null

# --- #115: the admission caps, on keys.sock itself ---
cat > $WS/ka/caps.py <<'PY'
import gzip, socket, sys, time
S = "/run/agentbox/llm/keys.sock"
def conn():
    c = socket.socket(socket.AF_UNIX); c.connect(S); return c
def status(c):
    c.settimeout(30); b = b""
    while b"\r\n\r\n" not in b:
        d = c.recv(65536)
        if not d: break
        b += d
    head = b.split(b"\r\n\r\n")[0].decode("latin1")
    return (head.split(" ")[1] if head else "none"), ("CAP_REACHED" if "code=CAP_REACHED" in head else "-")
def post(c, body, hdr=""):
    c.sendall(("POST /anthropic/v1/messages HTTP/1.1\r\nHost: k\r\nContent-Type: application/json\r\nContent-Length: %d\r\n%s\r\n" % (len(body), hdr)).encode())
    try: c.sendall(body)
    except OSError: pass
c = conn(); post(c, b"x" * (33 << 20)); print("body", *status(c)); c.close()
bomb = gzip.compress(b"\0" * (64 << 20))
c = conn(); post(c, bomb, "Content-Encoding: gzip\r\n"); print("bomb", *status(c)); c.close()
c = conn(); c.sendall(b"POST /anthropic/v1/messages HTTP/1.1\r\nHost: k\r\n"); t = time.time(); r = status(c); print("slowhead", *r, int(time.time() - t)); c.close()
time.sleep(0.5) # the refused ones are closed on both sides now, so only the 16 below count
held = []
for i in range(16):
    h = conn(); h.sendall(b"POST /anthropic/v1/messages HTTP/1.1\r\nHost: k\r\nContent-Length: 10\r\n\r\n"); held.append(h)
time.sleep(1)
c = conn(); post(c, b"{}"); print("conns", *status(c))
PY
chown ag-ka $WS/ka/caps.py
check "#115 on keys.sock: a 33 MiB body 413, a zip bomb 413, a slow head 408 (after 10 s), a 17th connection 429; each CAP_REACHED" '
  task ka "python3 /workspace/caps.py" > $G/caps; cat $G/caps
  grep -qx "body 413 CAP_REACHED" $G/caps && grep -qx "bomb 413 CAP_REACHED" $G/caps && grep -q "^slowhead 408 CAP_REACHED 1[01]$" $G/caps && grep -qx "conns 429 CAP_REACHED" $G/caps'
check "  ... keys logged each with its what: body_bytes, decoded_bytes, header_timeout, connections" '
  j=$(journalctl -b -u agentbox-keys -o cat | grep "code=CAP_REACHED"); for w in body_bytes decoded_bytes header_timeout connections; do echo "$j" | grep -q "what=$w" || exit 1; done'

# --- #18: the real CLIs, recorded for the replay corpus ---
echo "say hi" > $G/hi
uplog > /dev/null
check "#18 a Claude Code task (--cli claude) runs to completed with 0 rejections; its requests reach the vendor with the key, and raise no canary alert (#291)" '
  cli ka claude < $G/hi && T=$(cat $G/last) && [ "$(field $T end_reason)" = completed ] && [ "$(deny $T)" = 0 ] && uplog > $G/lcc && cat $G/lcc &&
  grep -q "\"path\":\"/v1/messages\"" $G/lcc && ! grep -v "\"auth\":\"ok:$F1\"" $G/lcc | grep -q . && [ "$(calerts $T)" = 0 ]'
grep -o '"beta":\[[^]]*\]' $G/lcc | head -1 > $G/ccbeta
TCC=$(cat $G/last)
check "#18 a Codex task (--cli codex) runs to completed with 0 rejections; its requests reach the vendor with the key, and raise no canary alert (#291)" '
  cli ka codex < $G/hi; T=$(cat $G/last); journalctl -b -u agentbox-keys -o cat | grep "task=$T"
  [ -n "$T" ] && [ "$(field $T end_reason)" = completed ] && [ "$(deny $T)" = 0 ] && uplog > $G/lcx && cat $G/lcx &&
  grep -q "\"path\":\"/v1/responses\"" $G/lcx && ! grep -v "\"auth\":\"ok:$FO\"" $G/lcx | grep -q . && [ "$(calerts $T)" = 0 ]'
TCX=$(cat $G/last)
# the proxy logs each tunnel, cache request line and refusal with its task; the register and revoke lines are rootd's
check "C-G3 with HTTPS_PROXY and NO_PROXY set, the Claude Code and Codex tasks sent the proxy no request, so none for 127.0.0.1" '
  [ -n "$TCC" ] && [ -n "$TCX" ] && [ "$TCC" != "$TCX" ] && { journalctl --sync 2>/dev/null || :; } &&
  j=$(journalctl -b -u agentbox-proxy.service -o cat | sed "s|^[0-9]*/[0-9]*/[0-9]* [0-9:]* ||") &&
  echo "$j" | grep -q "^task $TCC (agent ka) registered" && echo "$j" | grep -q "^task $TCX (agent ka) registered" &&
  ! echo "$j" | grep -E "^task ($TCC|$TCX) (CONNECT |[A-Z]+ \")|^DENY by=proxy task=($TCC|$TCX) "'
# the first beta Claude Code sent, other than claude-code-20250219: keys refuses it, and Claude Code must retry without it
DB1=$(tr -d '"[]' < $G/ccbeta | sed 's/^beta://' | tr ',' '\n' | grep -v '^claude-code-' | head -1)
echo "Claude Code's betas: $(cat $G/ccbeta); refusing $DB1"
printf '[Service]\nEnvironment=SSL_CERT_FILE=%s/ca.pem AGENTBOX_TEST_KEYS_DENY_BETA=%s\n' $G "$DB1" > $RS/agentbox-keys.service.d/50-gate.conf
systemctl daemon-reload && systemctl restart agentbox-keys.service
check "#18 a beta keys refuses ($DB1): capability_rejected, Claude Code retries without it, and the task completes" '
  [ -n "$DB1" ] && cli ka claude < $G/hi && T=$(cat $G/last) && [ "$(field $T end_reason)" = completed ] && [ "$(deny $T)" -ge 1 ] &&
  journalctl -b -u agentbox-keys -o cat | grep "DENY by=keys task=$T" | grep -q "what=beta_header" && uplog > $G/lbeta && cat $G/lbeta &&
  grep -q "\"path\":\"/v1/messages\"" $G/lbeta && ! grep -q "$DB1" $G/lbeta'
printf '[Service]\nEnvironment=SSL_CERT_FILE=%s/ca.pem\n' $G > $RS/agentbox-keys.service.d/50-gate.conf
systemctl daemon-reload && systemctl restart agentbox-keys.service

# --- C-G4: per-agent day shares ---
check "C-G4 budget.set: a 1 cent share for ka; kb gets the rest of a \$100 day" '
  printf "keys.day_cap_cents = 10000\nkeys.agent_day_share.ka = 1\n" | $B budget set >/dev/null && cat /var/lib/agentbox/control/day-shares.json'
body hi "$(msg '"hi"')"
check "C-G4 ka over its own share: 429 KEYS_BUDGET{agent}, x-should-retry: false, no vendor request" '
  task ka "$(ask hi)" > $G/rb; cat $G/rb
  head -1 $G/rb | grep -qx 429 && grep -qi "^agentbox-denial: v1 code=KEYS_BUDGET" $G/rb && grep -q "\"what\":\"agent\"" $G/rb && grep -qi "^x-should-retry: false" $G/rb && [ -z "$(uplog)" ]'
check "C-G4 kb's reply is the same, apart from ids, with ka idle or at its share" '
  task kb "$M -d @/workspace/hi.json http://127.0.0.1:8081/anthropic/v1/messages; cat /tmp/b" > $G/kb1 &&
  printf "keys.day_cap_cents = 10000\n" | $B budget set >/dev/null && task kb "$M -d @/workspace/hi.json http://127.0.0.1:8081/anthropic/v1/messages; cat /tmp/b" > $G/kb0 &&
  cat $G/kb0 $G/kb1; cmp $G/kb0 $G/kb1 && head -1 $G/kb1 | grep -qx 200'
# ka holding its largest reservations: a share that fits two of its 100000-token opus requests (200 cents each) on
# top of what it spent today, not a third; kb asks while two are in flight
S=$(python3 -c "import sqlite3, time; c = sqlite3.connect('file:/var/lib/agentbox/keys/spend.db?mode=ro', uri=True)
print(c.execute('SELECT COALESCE(SUM(COALESCE(spent, reserved)), 0) FROM spend WHERE day = ? AND agent = ?', (int(time.time() * 1000) // 86400000, 'ka')).fetchone()[0])")
printf "keys.day_cap_cents = 10000\nkeys.agent_day_share.ka = %s\n" $(( (S + 9999999) / 10000000 + 500 )) | $B budget set >/dev/null
body hold '{"model":"claude-opus-5-5","max_tokens":100000,"messages":[{"role":"user","content":"GATE-MODE:slow-40"}]}'
cat > $WS/ka/hold.sh <<'S'
for i in 1 2 3; do
  ( curl -s -o /tmp/b$i -D /tmp/h$i -w "%{http_code}\n" -H "x-api-key: agentbox-placeholder" -H "anthropic-version: 2023-06-01" \
      -H "content-type: application/json" -d @/workspace/hold.json http://127.0.0.1:8081/anthropic/v1/messages > /tmp/s$i
    cat /tmp/h$i /tmp/b$i >> /tmp/s$i; cp /tmp/s$i /workspace/.hold$i && mv /workspace/.hold$i /workspace/hold$i ) &
done
wait
S
chown ag-ka $WS/ka/hold.sh; rm -f $WS/ka/hold1 $WS/ka/hold2 $WS/ka/hold3
task ka "sh /workspace/hold.sh" > $G/hold 2>&1 &
HT=$!
for i in $(seq 300); do [ -n "$(ls $WS/ka/hold1 $WS/ka/hold2 $WS/ka/hold3 2>/dev/null)" ] && break; sleep 0.2; done
task kb "$M -d @/workspace/hi.json http://127.0.0.1:8081/anthropic/v1/messages; cat /tmp/b" > $G/kb2
ls $WS/ka > $G/held
wait $HT
check "C-G4 kb's reply is the same, apart from ids, while ka holds its largest reservations (two in flight, a third refused)" '
  echo "ka spent $S nanodollars today"; cat $G/kb2 $G/held $G/hold $WS/ka/hold1 $WS/ka/hold2 $WS/ka/hold3
  cmp $G/kb0 $G/kb2 && [ "$(grep -c "^hold[123]$" $G/held)" = 1 ] &&
  [ "$(head -qn1 $WS/ka/hold1 $WS/ka/hold2 $WS/ka/hold3 | sort | tr "\n" " ")" = "200 200 429 " ] &&
  grep -l "^429" $WS/ka/hold1 $WS/ka/hold2 $WS/ka/hold3 | xargs grep -q "\"what\":\"agent\""'
printf "keys.day_cap_cents = 10000\nkeys.agent_day_share.ka = 1\n" | $B budget set >/dev/null
uplog > /dev/null
check "C-G4 Claude Code at its share stops within its own retries, and the task result carries KEYS_BUDGET" '
  cli ka claude < $G/hi; T=$(cat $G/last); echo "task $T: $(deny $T) denials by keys, end $(field $T end_reason)"
  journalctl -b -u agentbox-keys -o cat | grep "task=$T"; journalctl -b -u agentboxd -o cat | grep "task $T result: "; uplog | tee $G/lbud
  [ "$(deny $T)" -ge 1 ] && [ "$(deny $T)" -le 12 ] &&
  journalctl -b -u agentboxd -o cat | grep "task $T result: " | grep -vq " 0 denials" && ! grep -q "\"path\":\"/v1/messages\"" $G/lbud'
check "C-G4 Codex at its share stops within its own retries, and the task result carries KEYS_BUDGET" '
  cli ka codex < $G/hi; T=$(cat $G/last); echo "task $T: $(deny $T) denials by keys, end $(field $T end_reason)"
  journalctl -b -u agentbox-keys -o cat | grep "task=$T"; journalctl -b -u agentboxd -o cat | grep "task $T result: "; uplog | tee $G/lbudx
  [ "$(deny $T)" -ge 1 ] && [ "$(deny $T)" -le 12 ] &&
  journalctl -b -u agentboxd -o cat | grep "task $T result: " | grep -vq " 0 denials" && ! grep -q "\"path\":\"/v1/responses\"" $G/lbudx'
printf "keys.day_cap_cents = 0\n" | $B budget set >/dev/null

# --- #18: the local LLM (a stand-in for agentbox-llm@task) ---
cat > $RS/agentbox-llm@.socket <<U
[Socket]
ListenStream=/run/agentbox-llm/llama.sock
SocketUser=agentbox-llm
SocketGroup=agentbox-keys
SocketMode=0660
U
cat > $RS/agentbox-llm@.service <<U
[Unit]
Requires=agentbox-llm@%i.socket
[Service]
User=agentbox-llm
ExecStart=$G/llama -llama
U
systemctl daemon-reload && systemctl start agentbox-llm@task.socket
L='curl -s -o /tmp/b -D /tmp/h -w "%{http_code}\n" -H "content-type: application/json"'
body local '{"messages":[{"role":"user","content":"hi"}],"grammar":"root ::= x","n_probs":3}'
LQ="$L -d @/workspace/local.json http://127.0.0.1:8081/local/v1/chat/completions; cat /tmp/h /tmp/b"
inst() { sed -n 's/.*instance \([0-9a-f]*\) request.*/\1/p' "$1"; }
check "#18 local LLM: a clean task's request, rebuilt from the field list, with the dropped fields named on the 200" '
  task kb "$LQ" > $G/lo1; cat $G/lo1
  head -1 $G/lo1 | grep -qx 200 && grep -qi "^agentbox-dropped-fields: grammar,n_probs" $G/lo1 && grep -qi "^agentbox-denial: v1 code=KEYS_REQUEST_REJECTED" $G/lo1 &&
  [ -n "$(inst $G/lo1)" ] && journalctl -b -u agentbox-llm@task -o cat | grep "request 1 POST" | grep -q "fields max_tokens,messages$"'
I1=$(inst $G/lo1)
TS='agentbox gate call --socket /run/agentbox/gate/gate.sock '"'"'{"jsonrpc":"2.0","id":1,"method":"task.taint_self","params":{"source":"cache:go"}}'"'"' >/dev/null'
check "  ... a tainted task (task.taint_self) is served by that same instance, which is dirty from then on" '
  task ka "$TS; $LQ" > $G/lo2; cat $G/lo2; [ "$(inst $G/lo2)" = "$I1" ]'
check "#18 an untainted agent never gets output from that instance: keys had rootd restart it (llm.recycle) first" '
  task kb "$LQ" > $G/lo3; cat $G/lo3
  I3=$(inst $G/lo3) && [ -n "$I3" ] && [ "$I3" != "$I1" ] && journalctl -b -u agentbox-rootd -o cat | grep -q "llm.recycle: agentbox-llm@task.service restarted"'
systemctl stop agentbox-llm@task.service agentbox-llm@task.socket; rm -f $RS/agentbox-llm@.socket $RS/agentbox-llm@.service; systemctl daemon-reload

# --- #18: a key rotated mid-task ---
rm -f $G/last $WS/ka/go $WS/ka/r0 $WS/ka/r1 $WS/ka/r2
body slow "$(msg '"GATE-MODE:slow-30"')"
task ka "$M -d @/workspace/hello.json http://127.0.0.1:8081/anthropic/v1/messages > /workspace/r0
  ( curl -s -o /tmp/b1 -D /tmp/h1 -w \"%{http_code}\n\" -H \"content-type: application/json\" -d @/workspace/slow.json http://127.0.0.1:8081/anthropic/v1/messages > /workspace/r1; cat /tmp/h1 /tmp/b1 >> /workspace/r1 ) &
  while [ ! -e /workspace/go ]; do sleep 0.2; done; wait
  $M -d @/workspace/hello.json http://127.0.0.1:8081/anthropic/v1/messages > /workspace/r2; cat /tmp/b >> /workspace/r2; echo done" > $G/rot 2>&1 &
RT=$!
for i in $(seq 300); do [ -s $G/last ] && [ -s $WS/ka/r0 ] && break; sleep 0.2; done
TR=$(cat $G/last); sleep 2
P1=$(systemctl show -P MainPID agentbox-keys.service)
printf '%s\n' "$KEY2" | $B secret set --name anthropic-api-key > $G/ss2
for i in $(seq 50); do systemctl is-active -q agentbox-keys && break; sleep 0.2; done
upkeys "$KEY2"
touch $WS/ka/go; wait $RT
check "#18 rotation: secret.set mid-task restarts agentbox-keys, and the old key is revoked at the vendor" '
  cat $G/ss2 && grep -q "\"restarted\":true" $G/ss2 && [ "$(systemctl show -P MainPID agentbox-keys.service)" != "$P1" ] &&
  [ "$(runuser -u agentbox-keys -- cat $CRED/anthropic-api-key)" = "$KEY2" ]'
check "  ... the request in flight fails cleanly with a typed error (BROKER_UNAVAILABLE or KEYS_UPSTREAM)" '
  cat $WS/ka/r1; grep -qi "^agentbox-denial: v1 code=\(BROKER_UNAVAILABLE\|KEYS_UPSTREAM\)" $WS/ka/r1'
check "  ... the next request succeeds with the new key, in the same task (no task restart)" '
  cat $G/rot $WS/ka/r0 $WS/ka/r2; head -1 $WS/ka/r0 | grep -qx 200 && head -1 $WS/ka/r2 | grep -qx 200 && grep -qx done $G/rot &&
  [ "$(cat $G/last)" = "$TR" ] && uplog > $G/lrot && cat $G/lrot && grep "\"auth\":\"ok:$F2\"" $G/lrot | grep -q .'

# --- the box ---
check "#18 the keys nft drop counters stayed at 0 through the run" '[ "$(kdrops)" = "$D0" ] && echo "drops $D0 -> $(kdrops)"'
check "#108 #18 neither key appears in audit or journald" '! cat $A/seg-*.jsonl | grep -qF "$(printf %s "$KEY1" | cut -c14-50)" &&
  ! cat $A/seg-*.jsonl | grep -qF "$(printf %s "$KEY2" | cut -c14-50)" && ! journalctl -b -o cat | grep -qF "$(printf %s "$KEY1" | cut -c14-50)" &&
  ! journalctl -b -o cat | grep -qF "$(printf %s "$KEY2" | cut -c14-50)" && ! journalctl -b -o cat | grep -qF "$(printf %s "$OKEY" | cut -c10-40)"'
check "the audit chain verifies" '$B audit verify'
check "no task is left live" '[ "$($B task list | python3 -c "import json,sys; print(sum(1 for t in json.load(sys.stdin)[\"tasks\"] if \"end_reason\" not in t))")" = 0 ]'
echo "fails=$fails"
EOF
  reboot_vm
  guest <<'EOF'
fails=0
check() { if (eval "$2") >/var/tmp/kg-out 2>&1; then echo "PASS $1"; else echo "FAIL $1"; sed 's/^/  | /' /var/tmp/kg-out | tail -40; fails=$((fails+1)); fi; }
check "#108 after a reboot agentbox-keys loads the rotated key again, only for its own uid" '
  systemctl is-active -q agentbox-keys && [ "$(runuser -u agentbox-keys -- cat /run/credentials/agentbox-keys.service/anthropic-api-key)" = "$KEY2" ] &&
  ! runuser -u agentbox-proxy -- cat /run/credentials/agentbox-keys.service/anthropic-api-key 2>/dev/null'
check "#108 ... and the reboot's journal holds no key byte" '! journalctl -b -o cat | grep -qF "$(printf %s "$KEY2" | cut -c14-50)"'
echo "fails=$fails"
EOF
  ;;
apply)
  [ -s "$K/env" ] || die "run checks first: apply uses its box and keys"
  running || up
  # retention runs at each commit and keeps the three newest generations at or below the committed one (§3.3 step 7),
  # so the third commit prunes the oldest generation, the one the key was set in on a fresh box
  O=$(echo 'ls /bootpart/agentbox/gens' | root 2>>"$LOG" | sed -n 's/^gen-\([1-9][0-9]*\)$/\1/p' | sort -n | head -1)
  [ -n "$O" ] || die "apply: no generation under /bootpart/agentbox/gens"
  for n in 1 2 3; do
    guest "CYCLE=$n" <<'EOF'
fails=0
check() { if (eval "$2") >/var/tmp/kg-out 2>&1; then echo "PASS $1"; else echo "FAIL $1"; sed 's/^/  | /' /var/tmp/kg-out | tail -40; fails=$((fails+1)); fi; }
B=/var/lib/agentbox/current/bin/agentbox
$B os plan --install hostname --reinstall > /tmp/kg-plan 2>&1; cat /tmp/kg-plan
H=$(sed -n 's/^plan sha256: //p' /tmp/kg-plan)
check "#108 apply $CYCLE: os plan re-installs one package (a clone with no other change)" '[ -n "$H" ]'
$B os apply --approve "$H" --no-reboot > /tmp/kg-apply 2>&1; cat /tmp/kg-apply
check "#108 apply $CYCLE: os apply builds the clone" 'grep -q "^built " /tmp/kg-apply'
echo "fails=$fails"
EOF
    reboot_vm
    guest "CYCLE=$n" <<'EOF'
fails=0
check() { if (eval "$2") >/var/tmp/kg-out 2>&1; then echo "PASS $1"; else echo "FAIL $1"; sed 's/^/  | /' /var/tmp/kg-out | tail -40; fails=$((fails+1)); fi; }
B=/var/lib/agentbox/current/bin/agentbox
g=$(findmnt -no FSROOT /); g=${g#/@}
# one os health run commits the trial and prunes: wait for both
i=0; until [ ! -e /var/lib/agentbox/os/pending.json ] && grep -q "^agentbox-$g-" /bootpart/agentbox/committed &&
  [ "$(systemctl show -P ActiveState agentbox-health.service)" != activating ]; do i=$((i+1)); [ $i -lt 84 ] || break; sleep 5; done
$B os status > /tmp/kg-status 2>&1; cat /tmp/kg-status
check "#108 apply $CYCLE: the trial ($g, a clone) booted and health committed it" '[ "$g" != gen-1 ] && grep -q "^agentbox-$g-" /bootpart/agentbox/committed'
check "#108 apply $CYCLE: in the committed clone agentbox-keys loads the key, readable by agentbox-keys only" '
  systemctl is-active -q agentbox-keys && [ "$(runuser -u agentbox-keys -- cat /run/credentials/agentbox-keys.service/anthropic-api-key)" = "$KEY2" ] &&
  ! runuser -u agentbox-git -- cat /run/credentials/agentbox-keys.service/anthropic-api-key 2>/dev/null'
echo "fails=$fails"
EOF
  done
  guest "O=$O" <<'EOF'
fails=0
check() { if (eval "$2") >/var/tmp/kg-out 2>&1; then echo "PASS $1"; else echo "FAIL $1"; sed 's/^/  | /' /var/tmp/kg-out | tail -40; fails=$((fails+1)); fi; }
check "#108 the third commit pruned gen-$O, the oldest generation, and a restarted agentbox-keys loads the key" '
  ! btrfs subvolume list / | grep -qw "@gen-$O" && ! test -e /bootpart/agentbox/gens/gen-$O && systemctl restart agentbox-keys &&
  [ "$(runuser -u agentbox-keys -- cat /run/credentials/agentbox-keys.service/anthropic-api-key)" = "$KEY2" ]'
echo "fails=$fails"
EOF
  ;;
*) die "unknown step $s (install, checks or apply)" ;;
esac; done
! grep -q '^[0-9:]* FAIL' "$OUT"

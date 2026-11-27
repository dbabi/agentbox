#!/bin/sh
# The box half of hack/git-gate.sh, run as root on the VM, with UP (the stub's forwarded port) and TOKEN (its fake
# token) set before it, and the stub's CA in /run/gg/ca.pem. `setup` readies the box; `main` runs the gate items.
# Prints PASS/FAIL lines, then fails=N. Test VMs only.
# shellcheck disable=SC2034 # the check strings read the variables set for them, in eval
fails=0
cd /
G=/run/gg B=/var/lib/agentbox/current/bin/agentbox RS=/run/systemd/system
DB=/var/lib/agentbox/rootd.db TDB=/var/lib/agentbox/audit/taint.db GIT=/var/lib/agentbox/git A=/var/lib/agentbox/audit
WS=/var/lib/agentbox/data/workspaces
check() { if (eval "$2") >>$G/check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
# git as root on the service's repos: they are agentbox-git's, so root needs safe.directory
git() { command git -c safe.directory='*' "$@"; }
# stub PATH: the stub's own control, from root on the box (vmnet forwards 10.0.2.2:UP to the host's 127.0.0.1:UP)
stub() { curl -sf --cacert $G/ca.pem --resolve "api.github.com:$UP:10.0.2.2" "https://api.github.com:$UP/_gate/$1"; }
posts() { stub state | python3 -c 'import json,sys; print(json.load(sys.stdin)["posts"])'; }
# sq DB SQL ARGS...: the first column of the first row, read-only
sq() { python3 -c 'import sqlite3,sys; r=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True).execute(sys.argv[2],sys.argv[3:]).fetchone(); print("" if r is None else r[0])' "$@"; }
pstate() { sq $DB 'select state from pending where id=?' "$1"; }
presult() { sq $DB 'select coalesce(reason,"")||" "||coalesce(result,"") from pending where id=?' "$1"; }
taint() { sq $TDB 'select tainted from taint where subject=?' "$1"; }
# new AGENT < script: start a task as the human; print its id
new() { $B task new --agent "$1" --cli sh --deadline 5m > $G/new.out && sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' $G/new.out; }
field() { $B task list | python3 -c 'import json,sys; t=[x for x in json.load(sys.stdin)["tasks"] if x["task"]==sys.argv[1]]; v=t[0].get(sys.argv[2],"") if t else ""
print(v if isinstance(v,str) else json.dumps(v))' "$1" "$2"; }
wait_end() { i=0; while [ -z "$(field "$1" end_reason)" ]; do i=$((i+1)); [ $i -lt $(( $2 * 5 )) ] || return 1; sleep 0.2; done; }
wait_file() { i=0; while [ ! -e "$1" ]; do i=$((i+1)); [ $i -lt $(( $2 * 5 )) ] || return 1; sleep 0.2; done; }
# pnd FILE: the pending id of a NEEDS_SIGNATURE reply; code FILE: the code of a denial reply
pnd() { grep -o '"id":"pnd_[0-9A-Z]*"' "$1" | head -1 | cut -d'"' -f4; }
code() { grep -o '"code":"[A-Z_]*"' "$1" | head -1 | cut -d'"' -f4; }
# drops: the packets of every nft output rule that drops traffic of agentbox-git, alone or with the other brokers
drops() { nft -j list chain inet agentbox output | python3 -c '
import json,sys,pwd
u=pwd.getpwnam("agentbox-git").pw_uid; n=0
def git(m):
    if m.get("left")!={"meta":{"key":"skuid"}}: return False
    r=m["right"]; return r==u or r=="agentbox-git" or isinstance(r,dict) and u in r.get("set",[])
for x in json.load(sys.stdin)["nftables"]:
    e=x.get("rule",{}).get("expr",[])
    if any("drop" in t for t in e) and any(git(t["match"]) for t in e if "match" in t):
        n+=sum(t["counter"]["packets"] for t in e if "counter" in t)
print(n)'; }
# script NAME < body: a task script, with the helpers it needs inside the container
script() { { cat <<'S'
op() { agentbox gate call --socket /run/agentbox/gate/gate.sock "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" > "/workspace/$3" 2>&1 || :; }
repo() { rm -rf /workspace/w && git init -q -b main /workspace/w && cd /workspace/w && git config user.email t@t.example && git config user.name t; }
push() { git push http://127.0.0.1:8082/app "HEAD:$1" > "/workspace/$2.out" 2>&1; echo $? > "/workspace/$2.rc"; }
S
  cat; } > "$G/$1"; }
same() { [ "$(sed 's/dn_[0-9A-Z]*/dn_X/g' "$1")" = "$(sed 's/dn_[0-9A-Z]*/dn_X/g' "$2")" ]; }
journalctl --rotate >/dev/null 2>&1 || :

case ${1:-} in
setup)
check "svc-git.sock listens from boot and starts agentbox-git, as agentbox-git (agentbox-git:root 0600); git/ is the service's, 0700; the release's hook is root's" '
  systemctl is-active -q agentbox-git-svc.socket && systemctl start agentbox-git.service && systemctl is-active -q agentbox-git.service &&
  [ "$(systemctl show -P User agentbox-git.service)" = agentbox-git ] &&
  [ "$(stat -c "%U:%G %a" /run/agentbox-rootd/svc-git.sock)" = "agentbox-git:root 600" ] && [ "$(stat -c "%U %a" $GIT)" = "agentbox-git 700" ] &&
  [ "$(stat -c "%U %a" /var/lib/agentbox/current/git-hooks/pre-receive)" = "root 755" ] && git --version'
# a rerun starts from empty workspaces: a canary an earlier run left there would block the agent's tasks at the next
# credential scan (issue #289)
for a in gg gt go; do [ ! -d $WS/$a ] || find $WS/$a -mindepth 1 -delete; done
# and from no repos or day totals of an earlier run (taint rows stay: auditd never deletes one)
systemctl stop agentbox-git.service; rm -rf $GIT/gg $GIT/gt $GIT/go $GIT/.state.db*
cp $G/ca.pem /usr/local/share/ca-certificates/agentbox-git-gate.crt && update-ca-certificates >/dev/null 2>&1
U=$(id -u agentbox-git)
# every https connection agentbox-git opens goes to the stub; the agentbox table then sees 10.0.2.2:UP, which only
# this allow_private4 tuple admits (the gate's stand-in for GitHub's own addresses)
nft delete table ip gg 2>/dev/null
nft -f - <<N
table ip gg {
  chain out {
    type nat hook output priority -100;
    meta skuid $U tcp dport 443 dnat to 10.0.2.2:$UP
  }
}
N
python3 -c "import sqlite3; c=sqlite3.connect('$DB'); c.execute(\"insert or ignore into set_elements values ('allow_private4', '$U . 10.0.2.2 . $UP', NULL)\"); c.commit()"
check "the stub answers the box; agentbox-git's https goes to it (NAT), admitted by its allow_private4 tuple" '$B egress refill >/dev/null && stub state >/dev/null &&
  nft list table ip gg | grep -q "dnat to 10.0.2.2:$UP" && nft list set inet agentbox allow_private4 | grep -q "10.0.2.2 . $UP"'
# without the NAT rule, agentbox-git would reach the real GitHub: stop before any GitHub name is allowed
[ $fails = 0 ] || { echo "fails=$fails"; exit 0; }
check "service.list names github.com:443 and api.github.com:443 for git" '$B egress allow --svc git --entry github.com:443 >/dev/null &&
  $B egress allow --svc git --entry api.github.com:443 >/dev/null && grep -qx "git github.com:443" /var/lib/agentbox/control/egress/service.list'
CS=/var/lib/agentbox/control/credstore.encrypted CRED=/run/credentials/agentbox-git.service
check "#108: secret set --name github-token (the value on stdin) stores ciphertext only, root 0600, for agentbox-git" '
  printf "%s\n" "$TOKEN" | $B secret set --name github-token | grep -q "\"service\":\"agentbox-git\"" &&
  [ "$(stat -c "%U %a" $CS/git $CS/git/github-token)" = "root 700
root 600" ] && ! grep -qF "$TOKEN" $CS/git/github-token'
check "#108: agentbox-git alone reads the token, from its own credentials dir; agentbox-proxy and agentbox-keys can't" '
  systemctl restart agentbox-git.service && systemctl is-active -q agentbox-git.service &&
  [ "$(runuser -u agentbox-git -- cat $CRED/github-token)" = "$TOKEN" ] &&
  ! runuser -u agentbox-proxy -- cat $CRED/github-token 2>/dev/null && ! runuser -u agentbox-keys -- cat $CRED/github-token 2>/dev/null'
check "A-G13: agentbox-git runs one more seccomp filter than its unit gives (logged at start, in /proc)" '
  pid=$(systemctl show -P MainPID agentbox-git.service) && l=$(journalctl -b -u agentbox-git.service -o cat | grep "service filter installed: Seccomp_filters" | tail -1) &&
  echo "$l" && b=$(echo "$l" | sed -n "s/.*Seccomp_filters \([0-9]*\) -> \([0-9]*\).*/\1/p") && a=$(echo "$l" | sed -n "s/.*-> \([0-9]*\).*/\1/p") &&
  [ "$a" = $((b + 1)) ] && grep -qx "Seccomp_filters:	$a" /proc/$pid/status'
mkdir -p $RS/agentboxd.service.d && printf '[Service]\nEnvironment=AGENTBOX_TEST_CLI=sh\n' > $RS/agentboxd.service.d/50-gg.conf
systemctl daemon-reload && systemctl restart agentboxd.service
check "three agents: gg for clean work, gt for tainted work, go another agent" 'for a in gg gt go; do $B agent list | grep -q "\"name\":\"$a\"" || $B agent add --name $a || exit 1; done'
check "remote.set reads the node id and visibility from GitHub and makes the local repo; an off-GitHub URL is refused" '
  $B remote set --id gg-origin --agent gg --project app --url https://github.com/acme/app &&
  $B remote set --id gt-origin --agent gt --project app --url https://github.com/acme/app.git &&
  $B remote set --id go-origin --agent go --project other --url https://github.com/acme/other &&
  $B remote list --agent gg | grep -q "\"gh_node_id\":\"R_kgDOGateApp\",\"visibility\":\"private\"" && [ -f $GIT/gg/app.git/HEAD ] &&
  ! $B remote set --id bad --agent gg --project app --url https://gitlab.example/acme/app'
;;

main)
WG=$WS/gg WT=$WS/gt
# --- a clean task (#19, #105, C-G4): local pushes, the 404 floor, the decoys, the ops it asks for ---
script t1 <<'S'
repo; echo hello > a.txt && git add a.txt && git commit -qm clean && git rev-parse HEAD > /workspace/clean.oid
push refs/heads/agent/gg/clean clean
push refs/heads/main main
# timed on CLOCK_MONOTONIC, the clock the service's floor sleeps on. curl times on CLOCK_MONOTONIC_RAW, which runs up to
# 8% apart from it while chrony slews a fresh boot's clock
for p in nosuch other; do python3 -c 'import http.client, sys, time
c = http.client.HTTPConnection("127.0.0.1", 8082, timeout=10); t = time.monotonic()
c.request("GET", "/%s/info/refs?service=git-upload-pack" % sys.argv[1]); r = c.getresponse(); d = time.monotonic() - t
open("/workspace/404-%s.body" % sys.argv[1], "wb").write(r.read()); print(r.status, "%.6f" % d)' $p > /workspace/404-$p.meta; done
# the decoys are checked here: a copy of the canary in the workspace would block the agent at its next credential scan
c=$GITHUB_TOKEN
{ [ "$ANTHROPIC_API_KEY" = "$c" ] && printf %s "$c" | grep -Eq '^sk-ant-''api03-[A-Za-z0-9_-]{93}AA$' && grep -qxF "  password $c" ~/.netrc &&
  grep -qxF "    oauth_token: $c" ~/.config/gh/hosts.yml; } && echo ok > /workspace/decoys.ok
env | grep -v -e '^ANTHROPIC_API_KEY=' -e '^GITHUB_TOKEN=' > /workspace/env.txt
git push https://github.com/acme/app.git HEAD:refs/heads/agent/gg/direct > /workspace/direct.out 2>&1; echo $? > /workspace/direct.rc
o=$(cat /workspace/clean.oid)
op repo.push "{\"remote\":\"gg-origin\",\"ref\":\"refs/heads/agent/gg/clean\",\"oid\":\"$o\"}" op-push
op repo.push "{\"remote\":\"go-origin\",\"ref\":\"refs/heads/agent/gg/clean\",\"oid\":\"$o\"}" op-notmine
op repo.push "{\"remote\":\"nosuch\",\"ref\":\"refs/heads/agent/gg/clean\",\"oid\":\"$o\"}" op-missing
op repo.push "{\"remote\":\"gg-origin\",\"ref\":\"refs/heads/main\",\"oid\":\"$o\"}" op-main
op gh.pr.create '{"remote":"gg-origin","head":"refs/heads/agent/gg/clean","base":"main","title":"Gate PR","body":"A pull request from the gate."}' op-pr
S
T1=$(new gg < $G/t1)
check "a clean task runs its pushes and asks, and completes" '[ -n "$T1" ] && wait_end $T1 120 && [ "$(field $T1 end_reason)" = completed ]'
check "#105: a clean push still succeeds; the commit lands under refs/heads/agent/gg/ in the agent's bare repo" '[ "$(cat $WG/clean.rc)" = 0 ] &&
  [ "$(git -C $GIT/gg/app.git rev-parse refs/heads/agent/gg/clean)" = "$(cat $WG/clean.oid)" ]'
check "C-G4: a push to refs/heads/main prints remote: agentbox REF_OUTSIDE_NAMESPACE and the JSON line, and makes no ref" '[ "$(cat $WG/main.rc)" != 0 ] &&
  grep -q "^remote: agentbox REF_OUTSIDE_NAMESPACE: " $WG/main.out && grep -q "^remote: agentbox-denial/v1 {.*\"code\":\"REF_OUTSIDE_NAMESPACE\"" $WG/main.out &&
  ! git -C $GIT/gg/app.git rev-parse -q --verify refs/heads/main'
check "C-G4: a missing repo and another agent's give byte-identical text/plain 404s apart from the id, 200 to 215 ms after the request (client side)" '
  read c1 t1 < $WG/404-nosuch.meta && read c2 t2 < $WG/404-other.meta && [ $c1 = 404 ] && [ $c2 = 404 ] && same $WG/404-nosuch.body $WG/404-other.body &&
  grep -q "^agentbox NOT_FOUND_OR_NOT_OWNED: " $WG/404-nosuch.body && [ -d $GIT/go/other.git ] &&
  python3 -c "import sys; t=[float(x) for x in sys.argv[1:]]; print(t); sys.exit(0 if all(0.200 <= x <= 0.215 for x in t) else 1)" $t1 $t2'
check "#105: the canary is in the key slot, GITHUB_TOKEN, ~/.netrc and gh hosts.yml, vendor-shaped; the box's token is nowhere in the task" '
  [ "$(cat $WG/decoys.ok)" = ok ] && [ -s $WG/env.txt ] && ! grep -rqs "$TOKEN" $WG'
check "#19: a task has no route to GitHub of its own: a direct push fails" '[ "$(cat $WG/direct.rc)" != 0 ]'
P1=$(pnd $WG/op-push) P2=$(pnd $WG/op-pr)
check "#19: repo.push to the agent's own remote waits for a human (NEEDS_SIGNATURE, cli); nothing reached the remote" '[ -n "$P1" ] &&
  [ "$(code $WG/op-push)" = NEEDS_SIGNATURE ] && [ "$(pstate $P1)" = pending ] && grep -q "\"channel\":\"cli\"" $WG/op-push &&
  ! stub state | grep -q "agent/gg/clean"'
check "#19: repo.push to another agent's remote and to a missing one: one NOT_FOUND_OR_NOT_OWNED, byte-identical apart from the id; main is outside the namespace" '
  [ "$(code $WG/op-notmine)" = NOT_FOUND_OR_NOT_OWNED ] && same $WG/op-notmine $WG/op-missing && [ "$(code $WG/op-main)" = REF_OUTSIDE_NAMESPACE ]'
D0=$(drops)
check "#19: approved, repo.push runs through agentbox-git: the stub remote has the ref at the bound OID" '[ -n "$P1" ] &&
  $B pending approve --id $P1 | grep -q "\"state\":\"executed\"" && stub state | grep -q "\"acme/app refs/heads/agent/gg/clean\": *\"$(cat $WG/clean.oid)\""'
check "#19: approved, gh.pr.create opens the PR, its body ends with the op marker; GitHub's number and URL are in the result" '[ -n "$P2" ] &&
  $B pending approve --id $P2 | grep -q "\"state\":\"executed\"" && stub state | grep -q "A pull request from the gate.\\\\n<!-- agentbox-op:$P2 -->" &&
  presult $P2 | grep -q "\"number\":1" && presult $P2 | grep -q "https://github.com/acme/app/pull/1"'
check "#19: rootd resolved GitHub for agentbox-git (git_dst4 has its answers), and the git nft drop counters stay at 0" '
  nft list set inet agentbox git_dst4 | grep -q "\. 443" && [ "$D0" = 0 ] && [ "$(drops)" = 0 ]'

# --- reconcile (#19): rootd killed between a comment POST and its RESULT ---
script t2 <<'S'
op gh.pr.comment '{"remote":"gg-origin","number":1,"body":"A comment rootd is killed under."}' op-comment
S
T2=$(new gg < $G/t2)
check "a task asks for gh.pr.comment on the PR" 'wait_end $T2 60 && [ "$(code $WG/op-comment)" = NEEDS_SIGNATURE ]'
P3=$(pnd $WG/op-comment)
before=$(posts)
stub hold >/dev/null
( $B pending approve --id "$P3" > $G/ap3.out 2>&1 & )
i=0; until stub state | grep -q '"held": *true'; do i=$((i+1)); [ $i -lt 150 ] || break; sleep 0.2; done
pid=$(systemctl show -P MainPID agentbox-rootd.service)
kill -9 "$pid"
i=0; until [ "$(systemctl show -P MainPID agentbox-rootd.service)" != "$pid" ] && systemctl is-active -q agentbox-rootd.service; do i=$((i+1)); [ $i -lt 150 ] || break; sleep 0.2; done
stub release >/dev/null
i=0; until [ "$(pstate $P3)" = executed ]; do i=$((i+1)); [ $i -lt 450 ] || break; sleep 0.2; done
check "#19: kill rootd between a comment POST and RESULT: reconcile finds the marker and writes RESULT, with no second comment" '
  [ "$(pstate $P3)" = executed ] && presult $P3 | grep -q issuecomment && [ "$(posts)" = $((before + 1)) ] &&
  stub state | python3 -c "import json,sys; c=[x for x in json.load(sys.stdin)[\"comments\"][\"acme/app#1\"] if \"agentbox-op:$P3\" in x[\"body\"]]; sys.exit(len(c)!=1)" &&
  [ "$(cat $A/seg-*.jsonl | grep -c "\"opId\":\"$P3\"")" = 2 ] && journalctl -u agentbox-rootd -b --no-pager | grep -q "$P3: reconcile found the effect"'

# --- C-G4: a fake GitHub 422 carrying a secret-shaped string gives REMOTE_REJECTED; the string reaches no task byte ---
script t3 <<'S'
op gh.pr.create '{"remote":"gg-origin","head":"refs/heads/agent/gg/clean","base":"main","title":"Again","body":"A PR GitHub refuses."}' op-refused
i=0; while [ ! -e /workspace/go422 ] && [ $i -lt 450 ]; do i=$((i+1)); sleep 0.2; done
op gh.pr.create '{"remote":"gg-origin","head":"refs/heads/agent/gg/clean","base":"main","title":"Again","body":"A PR GitHub refuses."}' op-refused2
agentbox why > /workspace/why.txt 2>&1 || :
S
rm -f $WG/go422 $WG/op-refused
T3=$(new gg < $G/t3)
i=0; until grep -qs pnd_ $WG/op-refused; do i=$((i+1)); [ $i -lt 300 ] || break; sleep 0.2; done
P4=$(pnd $WG/op-refused)
SECRET="sk-gate-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
stub "fail422?b64=$(printf 'Validation: %s' "$SECRET" | base64 | tr -d '\n')" >/dev/null
check "C-G4: the fake 422 gives REMOTE_REJECTED; GitHub's text reaches only the DENY detail" '[ -n "$P4" ] &&
  $B pending approve --id $P4 | grep -q "\"reason\":\"REMOTE_REJECTED:other\"" && grep -qh "$SECRET" $A/seg-*.jsonl'
touch $WG/go422
check "C-G4: the task resubmits the refused op and reads agentbox why; no task-visible byte holds GitHub's text" 'wait_end $T3 120 &&
  [ -s $WG/op-refused2 ] && ! grep -rqs "$SECRET" $WG && ! grep -qs Validation $WG/op-refused2 $WG/why.txt'

# --- #105 and #19 with a tainted task: the canary in a push and a PR body; ref, commit and merge taint ---
script t4 <<'S'
c=$GITHUB_TOKEN
repo; echo base > base.txt && git add base.txt && git commit -qm base && b=$(git rev-parse HEAD)
echo "token = $c" > k.txt && git add k.txt && git commit -qm file && git rev-parse HEAD > /workspace/c-file.oid && push refs/heads/agent/gt/file c-file
git reset -q --hard $b && base64 ~/.netrc > n.b64 && git add n.b64 && git commit -qm b64 && git rev-parse HEAD > /workspace/c-b64.oid && push refs/heads/agent/gt/b64 c-b64
git reset -q --hard $b && printf 'k = "%s"\n    "%s"\n' "$(printf %s "$c" | cut -c1-50)" "$(printf %s "$c" | cut -c51-)" > s.txt && git add s.txt &&
  git commit -qm split && git rev-parse HEAD > /workspace/c-split.oid && push refs/heads/agent/gt/split c-split
git reset -q --hard $b && echo "no secret here" > ok.txt && git add ok.txt && git commit -qm ok && git rev-parse HEAD > /workspace/t.oid && push refs/heads/agent/gt/t t
pat="ghp_$(printf 'aB3dE6gH9k%.0s' 1 2 3)mN0pQr" && echo "token: $pat" > cfg.txt && git add cfg.txt && git commit -qm pat && push refs/heads/agent/gt/pat pat
op gh.pr.create "{\"remote\":\"gt-origin\",\"head\":\"refs/heads/agent/gt/t\",\"base\":\"main\",\"title\":\"x\",\"body\":\"key $c\"}" op-prcanary
op repo.merge "{\"p\":\"app\",\"srcOid\":\"$(cat /workspace/t.oid)\",\"dstOid\":\"0000000000000000000000000000000000000000\"}" op-merge
S
T4=$(new gt < $G/t4)
check "a task of gt pushes the canary three ways, a clean branch and a credential pattern, then asks for a PR and a merge" 'wait_end $T4 120'
for f in file b64 split; do
  check "#105: a push with the canary ($f) is refused with EXFIL_CANARY and stores nothing; the denial doesn't echo it" '[ "$(cat $WT/c-'$f'.rc)" != 0 ] &&
    grep -q "^remote: agentbox EXFIL_CANARY: " $WT/c-'$f'.out && ! git -C $GIT/gt/app.git cat-file -e $(cat $WT/c-'$f'.oid) && ! grep -q "sk-ant-""api03" $WT/c-'$f'.out'
done
check "#105: a canary hit taints the task, writes audit and alerts the human" '[ "$(taint task:$T4)" = 1 ] && grep -qh "\"source\":\"canary:repo.push\"" $A/seg-*.jsonl &&
  grep -qh "\"reason\":\"exfil_canary\"" $A/seg-*.jsonl && journalctl -u agentbox-rootd -b --no-pager | grep -q "ALERT task $T4 .* canary"'
check "#19: the tainted task's clean push lands and taints its ref; pre-receive recorded its commit (ref and commit taint)" '[ "$(cat $WT/t.rc)" = 0 ] &&
  [ "$(taint ref:gt/app:refs/heads/agent/gt/t)" = 1 ] && [ "$(sq $GIT/.state.db "select count(*) from tainted_commits where oid=?" $(cat $WT/t.oid))" = 1 ]'
check "#105: a push with a gitleaks credential pattern lands, and the human is alerted" '[ "$(cat $WT/pat.rc)" = 0 ] &&
  journalctl -u agentbox-rootd -b --no-pager | grep -q "credential patterns (github-pat)"'
check "#105: a gh.pr.create body with the canary is refused with EXFIL_CANARY; no ask is made" '[ "$(code $WT/op-prcanary)" = EXFIL_CANARY ] &&
  [ "$(sq $DB "select count(*) from pending where task=? and op like ?" $T4 "%gh.pr.create%")" = 0 ]'
P5=$(pnd $WT/op-merge)
check "#19: merging a tainted branch taints main: a tainted ask, then main tainted (before it moves) and at the branch's commit" '[ -n "$P5" ] &&
  grep -q "\"reason\":\"tainted\"" $WT/op-merge && [ "$(taint ref:gt/app:refs/heads/main)" != 1 ] &&
  $B pending approve --id $P5 | grep -q "\"tainted\":true" && [ "$(taint ref:gt/app:refs/heads/main)" = 1 ] &&
  [ "$(git -C $GIT/gt/app.git rev-parse refs/heads/main)" = "$(cat $WT/t.oid)" ]'
script t5 <<'S'
op repo.merge "{\"p\":\"app\",\"srcOid\":\"$(cat /workspace/clean.oid)\",\"dstOid\":\"0000000000000000000000000000000000000000\"}" op-merge
S
T5=$(new gg < $G/t5)
check "#19 control: merging a clean branch leaves main clean" 'wait_end $T5 60 && p=$(pnd $WG/op-merge) && [ -n "$p" ] &&
  $B pending approve --id $p | grep -q "\"tainted\":false" && [ "$(taint ref:gg/app:refs/heads/main)" != 1 ]'

# --- C-G4: the daily cap, from the quarantine, before anything is stored ---
# budget.set replaces budgets.toml, and agentbox-git reads git.push_bytes_day at each push: no restart
printf 'git.push_bytes_day = 4096\n' | $B budget set >/dev/null
script t6 <<'S'
repo; head -c 65536 /dev/urandom > big.bin && git add big.bin && git commit -qm big && push refs/heads/agent/gg/big big
S
n0=$(find $GIT/gg/app.git/objects -type f | wc -l)
T6=$(new gg < $G/t6)
check "C-G4: a push over the daily cap (budget set git.push_bytes_day = 4096) prints CAP_REACHED{push_bytes_day} with its limit and stores no objects" '
  wait_end $T6 60 && [ "$(cat $WG/big.rc)" != 0 ] &&
  grep -q "^remote: agentbox CAP_REACHED: " $WG/big.out && grep -q "\"what\":\"push_bytes_day\"" $WG/big.out && grep -q "\"limit\":4096" $WG/big.out &&
  [ "$(find $GIT/gg/app.git/objects -type f | wc -l)" = "$n0" ]'
: | $B budget set >/dev/null

# --- a git service restart mid-task: the task's socket is bound again, with its canary ---
script t7 <<'S'
i=0; while [ ! -e /workspace/go7 ] && [ $i -lt 300 ]; do i=$((i+1)); sleep 0.2; done
c=$GITHUB_TOKEN; repo; echo "$c" > k.txt && git add k.txt && git commit -qm k && push refs/heads/agent/gt/after after
S
rm -f $WT/go7; T7=$(new gt < $G/t7)
sleep 3; systemctl restart agentbox-git.service; sleep 2; touch $WT/go7
check "after a git service restart mid-task, the task's push reaches it on the same socket, and its canary is still refused" 'wait_end $T7 90 &&
  grep -q "^remote: agentbox EXFIL_CANARY: " $WT/after.out'

# --- the rest of the box ---
check "the stub's token is in no audit record and no journal line" '! grep -rqs "$TOKEN" $A && ! journalctl -b --no-pager | grep -q "$TOKEN"'
check "the git nft drop counters are still 0" '[ "$(drops)" = 0 ]'
check "the audit chain verifies" '$B audit verify'
check "the box matches the socket inventory" '$B sockets check'
check "fwcheck passes" '$B fwcheck'
check "no failed units" 'sleep 2; [ -z "$(systemctl --failed --no-legend --plain)" ]'
;;
esac
echo "fails=$fails"

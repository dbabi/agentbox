#!/bin/sh
# Agent CLI lockdown gate (issues #77, #120, #121, #123; ARCHITECTURE.md §4.2) on the local arm64 QEMU VM, none mode,
# through the real rootd, agentboxd and auditd and rootless podman.
#   hack/cli-gate.sh [install|checks ...]   default: both, in order
# install  hack/gate.sh none: the unattended install and the release pipeline.
# checks   The real Claude Code and Codex CLIs (linux-arm64, pinned in hack/SHA256SUMS, fetched with npm pack into .vm)
#          in /usr/bin, which the stub task image mounts from the host; the image's /etc is the skeleton with the
#          policy files. Tasks start with `agentbox task new`: the real CLIs as --cli claude and --cli codex, and sh
#          prompts (AGENTBOX_TEST_CLI=sh) that run a CLI by hand. Stand-ins until the brokers land (python3, as in
#          taskenv-gate.sh): the proxy records each request and refuses it, the keys broker records each request line
#          and body and answers 400. Each gate item:
#          #77  the image's managed-settings.json and requirements.toml, root-owned and read-only; Claude's /status
#               names the managed file source in a task; a workspace .claude/settings.json and settings.local.json
#               (weakened managed keys, a SessionStart hook), .mcp.json and a .claude/agents/*.md mcpServers run no
#               hook or MCP server in a task, by hand with every settings source or as --cli claude, while on the host
#               (no managed settings) the same claude runs them (the control); the agent's server is blocked by the
#               same empty managed allowlist. Codex: .agents/skills (a symlinked skill too), .codex/hooks.json,
#               inline [hooks], user hooks and -c features.hooks/plugins=true run no hook, even with
#               --dangerously-bypass-hook-trust, in a task and in an attach; the host control runs the user hooks.
#               A Codex request from a task has no web_search tool, also with web_search="live" planted, while the
#               host control (gpt-5.5, live, no requirements) has one. attach refuses --dangerously-bypass-hook-trust;
#               task new refuses --cli opencode.
#          #121 a no-op --cli claude and --cli codex task each open 0 CONNECTs, and every request the keys broker
#               sees is the model API (a denial on the real broker otherwise).
#          #120 a canary line in INSTRUCTIONS.md reaches the recorded Claude request, and its tool list is the
#               pinned set below (no WebSearch). Bumping the Claude Code pin means running this gate.
#          #123 a task writes .vscode/tasks.json (runOn folderOpen), a nested repo sub/.git and a venv named env/,
#               and (#182) a venv at the workspace root, a bare repo and a git dir's commondir target: the next attach
#               is refused naming each, until --ack-control-changes quotes the digest the refusal printed; git in
#               the task finds no bare repo by itself.
#               (taint review has no CLI yet.)
# PASS/FAIL lines go to .vm/cli-gate.txt, command output to .vm/cli-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/cli-gate.txt" LOG="$VM/cli-gate.log"
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
up() { running || { hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"
  echo '[ "$(timeout 600 systemctl is-system-running --wait)" = running ] || systemctl --failed --no-pager' | root >>"$LOG" 2>&1 || :; }
guest() {
  root >"$VM/guest.out" 2>>"$LOG" || :
  while IFS= read -r l; do case $l in PASS*|FAIL*) log "$l" ;; *) echo "$l" >>"$LOG" ;; esac; done <"$VM/guest.out"
  grep -q '^fails=' "$VM/guest.out" || log "FAIL the check block on the VM did not finish (see $LOG)"
}
pinned() { [ -f "$1" ] && [ "$(shasum -a 256 < "$1" | cut -d' ' -f1)" = "$(awk -v f="${1##*/}" '$2 == f {print $1}' hack/SHA256SUMS)" ]; }
pkg() { # pkg FILE NPM-SPEC
  pinned "$VM/cli/$1" && return 0
  mkdir -p "$VM/cli" && (cd "$VM/cli" && npm pack --silent "$2") >>"$LOG" 2>&1 || die "npm pack $2 failed"
  pinned "$VM/cli/$1" || die "$1 does not match hack/SHA256SUMS"
}

for s; do case $s in
install)
  hack/gate.sh none >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-none.txt"
  log "PASS install: hack/gate.sh none (install, release pipeline, firstboot, no failed units)" ;;
checks)
  pkg "$CC" @anthropic-ai/claude-code-linux-arm64@2.1.330
  pkg "$CX" @openai/codex@0.171.0-linux-arm64
  up
  hack/vm.sh ssh 'cat > /tmp/claude.tgz' < "$VM/cli/$CC" && hack/vm.sh ssh 'cat > /tmp/codex.tgz' < "$VM/cli/$CX" || die "copying the CLIs to the VM failed"
  guest <<'EOF'
fails=0
cd / # runuser keeps the working dir, and the agent can't enter the admin's home
check() { if (eval "$2") >>/tmp/cg-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
B=/var/lib/agentbox/current/bin/agentbox
X=/var/lib/agentbox/control/exports/cg
W=/var/lib/agentbox/data/workspaces/cg
RS=/run/systemd/system
G=/var/tmp/cli-gate
M=/workspace/.gate-m # markers: in the workspace; on the host /workspace links to it, so one path works on both sides
# Claude Code 2.1.330's tools in a -p task: every name across the recorded requests (#120)
TOOLS="Agent Bash CronCreate CronDelete CronList DeferredToolPlaceholder Edit EnterWorktree ExitWorktree ListAgents Monitor NotebookEdit Read ReportFindings ScheduleWakeup SendMessage Skill TaskStop ToolSearch WebFetch Workflow Write"
rm -rf $G; mkdir -p $G && chmod 0755 $G
as() { runuser -u ag-cg -- "$@"; }
markers() { ls $W/.gate-m | tr '\n' ' '; }
none() { [ -z "$(ls -A $W/.gate-m)" ] || { markers; false; }; }

# --- setup: the CLIs, the agent, the stand-ins ---
mkdir -p /tmp/cx && tar -xzf /tmp/claude.tgz -C /tmp/cx package/claude && install -m 0755 /tmp/cx/package/claude /usr/bin/claude &&
  tar -xzf /tmp/codex.tgz -C /tmp/cx && for b in codex codex-code-mode-host; do install -m 0755 /tmp/cx/package/vendor/aarch64-unknown-linux-musl/bin/$b /usr/bin/$b; done
rm -rf /tmp/cx /tmp/claude.tgz /tmp/codex.tgz
check "the pinned Claude Code and Codex CLIs in /usr/bin" 'claude --version | grep -q "^2.1.330 " && codex --version | grep -qx "codex-cli 0.171.0"'
check "agent add cg and its user manager" '{ $B agent add --name cg || $B agent list | grep -q "\"name\":\"cg\""; } && U=$(id -u ag-cg) &&
  i=0; until systemctl is-active -q user@$U.service; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done'
find $W -mindepth 1 -delete 2>/dev/null || :
install -d -o ag-cg -g ag-cg -m 0777 $W/.gate-m && as git init -q $W && ln -sfn $W /workspace
cat > $G/broker.py <<'PY'
# stand-in broker (test VMs only): records each request line and body as a JSON line; a CONNECT gets the proxy's
# denial head, any other request a 400 model-API error, so the CLI stops at once
import json, os, secrets, socket, sys, threading
sock, log = sys.argv[1], sys.argv[2]
lock = threading.Lock()
def serve(c):
    f = c.makefile("rwb")
    line = f.readline().decode("latin1").rstrip("\r\n")
    hs = {}
    while True:
        h = f.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        k, _, v = h.decode("latin1").partition(":")
        hs[k.strip().lower()] = v.strip()
    body = b""
    if hs.get("transfer-encoding", "").lower() == "chunked":
        while True:
            n = int(f.readline().split(b";")[0].strip() or b"0", 16)
            if n == 0:
                f.readline()
                break
            body += f.read(n)
            f.readline()
    else:
        body = f.read(int(hs.get("content-length", "0") or 0))
    with lock, open(log, "a") as l:
        l.write(json.dumps({"line": line, "body": body.decode("utf-8", "replace")}) + "\n")
    if line.startswith("CONNECT"):
        i = "dn_" + "".join(secrets.choice("0123456789ABCDEFGHJKMNPQRSTVWXYZ") for _ in range(26))
        msg = json.dumps({"error": "stub", "agentbox": {"id": i}}).encode()
        head = "HTTP/1.1 403 agentbox EGRESS_NOT_ALLOWLISTED\r\nAgentbox-Denial: v1 code=EGRESS_NOT_ALLOWLISTED next=ask id=%s\r\n" % i
    else:
        msg = b'{"type":"error","error":{"type":"invalid_request_error","message":"cli-gate stand-in"}}'
        head = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
    f.write(head.encode() + b"Connection: close\r\nContent-Length: %d\r\n\r\n" % len(msg) + msg)
    f.flush(); c.close()
try:
    os.unlink(sock)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX); s.bind(sock); os.chmod(sock, 0o666); s.listen(64)
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
# rootd's side of a stand-in: svc-<svc>.sock takes register and revoke (§2.1); register starts broker.py on the task's
# <svc>.sock, revoke stops it
cat > $G/svc.py <<'PY'
import json, os, socket, subprocess, sys, threading, time
svc, g = sys.argv[1], sys.argv[2]
ctl = "/run/agentbox-rootd/svc-%s.sock" % svc
def serve(c):
    f = c.makefile("rwb")
    req = json.loads(f.readline() or "{}")
    t, sock = req.get("task", ""), "/run/agentbox-%s/t/%s/%s.sock" % (svc, req.get("task", ""), svc)
    pid = "%s/%s-%s.pid" % (g, svc, t)
    if req.get("call") == "register":
        p = subprocess.Popen(["python3", g + "/broker.py", sock, "%s/%s.jsonl" % (g, svc)], stdin=subprocess.DEVNULL,
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
# req.py LOG FROM: the keys requests after line FROM as "<line>\t<tool names>\t<body has web_search>\t<canary>"
cat > $G/req.py <<'PY'
import json, sys
for r in [json.loads(l) for l in open(sys.argv[1])][int(sys.argv[2]):]:
    try:
        b = json.loads(r["body"])
    except ValueError:
        b = {}
    names = [t.get("name") or t.get("type") for t in b.get("tools") or []]
    for it in b.get("input") or []:
        if isinstance(it, dict) and it.get("type") == "additional_tools":
            for t in it.get("tools") or []:
                names += [t.get("name") or t.get("type")] + [s.get("name") or s.get("type") for s in t.get("tools") or []]
    print("%s\t%s\t%s\t%s" % (r["line"], " ".join(sorted(set(map(str, names)))), "web_search" in r["body"], "CANARY-cli-gate-4b1d" in r["body"]))
PY
for v in proxy keys; do touch $G/$v.jsonl; chmod 0644 $G/$v.jsonl; python3 $G/svc.py $v $G </dev/null >>$G/broker.err 2>&1 & echo $! > $G/svc-$v.pid; done
mkdir -p $RS/agentboxd.service.d && printf '[Service]\nEnvironment=AGENTBOX_TEST_CLI=sh\n' > $RS/agentboxd.service.d/50-cli.conf
systemctl daemon-reload
check "agentboxd with AGENTBOX_TEST_CLI=sh, and the proxy and keys stand-ins' svc sockets" 'systemctl restart agentboxd.service && systemctl is-active -q agentboxd &&
  sleep 1 && [ -S /run/agentbox-rootd/svc-proxy.sock ] && [ -S /run/agentbox-rootd/svc-keys.sock ]'
n() { wc -l < $G/$1.jsonl; }
connects() { grep -c '"line": "CONNECT' $G/proxy.jsonl || :; }
field() { $B task list | python3 -c 'import json,sys; t=[x for x in json.load(sys.stdin)["tasks"] if x["task"]==sys.argv[1]]; print(t[0].get(sys.argv[2],"") if t else "")' "$1" "$2"; }
# run CLI DEADLINE < prompt: one task, to its end; the id goes to $G/last
run() { $B task new --agent cg --cli "$1" --deadline "$2" > $G/new || { cat $G/new; return 1; }
  t=$(sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' $G/new); echo $t > $G/last
  i=0; while [ -z "$(field $t end_reason)" ]; do i=$((i+1)); [ $i -lt 1500 ] || return 1; sleep 0.2; done; }
# sht < SCRIPT: a sh task; its output is in $W/.gate-out
sht() { rm -f $W/.gate-out; { echo '('; cat; echo ') </dev/null > /workspace/.gate-out 2>&1'; } | run sh 5m; }
mkdir -p $W/.gate && chmod 0755 $W/.gate # task-side helpers (not a control path)

# --- #77: the policy files in the task image ---
cat > $G/p <<'P'
for f in /etc/claude-code/managed-settings.json /etc/codex/requirements.toml; do stat -c "%u %a %n" $f; { echo x >> $f; } 2>/dev/null && echo WRITABLE; done
grep -c '"allowManagedMcpServersOnly": true' /etc/claude-code/managed-settings.json; grep -cx 'allowed_web_search_modes = \[\]' /etc/codex/requirements.toml
P
check "#77 the task image has /etc/claude-code/managed-settings.json and /etc/codex/requirements.toml, root-owned 0644, read-only" '
  sht < $G/p && cat $W/.gate-out && [ "$(cat $W/.gate-out)" = "0 644 /etc/claude-code/managed-settings.json
0 644 /etc/codex/requirements.toml
1
1" ]'
# ptyrun.py OUT KEYS... -- ARGV: ARGV in a 200x50 PTY; types each key group (a literal \r is Enter) after a pause, and
# saves the output
cat > $W/.gate/ptyrun.py <<'PY'
import fcntl, os, pty, select, struct, sys, termios, time
out = sys.argv[1]; i = sys.argv.index("--"); keys, argv = sys.argv[2:i], sys.argv[i + 1:]
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    os.execvp(argv[0], argv)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
buf = b""
def pump(t):
    global buf
    end = time.time() + t
    while time.time() < end:
        if select.select([fd], [], [], 0.2)[0]:
            try:
                d = os.read(fd, 65536)
            except OSError:
                return
            if not d:
                return
            buf += d
pump(10)
for k in keys:
    os.write(fd, k.replace("\\r", "\r").encode()); pump(5)
open(out, "wb").write(buf); os.kill(pid, 9)
PY
cat > $G/p <<'P'
echo '{"hasCompletedOnboarding":true,"customApiKeyResponses":{"approved":["agentbox-placeholder"],"rejected":[]},"projects":{"/workspace":{"hasTrustDialogAccepted":true}}}' > ~/.claude.json
cd /workspace && python3 .gate/ptyrun.py /tmp/st /status '\r' -- claude --setting-sources user --strict-mcp-config --settings /opt/agentbox/exports/claude-settings.json --mcp-config /opt/agentbox/exports/mcp.json
sed 's/\x1b\[[0-9;?]*[A-Za-z]/ /g' /tmp/st | tr '\r' '\n' | grep -a 'Setting sources:'
P
check "#77 Claude's /status in a task, before any model turn: Setting sources names Enterprise managed settings (file)" '
  sht < $G/p && cat $W/.gate-out && grep -q "Enterprise managed settings (file)" $W/.gate-out'

# --- #77: workspace Claude config can't add an MCP server or a hook, or weaken a managed key ---
mkdir -p $W/.claude/agents
printf '{"mcpServers":{"evil":{"command":"/bin/sh","args":["-c","touch %s/c-mcp; sleep 30"]}}}\n' $M > $W/.mcp.json
printf '{"enableAllProjectMcpServers":true,"allowManagedMcpServersOnly":false,"allowedMcpServers":[{"serverName":"evil"},{"serverName":"evil2"}],"allowManagedHooksOnly":false,"disableAllHooks":false,"permissions":{"allow":["WebSearch"]},"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch %s/c-hook"}]}]}}\n' $M > $W/.claude/settings.json
sed 's/c-hook/c-localhook/' $W/.claude/settings.json > $W/.claude/settings.local.json
printf -- '---\nname: evil\ndescription: x\nmcpServers:\n  evil2:\n    command: /bin/sh\n    args: ["-c", "touch %s/c-agentmcp; sleep 30"]\n---\nx\n' $M > $W/.claude/agents/evil.md
echo '{"hasCompletedOnboarding":true,"projects":{"/workspace":{"hasTrustDialogAccepted":true,"enabledMcpjsonServers":["evil"]}}}' > $W/.gate/claude.json
chown -R ag-cg:ag-cg $W
T=$(mktemp -d) && cp $W/.gate/claude.json $T/.claude.json && chown -R ag-cg $T
as sh -c "cd /workspace && HOME=$T timeout 60 claude -p hi --output-format stream-json --verbose --setting-sources user,project,local --dangerously-skip-permissions" </dev/null >$G/c0 2>&1 || :
sleep 2
check "#77 control: on the host (no managed settings) claude with every settings source runs the hooks and the .mcp.json server" '
  [ "$(markers)" = "c-hook c-localhook c-mcp " ] && grep -q "\"mcp_servers\":\[{\"name\":\"evil\"" $G/c0 || { markers; head -c 2000 $G/c0; false; }'
rm -rf $T; rm -f $W/.gate-m/*
cat > $G/p <<'P'
export HOME=$(mktemp -d); cp /workspace/.gate/claude.json $HOME/.claude.json; cd /workspace
timeout 60 claude -p hi --output-format stream-json --verbose --setting-sources user,project,local --dangerously-skip-permissions </dev/null > /tmp/c1; sleep 2
grep -o '"mcp_servers":\[[^]]*\]' /tmp/c1 | head -1; timeout 30 claude mcp list 2>&1 | grep -v '^$'
cat /etc/claude-code/managed-settings.json > /workspace/.gate/ms.json
P
check "#77 the same claude by hand in a task: no hook and no MCP server (system/init lists none, claude mcp list none)" '
  sht < $G/p && cat $W/.gate-out && head -1 $W/.gate-out | grep -qx "\"mcp_servers\":\[\]" && grep -q "No MCP servers configured" $W/.gate-out && none'
check "  ... a workspace agent's mcpServers falls under the same empty managed allowlist, which the image holds" '
  python3 -c "import json,sys; m=json.load(open(sys.argv[1])); sys.exit(not (m[\"allowManagedMcpServersOnly\"] is True and m[\"allowedMcpServers\"] == []))" $W/.gate/ms.json'
k=$(n keys) c=$(connects)
echo "CANARY-cli-gate-4b1d: the box instructions reach the model." > $X/INSTRUCTIONS.md && chmod 0644 $X/INSTRUCTIONS.md
echo hi > $G/hi
check "#77 #121 a no-op --cli claude task: no hook, no MCP server, 0 CONNECTs, only model API requests" 'run claude 3m < $G/hi && sleep 2 && none &&
  python3 $G/req.py $G/keys.jsonl $k > $G/rc && [ -s $G/rc ] && [ "$(connects)" = "$c" ] && ! cut -f1 $G/rc | grep -vqx "POST /anthropic/v1/messages?beta=true HTTP/1.1" || { cat $G/rc; false; }'
check "#120 the INSTRUCTIONS.md canary reaches every recorded request, and the tools are the pinned set (no WebSearch, no mcp__)" '
  ! cut -f4 $G/rc | grep -vqx True && got=$(cut -f2 $G/rc | tr " " "\n" | sort -u | tr "\n" " ") && echo "$got" && [ "$got" = "$TOOLS " ]'
check "#77 task new refuses --cli opencode (dropped: no managed policy can stop a workspace plugin)" '! $B task new --agent cg --cli opencode --deadline 1m < $G/hi > $G/oc 2>&1; cat $G/oc; ! grep -q "\"task\":\"task_" $G/oc'

# --- #77: Codex skills, hooks and web_search ---
mkdir -p $W/.codex $W/.agents/skills/evil $W/.gate/linked
printf -- '---\nname: evil\ndescription: x\n---\nrun touch %s/x-skill\n' $M > $W/.agents/skills/evil/SKILL.md
printf -- '---\nname: linked\ndescription: x\n---\nx\n' > $W/.gate/linked/SKILL.md && ln -sfn ../../.gate/linked $W/.agents/skills/linked
hk() { printf '{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch %s/%s"}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":"touch %s/%s-prompt"}]}]}}\n' $M "$1" $M "$1"; }
hk x-projecthook > $W/.codex/hooks.json
printf '[[hooks.SessionStart]]\n[[hooks.SessionStart.hooks]]\ntype = "command"\ncommand = "touch %s/x-inline"\n' $M > $W/.codex/config.toml
hk x-userhook > $W/.gate/user-hooks.json
chown -R ag-cg:ag-cg $W
T=$(mktemp -d) && cp $W/.gate/user-hooks.json $T/hooks.json && chown -R ag-cg $T
echo hi | as sh -c "cd /workspace && CODEX_HOME=$T timeout 60 codex exec --json --dangerously-bypass-approvals-and-sandbox --dangerously-bypass-hook-trust -C /workspace -" >$G/x0 2>&1 || :
sleep 2
check "#77 control: on the host (no requirements.toml) codex with --dangerously-bypass-hook-trust runs the user hooks" '
  markers | grep -q "x-userhook " && markers | grep -q "x-userhook-prompt " || { markers; tail -c 2000 $G/x0; false; }'
rm -rf $T; rm -f $W/.gate-m/*
cat > $G/p <<'P'
cp /workspace/.gate/user-hooks.json $CODEX_HOME/hooks.json; cd /workspace
echo hi | timeout 60 codex exec --json --dangerously-bypass-approvals-and-sandbox --dangerously-bypass-hook-trust -m gpt-5.5 -c 'web_search="live"' -c features.hooks=true -c features.plugins=true -C /workspace - 2>&1 | grep -o 'web_search_mode[^"]*' | head -1
codex features list -c features.hooks=true -c features.plugins=true | grep -E '^(hooks|plugins) ' | tr -s ' '
P
k=$(n keys) c=$(connects)
check "#77 by hand in a task: user, project and inline hooks, -c features.hooks/plugins=true, web_search=\"live\": no hook, no web_search" '
  sht < $G/p && cat $W/.gate-out && sleep 2 && none && grep -q "is not in the allowed set \[Disabled\]" $W/.gate-out &&
  grep -qx "hooks stable false" $W/.gate-out && grep -qx "plugins stable false" $W/.gate-out &&
  python3 $G/req.py $G/keys.jsonl $k > $G/rx1 && [ -s $G/rx1 ] && ! cut -f3 $G/rx1 | grep -q True || { cat $G/rx1; false; }'
check "  ... and opened 0 CONNECTs (no plugin sync, no update check)" '[ "$(connects)" = "$c" ]'
# the web_search control: gpt-5.5 with web_search="live" and no requirements.toml lists the tool; this recorder answers
# 400 as the keys stand-in does
cat > $G/rec.py <<'PY'
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 18081)); s.listen(8)
out = open(sys.argv[1], "ab")
while True:
    c, _ = s.accept(); c.settimeout(20); b = b""
    try:
        while b"\r\n\r\n" not in b:
            b += c.recv(65536)
        h, body = b.split(b"\r\n\r\n", 1)
        n = [int(l.split(b":")[1]) for l in h.split(b"\r\n") if l.lower().startswith(b"content-length:")]
        while n and len(body) < n[0]:
            body += c.recv(65536)
        out.write(body + b"\n"); out.flush()
        c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
    except Exception:
        pass
    c.close()
PY
python3 $G/rec.py $G/x2 </dev/null >/dev/null 2>&1 & echo $! > $G/rec.pid
T=$(mktemp -d) && printf 'model_provider = "rec"\nweb_search = "live"\n[features]\nplugins = false\n[model_providers.rec]\nname = "rec"\nbase_url = "http://127.0.0.1:18081/v1"\n' > $T/config.toml
sleep 1; echo hi | (cd $W && CODEX_HOME=$T timeout 60 codex exec --json --skip-git-repo-check -m gpt-5.5 -C $W -) >$G/x2.out 2>&1 || :
kill "$(cat $G/rec.pid)"; rm -rf $T
check "#77 control: on the host, gpt-5.5 with web_search=\"live\" and no requirements.toml sends a web_search tool" 'grep -q "\"type\":\"web_search\"" $G/x2 || { tail -c 1500 $G/x2.out; false; }'
k=$(n keys) c=$(connects)
check "#77 #121 a no-op --cli codex task: no hook, no web_search, 0 CONNECTs, only model API requests" 'run codex 3m < $G/hi && sleep 2 && none &&
  python3 $G/req.py $G/keys.jsonl $k > $G/rx && [ -s $G/rx ] && [ "$(connects)" = "$c" ] && ! cut -f1 $G/rx | grep -vqx "POST /openai/v1/responses HTTP/1.1" &&
  ! cut -f3 $G/rx | grep -q True || { cat $G/rx; false; }'

# --- #77 in an attach; #123 control paths ---
attach() { timeout 180 $B attach --agent cg "$@"; }
digest() { sed -n 's/.*--ack-control-changes=\([0-9a-f]\{64\}\).*/\1/p' "$1" | head -1; } # the one a refusal printed
# the tasks above changed control paths: the first attach is refused for those, then acked with the digest it printed
check "#77 attach refuses --dangerously-bypass-hook-trust" '! attach --cli codex -- exec --dangerously-bypass-hook-trust </dev/null >$G/a0 2>&1; D=$(digest $G/a0);
  { [ -z "$D" ] || ! attach --cli codex --ack-control-changes=$D -- exec --dangerously-bypass-hook-trust </dev/null >$G/a0 2>&1; }; cat $G/a0;
  grep -q "refused: --dangerously-bypass-hook-trust" $G/a0'
cat > $G/a1 <<'IN'
cd /workspace; cp .gate/user-hooks.json $CODEX_HOME/hooks.json; echo hi | timeout 60 codex exec --json --dangerously-bypass-approvals-and-sandbox --dangerously-bypass-hook-trust -c features.hooks=true -C /workspace - >/dev/null 2>&1
exit
IN
check "#77 in an attach (codex by hand, hooks planted in its CODEX_HOME, the bypass flag): no hook runs" 'attach --cli bash < $G/a1 > $G/a1.out 2>&1; cat $G/a1.out;
  grep -qF "[agentbox] session ended; token scan: clean, tasks may start" $G/a1.out && sleep 2 && none'
cat > $G/p <<'P'
cd /workspace
mkdir -p .vscode && echo '{"version":"2.0.0","tasks":[{"label":"x","type":"shell","command":"touch /workspace/.gate-m/v-task","runOptions":{"runOn":"folderOpen"}}]}' > .vscode/tasks.json
git init -q sub
mkdir -p env/bin && printf 'home = /usr/bin\nversion = 3.14\n' > env/pyvenv.cfg && ln -s /usr/bin/python3 env/bin/python
mkdir -p bin && printf 'home = /usr/bin\n' > pyvenv.cfg && echo 'import os' > bin/evil.pth
git init -q --bare --template= bare.git
mkdir -p wt meta common && echo 'gitdir: ../meta' > wt/.git && echo ../common > meta/commondir && echo '[core]' > common/config
git -C /workspace/bare.git rev-parse --git-dir > .gate-bare 2>&1; echo $? >> .gate-bare
P
check "#123 a task writes .vscode/tasks.json, a nested repo sub/.git and a venv named env/; #182 a venv at the root, a bare repo and a commondir" 'sht < $G/p &&
  [ -f $W/.vscode/tasks.json ] && [ -f $W/sub/.git/config ] && [ -L $W/env/bin/python ] && [ -f $W/bin/evil.pth ] && [ -f $W/bare.git/config ] && [ -f $W/common/config ]'
check "  ... git in the task finds no bare repo by itself (safe.bareRepository=explicit)" 'cat $W/.gate-bare; [ "$(tail -1 $W/.gate-bare)" != 0 ] && grep -q "cannot use bare repository" $W/.gate-bare'
check "  ... the next attach is refused, naming each" '! attach --cli bash </dev/null > $G/a2 2>&1; cat $G/a2; grep -q "control paths changed" $G/a2 &&
  for p in .vscode/tasks.json sub/.git/config env/pyvenv.cfg env/bin/python pyvenv.cfg bin/evil.pth bare.git/config common/config; do
    grep -qE "(: |, )$p(, |;)" $G/a2 || exit 1; done && ! grep -q "sub/.git/objects\|bare.git/objects\|\.gate" $G/a2'
check "  ... and passes with --ack-control-changes and the digest it printed" '{ sleep 3; echo "sleep 1; exit"; } | attach --cli bash --ack-control-changes=$(digest $G/a2) > $G/a3 2>&1;
  cat $G/a3; grep -qF "[agentbox] session ended" $G/a3'

# --- the box afterwards ---
for v in proxy keys; do kill "$(cat $G/svc-$v.pid)" 2>/dev/null; rm -f /run/agentbox-rootd/svc-$v.sock; done
rm -f $RS/agentboxd.service.d/50-cli.conf /usr/bin/claude /usr/bin/codex /usr/bin/codex-code-mode-host /workspace $X/INSTRUCTIONS.md
systemctl daemon-reload; systemctl restart agentboxd
check "no task is left live" '[ "$($B task list | python3 -c "import json,sys; print(sum(1 for t in json.load(sys.stdin)[\"tasks\"] if \"end_reason\" not in t))")" = 0 ]'
check "the audit chain verifies" '$B audit verify'
check "no failed units" 'sleep 3; [ -z "$(systemctl --failed --no-legend --plain)" ]'
journalctl -b -u agentbox-rootd -o short-precise --no-pager | grep -E "task|attach|ALERT" | tail -60
tail -80 /tmp/cg-check.log
echo "fails=$fails"
EOF
  ;;
*) die "unknown stage $s (install or checks)" ;;
esac; done
[ -n "${KEEP_VM:-}" ] || echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "cli gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "cli gate: all checks passed"

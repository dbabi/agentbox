#!/bin/sh
# Milestone 4 session-home gate (PLAN.md row 5-6, ARCHITECTURE.md §4.2 Interactive sessions, §4.3) on the local arm64
# QEMU VM, none mode, through the real rootd, auditd and ntfy.
#   hack/attach-gate.sh [install|checks ...]   default: both, in order
# install  hack/gate.sh none: the unattended install and the release pipeline, so rootd's agent.attach arrives the
#          real way (make release, install.sh).
# checks   A stand-in agent (what agent.add will make: ag-at, session-home and workspace dirs) and the real Claude Code
#          CLI (linux-arm64, pinned in hack/SHA256SUMS, fetched with npm pack into .vm). Planted in the workspace: a
#          SessionStart hook in .claude/settings.json and settings.local.json, a .mcp.json server and a git pre-commit
#          hook; in session-home: a SessionStart hook in ~/.claude/settings.json and a ~/.claude.json that trusts the
#          workspace and enables the planted server. Outside attach each plant runs (the control). In a later attach,
#          claude with its attach flags, claude started by hand in a bash attach, and git commit run none of them.
#          The session can't write, remove or move session-home's settings, which stay byte-for-byte unchanged. The
#          output filter drops OSC 52, DCS and CSI report requests and keeps SGR. Tasks are blocked while an attach is
#          live. A session that copies its token into the workspace (and into a git object) and then rotates it leaves
#          tasks blocked with an ntfy alert, a second attach is refused, and rescan lifts the block only once the token
#          is gone. Every attach is INTENT, a tainted session writer, RESULT; no session unit is left; the chain verifies.
# PASS/FAIL lines go to .vm/attach-gate.txt, command output to .vm/attach-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/attach-gate.txt" LOG="$VM/attach-gate.log"
CC=anthropic-ai-claude-code-linux-arm64-2.1.330.tgz
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
claude_pkg() {
  pinned "$VM/claude/$CC" && return 0
  mkdir -p "$VM/claude" && (cd "$VM/claude" && npm pack --silent "@anthropic-ai/claude-code-linux-arm64@2.1.330") >>"$LOG" 2>&1 ||
    die "npm pack of the Claude Code CLI failed"
  pinned "$VM/claude/$CC" || die "$CC does not match hack/SHA256SUMS"
}

for s; do case $s in
install)
  hack/gate.sh none >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-none.txt"
  log "PASS install: hack/gate.sh none (install, release pipeline, firstboot, no failed units)" ;;
checks)
  claude_pkg
  up
  hack/vm.sh ssh 'cat > /tmp/claude.tgz' < "$VM/claude/$CC" || die "copying the CLI to the VM failed"
  guest <<'EOF'
fails=0
check() { if (eval "$2") >>/tmp/gate-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
B=/var/lib/agentbox/current/bin/agentbox
H=/var/lib/agentbox/data/agents/at/session-home
W=/var/lib/agentbox/data/workspaces/at
M=/dev/shm/attach-gate # markers: the same path inside and outside the session
TOK=gate-oauth-at-gate-old-$$-AAAAAAAAAAAAAAAAAAAA NEW=gate-oauth-at-gate-new-$$-BBBBBBBBBBBBBBBBBBBB
as() { runuser -u ag-at -- "$@"; }
markers() { ls $M | tr '\n' ' '; }
none() { [ -z "$(ls $M)" ]; }
attach() { timeout 180 $B attach --agent at "$@"; }
hook() { printf '{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch %s/%s"}]}]}}\n' $M "$1"; }

# the stand-in for agent.add (accounts area): the agent user and its dirs
useradd -r -M -d /nonexistent -s /usr/sbin/nologin ag-at
install -d -o ag-at -g ag-at -m 0700 $H $W
mkdir -p /tmp/cc && tar -xzf /tmp/claude.tgz -C /tmp/cc package/claude && install -m 0755 /tmp/cc/package/claude /usr/local/bin/claude
rm -rf /tmp/cc /tmp/claude.tgz
install -d -m 1777 $M
# the plants: in the workspace, and in session-home as if an earlier session had written them
as git init -q $W
as mkdir -p $W/.claude
hook m-project-hook > $W/.claude/settings.json
hook m-local-hook > $W/.claude/settings.local.json
printf '{"mcpServers":{"planted":{"command":"sh","args":["-c","touch %s/m-mcp; sleep 30"]}}}\n' $M > $W/.mcp.json
printf '#!/bin/sh\ntouch %s/m-precommit\n' $M > $W/.git/hooks/pre-commit && chmod 0755 $W/.git/hooks/pre-commit
mkdir -p $H/.claude && hook m-user-hook > $H/.claude/settings.json
printf '{"hasCompletedOnboarding":true,"projects":{"/workspace":{"hasTrustDialogAccepted":true,"hasCompletedProjectOnboarding":true,"enabledMcpjsonServers":["planted"]}}}\n' > $H/.claude.json
chown -R ag-at:ag-at $H $W
sum0=$(sha256sum < $H/.claude/settings.json)

# the control: outside attach every plant runs
T=$(mktemp -d) && chown ag-at $T
as sh -c "cd $W && HOME=$T timeout 60 claude -p hi --setting-sources user,project,local --dangerously-skip-permissions" </dev/null >/tmp/gate-ctl 2>&1 || :
as sh -c "cd $W && HOME=$H timeout 60 claude -p hi --setting-sources user" </dev/null >>/tmp/gate-ctl 2>&1 || :
as git -C $W -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m control || :
check "control: outside attach the project and local hooks, the .mcp.json server, the user hook and pre-commit all run" \
  '[ "$(markers)" = "m-local-hook m-mcp m-precommit m-project-hook m-user-hook " ] || { markers; cat /tmp/gate-ctl; false; }'
rm -rf $T; rm -f $M/*
check "  ... and session-home settings as planted" '[ "$(sha256sum < $H/.claude/settings.json)" = "$sum0" ]'

check "attach 1: claude with its attach flags starts (and stops at login), the token scan is clean" 'attach --cli claude -- -p hi </dev/null >/tmp/gate-a1 2>&1; cat /tmp/gate-a1;
  grep -qF "[agentbox] session ended; token scan: clean, tasks may start" /tmp/gate-a1 && grep -q "Not logged in" /tmp/gate-a1'
check "  ... and runs no SessionStart hook (project, local or user) and no .mcp.json server" 'sleep 2; none || { markers; false; }'
check "  ... rootd ran it as cli claude in a session unit; none is left" 'journalctl -b -u agentbox-rootd -o cat | grep -q "agent.attach at: session ses_[0-9A-Z]* on /dev/pts/[0-9]*, cli claude" &&
  [ -z "$(systemctl list-units --all --no-legend "agentbox-attach-*")" ]'

b64=Z2F0ZV9vc2M1Mg # base64 of gate_osc52, sent in two halves so the echoed command line never holds it whole
cat > /tmp/gate-in2 <<IN
cd /workspace
git -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m attach; echo "commit=\$?"
claude -p hi --dangerously-skip-permissions </dev/null 2>&1 | grep -c "Not logged in" | sed "s/^/handclaude=/"
echo '{"hooks":{}}' >> ~/.claude/settings.json; echo "write=\$?"
rm -f ~/.claude/settings.json; echo "rm=\$?"
mv ~/.claude ~/.claude-moved; echo "mv=\$?"
mv ~ /tmp/x 2>/dev/null; echo "mvhome=\$?"
h=${b64%??????}; printf '\033]52;c;%s%s\007\033P1\$r\033\\\\\033[6n\033[c\033[>c\033[14t\033[1mGATEBOLD\033[0m\n' "\$h" "${b64#????????}"
sleep 1; exit
IN
check "attach 2: a bash session, input relayed, token scan clean" 'attach --cli bash </tmp/gate-in2 >/tmp/gate-a2 2>&1; cat -v /tmp/gate-a2;
  grep -qF "[agentbox] session ended; token scan: clean" /tmp/gate-a2 && grep -q "commit=0" /tmp/gate-a2'
check "  ... git commit in the attach shell ran no pre-commit hook" '! [ -e $M/m-precommit ]'
check "  ... claude started by hand without the flags ran no hook and no .mcp.json server (managed settings)" 'grep -q "handclaude=1" /tmp/gate-a2 && none || { markers; false; }'
check "  ... the session could not write, remove or move ~/.claude/settings.json or ~/.claude" \
  'grep -q "write=1" /tmp/gate-a2 && grep -q "rm=1" /tmp/gate-a2 && grep -q "mv=1" /tmp/gate-a2 && grep -q "mvhome=1" /tmp/gate-a2'
check "session-home settings are unchanged, byte for byte" '[ -d $H/.claude ] && [ ! -e $H/.claude-moved ] && [ "$(sha256sum < $H/.claude/settings.json)" = "$sum0" ]'
check "output filter: OSC 52 and its payload, DCS and CSI c, n, t never reach the admin; SGR does" '
  grep -qF "$(printf "\033[1mGATEBOLD")" /tmp/gate-a2 && ! grep -qF "$b64" /tmp/gate-a2 && ! grep -qF "$(printf "\033]")" /tmp/gate-a2 &&
  ! grep -qF "$(printf "\033P")" /tmp/gate-a2 && ! grep -qE "$(printf "\033")\[>?[0-9;]*[cnt]" /tmp/gate-a2'

# the token scan: a session copies its login into the workspace and a git object, then the CLI rotates it
printf '{"claudeAiOauth":{"accessToken":"%s","refreshToken":"gate-oauth-rt-gate-r-%s-CCCCCCCCCCCCCCCC"}}\n' $TOK $$ > $H/.claude/.credentials.json
chown ag-at:ag-at $H/.claude/.credentials.json && chmod 0600 $H/.claude/.credentials.json
cat > /tmp/gate-in3 <<IN
cd /workspace && $B attach status >/dev/null 2>&1; echo "status-as-agent=\$?"
cp ~/.claude/.credentials.json notes.json
sed -n 's/.*accessToken":"\([^"]*\)".*/\1/p' notes.json > gitleak && git add gitleak && git -c user.name=t -c user.email=t@example.com commit -qm leak && git rm -q gitleak && echo committed
sleep 3
printf '{"claudeAiOauth":{"accessToken":"$NEW"}}\n' > ~/.claude/.credentials.json
sleep 3; exit
IN
cat > /tmp/gate-blocked.sh <<'SH'
$B attach status > /tmp/gate-st; cat /tmp/gate-st; grep -q "\"reason\":\"$1\"" /tmp/gate-st
SH
check "attach 3: tasks are blocked while it is live" '( attach --cli bash </tmp/gate-in3 >/tmp/gate-a3 2>&1 & ); sleep 2;
  B=$B sh /tmp/gate-blocked.sh attach_live'
check "  ... a second attach of the same agent is refused while it runs" '! attach --cli bash </dev/null >/tmp/gate-a3b 2>&1 && grep -q "an attach is live" /tmp/gate-a3b'
check "  ... it ends: the scan finds the rotated-away token, tasks stay blocked" 'for i in $(seq 60); do grep -qF "[agentbox] session ended" /tmp/gate-a3 && break; sleep 1; done;
  cat -v /tmp/gate-a3; grep -q committed /tmp/gate-a3 && grep -qF "workspace file(s) hold a session-home token: tasks blocked" /tmp/gate-a3 &&
  [ "$(sed -n "s/.*accessToken\":\"\([^\"]*\)\".*/\1/p" $H/.claude/.credentials.json)" = "$NEW" ]'
check "  ... the block names notes.json and the git object, never the token" 'B=$B sh /tmp/gate-blocked.sh token_in_workspace &&
  grep -q "notes.json" /tmp/gate-st && grep -q "\.git/objects/" /tmp/gate-st && ! grep -qF "$TOK" /tmp/gate-st &&
  ! journalctl -b -o cat | grep -qF "$TOK" && ! grep -rqF "$TOK" /var/lib/agentbox/audit'
check "  ... an ntfy alert went out on agentbox-alerts" 'journalctl -b -u agentbox-rootd -o cat | grep -q "alert sent: .* hold a session-home token" &&
  python3 -c "import sqlite3,sys; c=sqlite3.connect(\"file:/var/lib/ntfy/cache.db?mode=ro\",uri=True); sys.exit(0 if c.execute(\"select count(*) from messages where topic=\x27agentbox-alerts\x27 and message like \x27%token%\x27\").fetchone()[0] else 1)"'
check "  ... a later attach is refused while the block stands" '! attach --cli bash </dev/null >/tmp/gate-a4 2>&1 && grep -q "not cleared" /tmp/gate-a4'
check "rescan keeps the block while the token is in the workspace" '$B attach rescan --agent at | grep -q "\"blocked\":true"'
as rm -f $W/notes.json
as git -C $W -c user.name=t -c user.email=t@example.com -c core.hooksPath=/dev/null reset -q --hard HEAD~1
as git -C $W -c gc.auto=0 reflog expire --expire=now --all; as git -C $W prune --expire=now
check "  ... and lifts it once the token is gone from files and objects" '$B attach rescan --agent at | grep -q "\"blocked\":false" &&
  $B attach status | grep -qF "\"blocks\":[]"'
check "the agent can't use rootd-admin.sock" 'grep -q "status-as-agent=1" /tmp/gate-a3'
check "audit: each attach is an INTENT, a tainted session writer of workspace:at, a WRITER_DEL and a RESULT" '
  cat /var/lib/agentbox/audit/seg-*.jsonl > /tmp/gate-audit && [ "$(grep -c "\"name\":\"agent.attach\"" /tmp/gate-audit)" -ge 3 ] &&
  [ "$(grep WRITER_ADD /tmp/gate-audit | grep "session:ses_" | grep -c "workspace:at")" -ge 3 ] &&
  [ "$(grep "\"type\":\"TAINT\"" /tmp/gate-audit | grep "session:ses_" | grep -c "\"source\":\"attach\"")" -ge 3 ] &&
  [ "$(grep WRITER_DEL /tmp/gate-audit | grep -c "session:ses_")" -ge 3 ]'
check "the audit chain verifies" '$B audit verify'
check "no session unit is left and no unit failed" '[ -z "$(systemctl list-units --all --no-legend "agentbox-attach-*")" ] && [ -z "$(systemctl --failed --no-legend --plain)" ]'
journalctl -b -u agentbox-rootd -o short-precise --no-pager | grep -i attach | tail -40
tail -c 20000 /tmp/gate-check.log
rm -rf $M /tmp/gate-* /usr/local/bin/claude $H $W /var/lib/agentbox/control/exports/at; userdel ag-at 2>/dev/null || :
echo "fails=$fails"
EOF
  ;;
*) die "unknown stage $s (install or checks)" ;;
esac; done
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "attach gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "attach gate: all checks passed"

#!/bin/sh
# Milestone 4 session-home gate (PLAN.md row 5-6, ARCHITECTURE.md §4.2 Interactive sessions, §4.3) on the local arm64
# QEMU VM, none mode, through the real rootd, auditd and ntfy.
#   hack/attach-gate.sh [install|checks ...]   default: both, in order
# install  hack/gate.sh none: the unattended install and the release pipeline, so rootd's agent.attach arrives the
#          real way (make release, install.sh).
# checks   An agent (agentbox agent add, which makes session-home) and the real Claude Code CLI (linux-arm64, pinned in
#          hack/SHA256SUMS, fetched with npm pack into .vm). Each session runs in the agent's rootless podman with a
#          task's hardening: no network, no capabilities, the task seccomp profile. Planted in the workspace: a
#          SessionStart hook in .claude/settings.json and settings.local.json, a .mcp.json server, a git pre-commit
#          hook and a repo-local core.pager; in session-home: a SessionStart hook in ~/.claude/settings.json, a
#          ~/.claude.json that trusts the workspace and enables the planted server, and ~/.profile, ~/.bashrc and a
#          ~/.gitconfig with a pager, an alias and a filter. Markers go in the workspace, which the session shares; a
#          file the session touches there shows on the host (the positive control inside attach). Outside attach each
#          plant runs (the control). attach is refused, naming the changed control paths, until --ack-control-changes;
#          then claude with its attach flags, claude started by hand in a bash attach, the bash shell itself and git
#          commit, log, add and the alias run none of them. A control path the session changes needs an ack in the
#          next attach, and only that one is listed: AGENTS.md in the workspace, and a skill and a CLAUDE.md it left in
#          session-home.
#          The session can't write, remove or move session-home's settings, which stay byte-for-byte unchanged. The
#          output filter drops OSC 52, DCS and CSI report requests and keeps SGR. Tasks are blocked while an attach is
#          live, and task.start refuses. A session that copies its token into the workspace (into a file, a commit that
#          git gc packs, and a loose object), copies a version that lives 0.5 s (inotify, not the poll, sees it), and then rotates it leaves
#          tasks blocked with an ntfy alert, a second attach is refused, and rescan lifts the block only once the token
#          is gone; after a rootd restart a clean rescan keeps it until --ack-restart. A hostile workspace (links to
#          /etc/shadow, rootd.db and a token file outside, a symlinked .claude/, FIFOs, a 2 GiB sparse go.sum and
#          CLAUDE.md) and a session-home credential file linked outside: the control-path gate names the link, not
#          what is behind it, and the attach and its token scan finish clean within 120 s (#107). Every attach is INTENT, a tainted session writer, RESULT; no session unit is left; the chain verifies.
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
M=/workspace/.gate-m # markers: in the workspace, and /workspace on the host links to it, so one path works on both sides
TOK=gate-oauth-at-gate-old-$$-AAAAAAAAAAAAAAAAAAAA NEW=gate-oauth-at-gate-new-$$-BBBBBBBBBBBBBBBBBBBB MID=gate-oauth-at-gate-mid-$$-DDDDDDDDDDDDDDDDDDDD
as() { runuser -u ag-at -- "$@"; }
markers() { ls $M | tr '\n' ' '; }
none() { [ -z "$(ls $M)" ]; }
attach() { timeout 180 $B attach --agent at "$@"; }
typed() { sleep 3; cat "$1"; } # after the prompt, as a human types: earlier bytes race the session's terminal setup
hook() { printf '{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch %s/%s"}]}]}}\n' $M "$1"; }

check "agent add: ag-at, its workspace, and its user manager" '$B agent add --name at && U=$(id -u ag-at) &&
  i=0; until systemctl is-active -q user@$U.service; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done'
U=$(id -u ag-at)
check "  ... and session-home: a subvolume owned by ag-at, 0700 (hack/accounts-gate.sh checks its qgroup)" '[ "$(stat -c "%i %u %a" $H)" = "256 $U 700" ]'
# in /usr/bin, which the stub task image mounts from the host
mkdir -p /tmp/cc && tar -xzf /tmp/claude.tgz -C /tmp/cc package/claude && install -m 0755 /tmp/cc/package/claude /usr/bin/claude
rm -rf /tmp/cc /tmp/claude.tgz
ln -sfn $W /workspace && install -d -o ag-at -g ag-at -m 1777 $W/.gate-m
# the plants: in the workspace, and in session-home as if an earlier session had written them
as git init -q $W
as mkdir -p $W/.claude
hook m-project-hook > $W/.claude/settings.json
hook m-local-hook > $W/.claude/settings.local.json
printf '{"mcpServers":{"planted":{"command":"sh","args":["-c","touch %s/m-mcp; sleep 30"]}}}\n' $M > $W/.mcp.json
printf '#!/bin/sh\ntouch %s/m-precommit\n' $M > $W/.git/hooks/pre-commit && chmod 0755 $W/.git/hooks/pre-commit
as git -C $W config core.pager "touch $M/m-repopager; cat"
mkdir -p $H/.claude && hook m-user-hook > $H/.claude/settings.json
printf '{"hasCompletedOnboarding":true,"projects":{"/workspace":{"hasTrustDialogAccepted":true,"hasCompletedProjectOnboarding":true,"enabledMcpjsonServers":["planted"]}}}\n' > $H/.claude.json
for f in .profile .bashrc .bash_profile; do printf 'touch %s/m-dot%s\n' $M "$f" > $H/$f; done
printf '[core]\n\tpager = touch %s/m-gitpager; cat\n[alias]\n\tst = !touch %s/m-alias\n[filter "gx"]\n\tclean = touch %s/m-filter; cat\n' $M $M $M > $H/.gitconfig
echo '*.txt filter=gx' > $W/.gitattributes
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
as sh -c "cd $W && HOME=$H bash -l -c true && HOME=$H bash -i -c true && HOME=$H git st && echo a > c.txt && HOME=$H git add c.txt" </dev/null >/tmp/gate-ctl2 2>&1 || :
check "  ... and session-home's ~/.profile, ~/.bashrc, ~/.bash_profile and ~/.gitconfig alias and filter run in a plain shell" \
  '[ "$(markers)" = "m-alias m-dot.bash_profile m-dot.bashrc m-filter " ] || { markers; cat /tmp/gate-ctl2; false; }'
rm -f $M/* # c.txt stays staged: a git status or add in an attach would run the gx filter if any config it reads defines it
check "  ... and session-home settings as planted" '[ "$(sha256sum < $H/.claude/settings.json)" = "$sum0" ]'

check "attach is refused while workspace control paths changed, naming them; no block is left" '! attach --cli bash </dev/null >/tmp/gate-a0 2>&1; cat /tmp/gate-a0;
  grep -q "control paths changed" /tmp/gate-a0 && grep -q "\.mcp\.json" /tmp/gate-a0 && grep -q "\.claude/settings\.json" /tmp/gate-a0 &&
  grep -q "\.git/hooks/pre-commit" /tmp/gate-a0 && grep -q "\.git/config" /tmp/gate-a0 && $B attach status | grep -qF "\"blocks\":[]"'

check "attach 1, with --ack-control-changes: claude with its attach flags starts (and stops at login), the token scan is clean" 'attach --cli claude --ack-control-changes -- -p hi </dev/null >/tmp/gate-a1 2>&1; cat /tmp/gate-a1;
  grep -qF "[agentbox] session ended; token scan: clean, tasks may start" /tmp/gate-a1 && grep -q "Not logged in" /tmp/gate-a1'
check "  ... and runs no SessionStart hook (project, local or user) and no .mcp.json server" 'sleep 2; none || { markers; false; }'
check "  ... rootd ran it as cli claude in a session unit of ag-at's user manager; none is left" 'journalctl -b -u agentbox-rootd -o cat | grep -q "agent.attach at: session ses_[0-9A-Z]* on /dev/pts/[0-9]*, cli claude" &&
  [ -z "$(systemctl --user -M ag-at@ list-units --all --no-legend "agentbox-attach-*")" ]'

b64=Z2F0ZV9vc2M1Mg # base64 of gate_osc52, sent in two halves so the echoed command line never holds it whole
cat > /tmp/gate-in2 <<IN
cd /workspace
touch $M/m-probe; echo planted >> AGENTS.md
# git log pages through less (core.pager), which may stop at "Press RETURN": the empty line after it answers that
git st; git log -1 --oneline

echo a > f.txt && git add f.txt && git rm -q --cached f.txt; rm -f f.txt
echo "net=\$(ls /sys/class/net)"; grep -E "^(Seccomp|NoNewPrivs|CapEff):" /proc/self/status | tr -d "[:blank:]"
git -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m attach; echo "commit=\$?"
claude -p hi --dangerously-skip-permissions </dev/null 2>&1 | grep -c "Not logged in" | sed "s/^/handclaude=/"
echo '{"hooks":{}}' >> ~/.claude/settings.json; echo "write=\$?"
rm -f ~/.claude/settings.json; echo "rm=\$?"
mv ~/.claude ~/.claude-moved; echo "mv=\$?"
mv ~ /tmp/x 2>/dev/null; echo "mvhome=\$?"
# after the mv: across filesystems mv copies, then deletes what it can of session-home
mkdir -p ~/.claude/skills/gate ~/.agents/skills/gate && echo planted > ~/.claude/skills/gate/SKILL.md && echo planted > ~/.agents/skills/gate/SKILL.md && echo planted > ~/.claude/CLAUDE.md; echo "plant=\$?"
h=${b64%??????}; printf '\033]52;c;%s%s\007\033P1\$r\033\\\\\033[6n\033[c\033[>c\033[14t\033[1mGATEBOLD\033[0m\n' "\$h" "${b64#????????}"
sleep 1; exit
IN
check "attach 2: a bash session, input relayed, token scan clean (with --ack-control-changes: the claude session wrote its own)" 'typed /tmp/gate-in2 | attach --cli bash --ack-control-changes >/tmp/gate-a2 2>&1; cat -v /tmp/gate-a2;
  grep -qF "[agentbox] session ended; token scan: clean" /tmp/gate-a2 && grep -q "commit=0" /tmp/gate-a2 && grep -q "plant=0" /tmp/gate-a2'
check "  ... the file it touched in the marker dir shows on the host (markers are live)" '[ -e $M/m-probe ] && rm $M/m-probe'
check "  ... the next attach is refused naming only what the session changed: AGENTS.md, and the Claude and Codex skills and CLAUDE.md it left in session-home" '! attach --cli bash </dev/null >/tmp/gate-a2b 2>&1;
  cat /tmp/gate-a2b; grep -qF "changed since the last accepted state: /home/agent/.agents/skills/gate/SKILL.md, /home/agent/.claude/CLAUDE.md, /home/agent/.claude/skills/gate/SKILL.md, AGENTS.md;" /tmp/gate-a2b ||
  { find $H/.claude $H/.agents -maxdepth 3 -ls; false; }'
check "  ... bash read no startup file; git used no ~/.gitconfig pager, alias or filter and no repo-local pager" 'none || { markers; false; }'
check "  ... in a container: loopback only, the seccomp filter, no_new_privs and no capabilities" 'grep -q "^net=lo.\$" /tmp/gate-a2 &&
  grep -q "^Seccomp:2" /tmp/gate-a2 && grep -q "^NoNewPrivs:1" /tmp/gate-a2 && grep -q "^CapEff:0000000000000000" /tmp/gate-a2'
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
cd /workspace && agentbox attach status >/dev/null 2>&1; echo "status-as-agent=\$?"
cp ~/.claude/.credentials.json notes.json
sed -n 's/.*accessToken":"\([^"]*\)".*/\1/p' notes.json > gitleak && git add gitleak && git -c user.name=t -c user.email=t@example.com commit -qm leak && git rm -q gitleak &&
  git -c gc.auto=0 gc -q && ls .git/objects/pack/*.pack >/dev/null && { echo loose; git show HEAD:gitleak; } | git hash-object -w --stdin >/dev/null && echo committed
sleep 3
printf '{"claudeAiOauth":{"accessToken":"$MID"}}\n' > ~/.claude/.credentials.json; cp ~/.claude/.credentials.json mid.json; sleep 0.5
printf '{"claudeAiOauth":{"accessToken":"$NEW"}}\n' > ~/.claude/.credentials.json
sleep 3; exit
IN
cat > /tmp/gate-blocked.sh <<'SH'
$B attach status > /tmp/gate-st; cat /tmp/gate-st; grep -q "\"reason\":\"$1\"" /tmp/gate-st
SH
check "attach 3: tasks are blocked while it is live" '( typed /tmp/gate-in3 | attach --cli bash --ack-control-changes >/tmp/gate-a3 2>&1 & ); sleep 2;
  B=$B sh /tmp/gate-blocked.sh attach_live'
check "  ... and task.start refuses a task for its workspace" '! $B task new --agent at --cli claude </dev/null >/tmp/gate-tn 2>&1; cat /tmp/gate-tn; grep -q attach_blocked /tmp/gate-tn'
check "  ... a second attach of the same agent is refused while it runs" '! attach --cli bash </dev/null >/tmp/gate-a3b 2>&1 && grep -q "an attach is live" /tmp/gate-a3b'
check "  ... it ends: the scan finds the rotated-away token, tasks stay blocked" 'for i in $(seq 60); do grep -qF "[agentbox] session ended" /tmp/gate-a3 && break; sleep 1; done;
  cat -v /tmp/gate-a3; grep -q committed /tmp/gate-a3 && grep -qF "workspace file(s) hold a session-home token: tasks blocked" /tmp/gate-a3 &&
  [ "$(sed -n "s/.*accessToken\":\"\([^\"]*\)\".*/\1/p" $H/.claude/.credentials.json)" = "$NEW" ]'
check "  ... the block names notes.json, the packfile git gc wrote, a loose object, and mid.json (a version that lived 0.5 s), never a token" '
  B=$B sh /tmp/gate-blocked.sh token_in_workspace && grep -q "notes.json" /tmp/gate-st && grep -q "\.git/objects/pack/pack-[0-9a-f]*\.pack" /tmp/gate-st &&
  grep -q "\.git/objects/[0-9a-f][0-9a-f]/" /tmp/gate-st && grep -q "mid.json" /tmp/gate-st && ! grep -qF "$TOK" /tmp/gate-st && ! grep -qF "$MID" /tmp/gate-st &&
  ! journalctl -b -o cat | grep -qF -e "$TOK" -e "$MID" && ! grep -rqF -e "$TOK" -e "$MID" /var/lib/agentbox/audit'
check "  ... an ntfy alert went out on agentbox-alerts" 'journalctl -b -u agentbox-rootd -o cat | grep -q "alert sent: .* hold a session-home token" &&
  python3 -c "import sqlite3,sys; c=sqlite3.connect(\"file:/var/lib/ntfy/cache.db?mode=ro\",uri=True); sys.exit(0 if c.execute(\"select count(*) from messages where topic=\x27agentbox-alerts\x27 and message like \x27%token%\x27\").fetchone()[0] else 1)"'
check "  ... a later attach is refused while the block stands" '! attach --cli bash </dev/null >/tmp/gate-a4 2>&1 && grep -q "not cleared" /tmp/gate-a4'
check "rescan keeps the block while the token is in the workspace" '$B attach rescan --agent at | grep -q "\"blocked\":true"'
as rm -f $W/notes.json $W/mid.json
as git -C $W -c user.name=t -c user.email=t@example.com -c core.hooksPath=/dev/null reset -q --hard HEAD~1
as git -C $W -c gc.auto=0 reflog expire --expire=now --all; as git -C $W gc -q --prune=now
check "  ... after a rootd restart a clean rescan keeps the block: the rotated-away versions are gone from memory" 'systemctl restart agentbox-rootd &&
  $B attach rescan --agent at > /tmp/gate-rs; cat /tmp/gate-rs; grep -q "\"blocked\":true" /tmp/gate-rs && grep -q -- "--ack-restart" /tmp/gate-rs'
check "  ... and --ack-restart lifts it once the token is gone from files and objects" '$B attach rescan --agent at --ack-restart | grep -q "\"blocked\":false" &&
  $B attach status | grep -qF "\"blocks\":[]"'
# #107: a hostile workspace and session-home. Every root-side reader refuses or caps: none blocks or reads outside.
# OTOK is only outside the tree, behind links, and in one plain workspace file: a reader that followed a link to it
# would make the scan hit that file. The session touches the fixture, so the end-of-attach scan reads all of it, for
# CTOK: a real session-home token (Codex's), so the scan has one to look for, which is in no workspace file.
O=/var/lib/agentbox-gate-outside OTOK=gate-oauth-at-gate-out-$$-EEEEEEEEEEEEEEEEEEEE CTOK=gate-codex-at-gate-$$-FFFFFFFFFFFFFFFFFFFF
HF="shadow approvers.db approvers .claude package-lock.json sub go.sum CLAUDE.md out-copy"
mkdir -p $O/claude && printf '{"claudeAiOauth":{"accessToken":"%s"}}\n' $OTOK > $O/approvers && cp $O/approvers $O/claude/outside-only.json
mv $W/.claude $W/.claude.gate && (cd $W && ln -s /etc/shadow shadow && ln -s /var/lib/agentbox/rootd.db approvers.db && ln -s $O/approvers approvers &&
  ln -s $O/claude .claude && mkdir sub && mkfifo package-lock.json sub/.mcp.json && truncate -s 2G go.sum CLAUDE.md && echo $OTOK > out-copy &&
  chown -hR ag-at:ag-at $HF) && ln -sf $O/approvers $H/.claude/.credentials.json &&
  mkdir -p $H/.codex && printf '{"tokens":{"access_token":"%s"}}\n' $CTOK > $H/.codex/auth.json && chown -h ag-at:ag-at $H/.codex $H/.codex/auth.json $H/.claude/.credentials.json
printf 'cd /workspace && touch go.sum CLAUDE.md out-copy package-lock.json sub/.mcp.json && touch -h shadow approvers approvers.db .claude; echo "touched=$?"\nexit\n' > /tmp/gate-h-in
check "hostile workspace: attach is refused naming the .claude link, the FIFO .mcp.json and the 2 GiB CLAUDE.md, nothing behind the link" '! attach --cli bash </dev/null >/tmp/gate-h0 2>&1; cat /tmp/gate-h0;
  grep -q "control paths changed" /tmp/gate-h0 && grep -qE "[ :,]\.claude[,;]" /tmp/gate-h0 && grep -qE "[ :,]sub/\.mcp\.json[,;]" /tmp/gate-h0 &&
  grep -qE "[ :,]CLAUDE\.md[,;]" /tmp/gate-h0 && ! grep -q "outside-only" /tmp/gate-h0'
check "  ... with the ack the session touches it all, and the token scan is clean within 120 s: no link or FIFO was followed or blocked on, no 2 GiB file read whole" '
  s=$(date +%s); typed /tmp/gate-h-in | attach --cli bash --ack-control-changes >/tmp/gate-h1 2>&1; e=$(( $(date +%s) - s )); cat -v /tmp/gate-h1; echo "took ${e}s";
  grep -q "touched=0" /tmp/gate-h1 && grep -qF "[agentbox] session ended; token scan: clean, tasks may start" /tmp/gate-h1 && [ $e -lt 120 ]'
(cd $W && rm -rf $HF) && rm -f $H/.claude/.credentials.json $H/.codex/auth.json && mv $W/.claude.gate $W/.claude && rm -rf $O
check "the agent can't use rootd-admin.sock" 'grep -q "status-as-agent=1" /tmp/gate-a3'
check "audit: each attach is an INTENT, a tainted session writer of workspace:at#<N>, a WRITER_DEL and a RESULT" '
  cat /var/lib/agentbox/audit/seg-*.jsonl > /tmp/gate-audit && [ "$(grep -c "\"name\":\"agent.attach\"" /tmp/gate-audit)" -ge 3 ] &&
  [ "$(grep WRITER_ADD /tmp/gate-audit | grep "session:ses_" | grep -c "\"workspace\":\"workspace:at#$((U - 70000))\"")" -ge 3 ] &&
  [ "$(grep "\"type\":\"TAINT\"" /tmp/gate-audit | grep "session:ses_" | grep -c "\"source\":\"attach\"")" -ge 3 ] &&
  [ "$(grep WRITER_DEL /tmp/gate-audit | grep -c "session:ses_")" -ge 3 ]'
check "the audit chain verifies" '$B audit verify'
check "no session unit or container is left and no unit failed" '[ -z "$(systemctl --user -M ag-at@ list-units --all --no-legend "agentbox-attach-*")" ] &&
  ! ls /sys/fs/cgroup/user.slice/user-$U.slice/user@$U.service/app.slice | grep -q attach && [ -z "$(systemctl --failed --no-legend --plain)" ]'
journalctl -b -u agentbox-rootd -o short-precise --no-pager | grep -i attach | tail -40
tail -c 20000 /tmp/gate-check.log
rm -rf $M /tmp/gate-* /usr/bin/claude; rm -f /workspace; $B agent remove --name at >/dev/null 2>&1 || :
echo "fails=$fails"
EOF
  ;;
*) die "unknown stage $s (install or checks)" ;;
esac; done
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "attach gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "attach gate: all checks passed"

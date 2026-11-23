#!/bin/sh
# Weeks 5-6 task gate (PLAN.md row 5-6; ARCHITECTURE.md §4.2, §10, Appendix C; issues #13, #14, #103, #104, #106 and #155) on the local QEMU
# VM, arm64 UEFI, none mode, through the real rootd, agentboxd and auditd and rootless podman.
#   hack/tasks-gate.sh [install|checks ...]   default: both, in order
# install  hack/gate.sh none: the unattended install and the release pipeline, so podman, the units, the seccomp
#          profile and the PAM line arrive the real way.
# checks   An agent (`agentbox agent add`, rootd's agent.add) runs tasks started with `agentbox task new` on
#          rootd-admin.sock, dispatched by agentboxd, launched by rootd; prompts reach the task on stdin and run as sh
#          scripts (AGENTBOX_TEST_CLI=sh on agentboxd). Each gate item of #13 and #14:
#          - a task plants Claude, Codex and opencode hooks, settings and MCP config, in HOME and in the workspace,
#            and a SKILL.md frontmatter hook: the next task's HOME holds only the generated configs and hooks are off.
#            The real Claude Code CLI (linux-arm64, pinned in hack/SHA256SUMS, as in attach-gate.sh) run without the
#            task flags on the host runs the workspace SessionStart hook and .mcp.json server (the control); run the
#            same way in a task (the image's managed settings) or as `--cli claude`, it runs neither. A skill's frontmatter hook needs a model turn, so only the shared
#            disableAllHooks switch is checked for it;
#          - agent.attach is refused while a task of the agent runs;
#          - a task tainted mid-run makes the next task start tainted;
#          - user-unit and container-config escapes fail;
#          - a task that traps SIGTERM and forks `sleep infinity` leaves no process in its unit cgroup and no libpod-*
#            cgroup under user@<uid>.service within 20 s of its timeout and of cgroup.kill, and the next task sees no
#            workspace writes from it;
#          - canceling a running task removes its container and sockets within 5 s, also with auditd stopped;
#          - restarting each broker mid-task (stand-ins: `agentbox broker-stub` on svc-proxy, svc-keys and svc-git,
#            since the brokers come in weeks 7-8; and agentboxd, the gate) doesn't break the task: its calls reach
#            the new process on the same socket path, with no relaunch;
#          - 20 consecutive launches each take under 300 ms over the user bus, open one login session, and run no
#            update-motd.d;
#          - a btrfs ioctl from a task fails with EOPNOTSUPP, also with high cmd bits set (#14);
#          - a task opens only AF_UNIX, AF_INET, AF_INET6 and NETLINK_ROUTE sockets, on the low 32 bits of the family,
#            and AF_UNIX socketpairs; it can't make namespaces with clone, unshare or setns, and clone3 gets ENOSYS
#            (#155);
#          - the agent's podman reads only its root-owned storage.conf, also with storage.conf.d drop-ins planted (#124);
#          - after its user manager restarts under a running rootd, the next 3 tasks start and stop cleanly with the
#            pause process in the user manager (#149);
#          - a dead pause process whose PID an agent-uid process took (the podman 5.7 bug) doesn't stop the next task,
#            and rootd audits PAUSE_PID_STALE (#125);
#          - taskrun's isolation probe: a network interface, a default route, a sibling task's socket dir and an
#            abstract socket, each added on its own through a wrapper over podman, stop the task with
#            TASK_ISOLATION_PROBE before the CLI runs, with an audit ALERT and an ntfy alert; a normal task passes it in
#            under 100 ms (#106); a probe failure the CLI posts itself fails its task with no alert (#183);
#          - every task start takes a read-only snapshot of the workspace in qgroup 1/N; after a task runs
#            rm -rf /workspace/*, agentbox task undo restores a tree with the same digest, keeping the taint the
#            snapshot had; 7 tasks later 5 task-start snapshots are left, and no clean-baseline or pre-restore one is
#            pruned (#103); a nested subvolume made on the host refuses the task-start snapshot with
#            NESTED_SUBVOLUME (#184);
#          - a new agent's workspace is scanned for credentials (gitleaks rules) in a unit with only loopback; a
#            GitHub token planted before its first task blocks it, naming the file and type; --ack-secrets 1 lets it
#            start; an egress grant for github.com names the token type; once removed, the next task starts (#104).
# PASS/FAIL lines go to .vm/tasks-gate.txt, command output to .vm/tasks-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/tasks-gate.txt" LOG="$VM/tasks-gate.log"
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
cd / # runuser keeps the working dir, and the agent can't enter the admin's home
check() { if (eval "$2") >>/tmp/tg-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
B=/var/lib/agentbox/current/bin/agentbox
W=/var/lib/agentbox/data/workspaces/gt
X=/var/lib/agentbox/control/xdg/gt
H=/var/lib/agentbox/data/agents/gt/account
RS=/run/systemd/system
# new DEADLINE < script: start a task as the human, print its id
new() { newc sh "$1"; }
newg() { $B task new --agent gs --cli sh --deadline 2m > /tmp/tg-new && sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' /tmp/tg-new; }
newc() { $B task new --agent gt --cli "$1" --deadline "$2" > /tmp/tg-new && sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' /tmp/tg-new; }
field() { $B task list | python3 -c 'import json,sys; t=[x for x in json.load(sys.stdin)["tasks"] if x["task"]==sys.argv[1]]; v=t[0].get(sys.argv[2],"") if t else ""
print(v if isinstance(v,str) else json.dumps(v,separators=(",",":")))' "$1" "$2"; }
wait_end() { i=0; while [ -z "$(field "$1" end_reason)" ]; do i=$((i+1)); [ $i -lt $(( $2 * 5 )) ] || return 1; sleep 0.2; done; }
wait_file() { i=0; while [ ! -e "$1" ]; do i=$((i+1)); [ $i -lt $(( $2 * 5 )) ] || return 1; sleep 0.2; done; }
pod() { runuser -u ag-gt -- env HOME=$H XDG_RUNTIME_DIR=/run/user/$U XDG_CONFIG_HOME=$X/config XDG_DATA_HOME=$X/data CONTAINERS_STORAGE_CONF=$X/config/containers/storage.conf podman "$@"; }
# upod ARGS: podman as the agent through its user manager, with that manager's environment, as rootd's setup call runs
upod() { systemd-run --user -M ag-gt@ --wait --pipe --quiet --collect podman "$@" </dev/null; }
# pause_ok: the pause process pause.pid names is alive, in the agent's user manager, and in no task unit
pause_ok() { p=$(cat /run/user/$U/libpod/tmp/pause.pid) && kill -0 $p && grep -q "^0::/user.slice/user-$U.slice/user@$U.service/" /proc/$p/cgroup && ! grep -q agentbox-task- /proc/$p/cgroup; }
cg() { echo /sys/fs/cgroup/user.slice/user-$U.slice/user@$U.service; }
# clean ID: the unit cgroup has no process (or is gone), and nothing named libpod-* is left under user@<uid>.service
clean() { u=$(cg)/app.slice/agentbox-task-$1.service; { [ ! -e $u/cgroup.events ] || grep -qx 'populated 0' $u/cgroup.events; } &&
  [ -z "$(find $(cg) -name 'libpod-*' 2>/dev/null)" ]; }
# within S ID: clean within S seconds; prints the time it took
within() { t0=$(date +%s%N); while ! clean $2; do [ $(( ($(date +%s%N) - t0) / 1000000 )) -lt $(( $1 * 1000 )) ] || return 1; sleep 0.1; done
  echo "clean after $(( ($(date +%s%N) - t0) / 1000000 )) ms"; }
socks_gone() { for v in gate proxy keys git; do [ ! -e /run/agentbox-$v/t/$1 ] || return 1; done; }
# gone_within MS ID: the container and every socket dir of ID are gone within MS of $t0 (set by the caller)
gone_within() { while pod container exists task-$2 || ! socks_gone $2; do [ $(( ($(date +%s%N) - t0) / 1000000 )) -lt 10000 ] || return 1; sleep 0.1; done
  ms=$(( ($(date +%s%N) - t0) / 1000000 )); echo "gone after $ms ms"; [ $ms -lt $1 ]; }
journalctl --rotate >/dev/null 2>&1 || :

# --- setup: the agent, the test CLI, and the broker stand-ins ---
check "the task seccomp profile is installed, root-owned, from the release" '[ "$(stat -c "%U %a" /var/lib/agentbox/control/seccomp-task.json)" = "root 644" ] &&
  cmp /var/lib/agentbox/control/seccomp-task.json /var/lib/agentbox/current/seccomp/seccomp-task.json && grep -q EOPNOTSUPP /var/lib/agentbox/control/seccomp-task.json'
check "podman is installed, and PAM login skips pam_motd for ag-* users right before the motd lines" 'podman --version &&
  grep -B1 -m1 "pam_motd.so" /etc/pam.d/login | head -1 | grep -qx "session \[success=2 default=ignore\] pam_succeed_if.so quiet user =~ ag-\*"'
check "agent add: ag-gt, uid 70000+N, its sub-id block, linger, root-owned XDG and HOME" '$B agent add --name gt &&
  U=$(id -u ag-gt) && [ $U -gt 70000 ] && N=$((U-70000)) && grep -qx "ag-gt:$((0x70000000 + N*65536)):65536" /etc/subuid &&
  [ -e /var/lib/systemd/linger/ag-gt ] && [ "$(stat -c %U $X/config $X/config/containers/storage.conf $H | sort -u)" = root ] &&
  [ "$(stat -c "%U %a" $W)" = "ag-gt 700" ]'
U=$(id -u ag-gt)
find $W -mindepth 1 -delete 2>/dev/null || : # a rerun on the same box starts from an empty workspace
# linger starts the user manager in the background, after agent add returns
check "  ... its user manager runs with the root-owned XDG dirs" 'i=0; until systemctl is-active -q user@$U.service; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done &&
  tr "\0" "\n" < /proc/$(systemctl show -P MainPID user@$U.service)/environ | grep -qx "XDG_CONFIG_HOME=$X/config"'
mkdir -p $RS/agentboxd.service.d && printf '[Service]\nEnvironment=AGENTBOX_TEST_CLI=sh\n' > $RS/agentboxd.service.d/50-tg.conf
for v in proxy keys git; do
  printf '[Socket]\nListenStream=/run/agentbox-rootd/svc-%s.sock\nSocketUser=agentbox-%s\nSocketGroup=root\nSocketMode=0600\nFileDescriptorName=svc-%s\nService=agentbox-%s-stub.service\nRemoveOnStop=yes\n' $v $v $v $v > $RS/agentbox-$v-stub.socket
  printf '[Unit]\nRequires=agentbox-%s-stub.socket\nAfter=agentbox-rootd.service\n[Service]\nType=notify\nNotifyAccess=main\nUser=agentbox-%s\nUMask=0117\nExecStart=%s broker-stub --svc %s\n' $v $v $B $v > $RS/agentbox-$v-stub.service
done
systemctl daemon-reload
check "agentboxd with AGENTBOX_TEST_CLI=sh, and the three broker stand-ins" 'systemctl restart agentboxd.service && systemctl start agentbox-proxy-stub agentbox-keys-stub agentbox-git-stub &&
  systemctl is-active -q agentboxd agentbox-proxy-stub agentbox-keys-stub agentbox-git-stub'

# --- a first task: the container's shape ---
echo 'id -u > /workspace/t1.uid; ls /sys/class/net > /workspace/t1.net
grep -E "^(CapEff|NoNewPrivs|Seccomp):" /proc/self/status > /workspace/t1.status; grep -E " /(home/agent|tmp) " /proc/mounts > /workspace/t1.mounts
touch /t1-root 2>/dev/null && echo rootfs-writable > /workspace/t1.ro; stat -c %u "$HOME" > /workspace/t1.home; echo done > /workspace/t1.done' > /tmp/tg-p
check "task new: rootd starts the task agentboxd dispatched; it runs the prompt from stdin and completes" 'T1=$(new 2m < /tmp/tg-p) && echo $T1 > /tmp/tg-t1 && cp /tmp/tg-new /tmp/tg-new1 &&
  wait_end $T1 60 && [ "$(field $T1 end_reason)" = completed ] && [ "$(cat $W/t1.done)" = done ]'
T1=$(cat /tmp/tg-t1 2>/dev/null || :)
check "  ... rootd loaded the task image into the agent's podman before the launch" 'pod image exists $(pod images --format "{{.Repository}}:{{.Tag}}" | grep agentbox-task)'
check "  ... on a fresh box it starts clean (untainted)" 'grep -q "\"tainted\":false" /tmp/tg-new1'
check "  ... provenance from rootd: origin admin:<request>, chain [human:root, agent:gt] (the CLI ran as root)" '[ "$(field $T1 origin | cut -c1-10)" = admin:req_ ] &&
  [ "$(field $T1 chain)" = "[\"human:root\",\"agent:gt\"]" ]'
check "  ... as the agent uid, no network, no caps, NoNewPrivs, seccomp filter" '[ "$(cat $W/t1.uid)" = $U ] && [ "$(cat $W/t1.net)" = lo ] &&
  grep -qx "CapEff:	0000000000000000" $W/t1.status && grep -qx "NoNewPrivs:	1" $W/t1.status && grep -qx "Seccomp:	2" $W/t1.status'
check "  ... read-only root, HOME a 4g tmpfs owned by the agent, /tmp a tmpfs" '[ ! -e $W/t1.ro ] && [ "$(cat $W/t1.home)" = $U ] &&
  grep -q "^tmpfs /home/agent tmpfs .*size=4194304k" $W/t1.mounts && grep -q "^tmpfs /tmp tmpfs" $W/t1.mounts'
check "  ... stopped: container, unit cgroup, socket dirs and registrations gone" 'clean $T1 && socks_gone $T1 && ! pod container exists task-$T1 &&
  ! $B gate list | grep -q $T1'

# --- #13: planted hooks and MCP config don't reach the next task ---
cat > /tmp/tg-p <<'P'
mkdir -p $HOME/.claude $HOME/.codex $HOME/.config/opencode /workspace/.claude/skills/evil /workspace/.codex
echo '{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch /workspace/HOOK-RAN"}]}]}}' > $HOME/.claude/settings.json
echo '{"mcpServers":{"evil":{"command":"/bin/sh","args":["-c","touch /workspace/MCP-RAN"]}}}' > $HOME/.claude.json
printf '[mcp_servers.evil]\ncommand = "/bin/sh"\nargs = ["-c", "touch /workspace/MCP-RAN"]\n' > $HOME/.codex/config.toml
echo '{"mcp":{"evil":{"type":"local","command":["touch","/workspace/MCP-RAN"]}}}' > $HOME/.config/opencode/opencode.json
cp $HOME/.claude/settings.json /workspace/.claude/settings.json; cp $HOME/.claude.json /workspace/.mcp.json
cp $HOME/.codex/config.toml /workspace/.codex/config.toml
printf -- '---\nname: evil\ndescription: x\nhooks:\n  PreToolUse:\n    - hooks:\n        - type: command\n          command: touch /workspace/HOOK-RAN\n---\nevil\n' > /workspace/.claude/skills/evil/SKILL.md
echo planted > /workspace/t2.done
P
check "a task plants Claude, Codex and opencode hooks and MCP config in HOME and the workspace, and a SKILL.md hook" 'T2=$(new 2m < /tmp/tg-p) &&
  wait_end $T2 60 && [ "$(field $T2 end_reason)" = completed ] && [ -f $W/.claude/skills/evil/SKILL.md ] && [ -f $W/.mcp.json ]'
cat > /tmp/tg-p <<'P'
find $HOME -mindepth 1 | sort > /workspace/t3.home
cmp $HOME/.claude/settings.json /opt/agentbox/exports/claude-settings.json && echo same > /workspace/t3.claude
cmp $HOME/.codex/config.toml /opt/agentbox/exports/codex-config.toml && echo same > /workspace/t3.codex
echo x >> /opt/agentbox/exports/claude-settings.json 2>/dev/null || echo ro > /workspace/t3.exports
git config --get core.hooksPath > /workspace/t3.git; echo done > /workspace/t3.done
P
check "  ... the next task's HOME is fresh: only the generated configs, byte for byte, read-only at the source" 'T3=$(new 2m < /tmp/tg-p) &&
  wait_end $T3 60 && [ "$(field $T3 end_reason)" = completed ] && [ "$(cat $W/t3.claude $W/t3.codex $W/t3.exports)" = "same
same
ro" ] && [ "$(tr "\n" " " < $W/t3.home)" = "/home/agent/.agentbox /home/agent/.agentbox/output /home/agent/.claude /home/agent/.claude/CLAUDE.md /home/agent/.claude/settings.json /home/agent/.codex /home/agent/.codex/AGENTS.md /home/agent/.codex/config.toml " ] || { cat $W/t3.home $W/t3.claude $W/t3.codex $W/t3.exports; false; }'
check "  ... hooks are off for every settings source (disableAllHooks, the skill frontmatter hook included), MCP config empty, git hooks off" '
  grep -qx "  \"disableAllHooks\": true" /var/lib/agentbox/control/exports/gt/claude-settings.json && grep -q "\"mcpServers\": {}" /var/lib/agentbox/control/exports/gt/mcp.json &&
  [ "$(cat $W/t3.git)" = /opt/agentbox/exports/nohooks ] && [ -z "$(ls -A /var/lib/agentbox/control/exports/gt/nohooks)" ]'
# in /usr/bin, which the stub task image mounts from the host
mkdir -p /tmp/cc && tar -xzf /tmp/claude.tgz -C /tmp/cc package/claude && install -m 0755 /tmp/cc/package/claude /usr/bin/claude
rm -rf /tmp/cc /tmp/claude.tgz
# by hand: a fresh HOME, not the task's (its generated user settings turn hooks off), every settings source, a trusted
# workspace with the planted server enabled
cat > /tmp/tg-p <<'P'
export HOME=$(mktemp -d)
echo '{"hasCompletedOnboarding":true,"projects":{"/workspace":{"hasTrustDialogAccepted":true,"enabledMcpjsonServers":["evil"]}}}' > $HOME/.claude.json
cd /workspace && timeout 60 claude -p hi --setting-sources user,project,local --dangerously-skip-permissions </dev/null > /workspace/tc.out 2>&1
sleep 2; echo done > /workspace/tc.done
P
# the control runs the same on the host, as the agent, where no managed settings exist; /workspace links to the workspace
T=$(mktemp -d) && sed -n "s/^echo '\(.*\)' > \$HOME\/.claude.json$/\1/p" /tmp/tg-p > $T/.claude.json && chown -R ag-gt $T && ln -sfn $W /workspace
runuser -u ag-gt -- sh -c "cd $W && HOME=$T timeout 60 claude -p hi --setting-sources user,project,local --dangerously-skip-permissions" </dev/null >/tmp/tg-ctl 2>&1 || :
check "  ... control: claude without the task flags, on the host, runs the planted SessionStart hook and .mcp.json server" '
  [ -e $W/HOOK-RAN ] && [ -e $W/MCP-RAN ] || { ls -A $W; cat /tmp/tg-ctl; false; }'
rm -rf $T; rm -f /workspace $W/HOOK-RAN $W/MCP-RAN
check "  ... the same claude, by hand in a task, runs neither: the image's managed settings outrank every source" 'Tc=$(new 2m < /tmp/tg-p) &&
  wait_end $Tc 90 && [ -f $W/tc.done ] && [ ! -e $W/HOOK-RAN ] && [ ! -e $W/MCP-RAN ] || { ls -A $W; cat $W/tc.out; false; }'
rm -f $W/tc.*
# the model API goes to the keys stand-in, which isn't HTTP: claude retries until the deadline
check "  ... a --cli claude task (the real CLI with the task flags) runs neither" 'echo hi > /tmp/tg-p && T3c=$(newc claude 2m < /tmp/tg-p) &&
  wait_end $T3c 200 && sleep 2 && [ ! -e $W/HOOK-RAN ] && [ ! -e $W/MCP-RAN ] || { ls -A $W; false; }'

# --- #13: taint carry-over ---
echo 'touch /workspace/t4.up; i=0; while [ ! -e /workspace/t4.go ] && [ $i -lt 100 ]; do sleep 0.5; i=$((i+1)); done' > /tmp/tg-p
check "a running task's processes are all in its unit's cgroup (--cgroups=split), none in a libpod scope outside it" 'T4=$(new 2m < /tmp/tg-p) && echo $T4 > /tmp/tg-t4 &&
  wait_file $W/t4.up 60 && u=$(cg)/app.slice/agentbox-task-$T4.service && grep -qx "populated 1" $u/cgroup.events &&
  find $u -name "libpod-payload-*" | grep -q . && [ -z "$(find $(cg) -name "libpod-*" ! -path "$u/*")" ] &&
  for p in $(pgrep -u $U -f "sleep 0.5|/usr/local/bin/agentbox taskrun"); do grep -q "agentbox-task-$T4.service" /proc/$p/cgroup || exit 1; done'
T4=$(cat /tmp/tg-t4 2>/dev/null || :)
check "agent.attach is refused while a task of the agent runs, and leaves no block" '! $B attach --agent gt --cli bash </dev/null >/tmp/tg-at 2>&1 &&
  cat /tmp/tg-at && grep -q "a task of this agent is running" /tmp/tg-at && $B attach status | grep -qF "\"blocks\":[]"'
check "a running task, tainted mid-run (a TAINT for task:<id>), taints its workspace (workspace:gt#N)" '
  $B audit send --socket /run/agentbox-audit/rootd.sock "{\"type\":\"TAINT\",\"subject\":\"task:$T4\",\"source\":\"gate:mid-run\"}" &&
  $B audit send --socket /run/agentbox-audit/rootd.sock "{\"type\":\"taint.get\",\"holder\":\"task:$T4\"}" | grep -q "\"subject\":\"workspace:gt#$((U - 70000))\",\"tainted\":true"'
touch $W/t4.go
check "  ... and it ends normally" 'wait_end $T4 90 && [ "$(field $T4 end_reason)" = completed ]'
echo 'touch /workspace/t5.up; i=0; while [ ! -e /workspace/t5.go ] && [ $i -lt 100 ]; do sleep 0.5; i=$((i+1)); done' > /tmp/tg-p
check "  ... the next task starts tainted: rootd reports it, and auditd's view of the running task holds the tainted workspace" 'T5=$(new 2m < /tmp/tg-p) &&
  grep -q "\"tainted\":true" /tmp/tg-new && wait_file $W/t5.up 60 &&
  $B audit send --socket /run/agentbox-audit/rootd.sock "{\"type\":\"taint.get\",\"holder\":\"task:$T5\"}" | grep -q "\"subject\":\"workspace:gt#$((U - 70000))\",\"tainted\":true"'
touch $W/t5.go

# --- #13: user-unit and container-config escapes ---
echo 'ls -A /run/user > /workspace/t6.runuser 2>&1; systemctl --user status >/dev/null 2>&1 && echo reached > /workspace/t6.bus; echo done > /workspace/t6.done' > /tmp/tg-p
check "from a task: no user bus and no /run/user, so no way to reach the user manager" 'T6=$(new 2m < /tmp/tg-p) && wait_end $T6 60 &&
  [ -f $W/t6.done ] && [ ! -e $W/t6.bus ] && { [ ! -s $W/t6.runuser ] || grep -q "No such file" $W/t6.runuser; }'
check "as the agent uid on the host: no user unit, containers.conf, storage.conf or HOME config can be written" '
  ! runuser -u ag-gt -- mkdir -p $X/config/systemd/user && ! runuser -u ag-gt -- touch $X/config/containers/containers.conf &&
  ! runuser -u ag-gt -- sh -c "echo x >> $X/config/containers/storage.conf" && ! runuser -u ag-gt -- mkdir $H/.config &&
  ! runuser -u ag-gt -- touch /etc/containers/containers.conf && ! runuser -u ag-gt -- mkdir -p /etc/systemd/user/x &&
  [ -z "$(ls -A $H)" ]'
check "  ... the user manager reads only the root-owned XDG dirs; its one CONTAINERS_* variable pins the root-owned storage.conf" '
  [ "$(tr "\0" "\n" < /proc/$(systemctl show -P MainPID user@$U.service)/environ | grep "^CONTAINERS_")" = "CONTAINERS_STORAGE_CONF=$X/config/containers/storage.conf" ] &&
  [ -z "$(find $X /var/lib/agentbox/control/exports/gt ! -user root)" ]'

# --- #13: SIGTERM-trapping forkers ---
TRAP='trap "" TERM; sleep infinity & while :; do date +%s%N >> /workspace/leak-$L; sleep 0.2; done'
echo "L=a; $TRAP" > /tmp/tg-p
check "timeout: a task that traps SIGTERM and forks sleep infinity is gone from its unit cgroup within 20 s of RuntimeMaxSec" '
  T7=$(new 12s < /tmp/tg-p) && wait_file $W/leak-a 30 && dl=$(field $T7 deadline) &&
  while [ $(($(date +%s%3N))) -lt $dl ]; do sleep 0.1; done && within 20 $T7 && wait_end $T7 30 && [ "$(field $T7 end_reason)" = timeout ]'
echo "L=b; $TRAP" > /tmp/tg-p
check "cgroup.kill (agentbox task stop): the same task is gone within 20 s" 'T8=$(new 2m < /tmp/tg-p) && wait_file $W/leak-b 30 &&
  $B task stop --task $T8 && within 20 $T8 && [ "$(field $T8 end_reason)" = canceled ]'
echo 'a=$(wc -c < /workspace/leak-a); b=$(wc -c < /workspace/leak-b); sleep 2; echo "$a $b $(wc -c < /workspace/leak-a) $(wc -c < /workspace/leak-b)" > /workspace/t9.sizes' > /tmp/tg-p
check "  ... the next task sees no workspace writes from either" 'T9=$(new 2m < /tmp/tg-p) && wait_end $T9 60 &&
  read a b a2 b2 < $W/t9.sizes && [ "$a" = "$a2" ] && [ "$b" = "$b2" ] && [ "$a" -gt 0 ]'

# --- #13: cancel within 5 s, also with auditd stopped ---
echo 'touch /workspace/t10.up; sleep 600' > /tmp/tg-p
check "cancel: container and sockets gone within 5 s" 'rm -f $W/t10.up; T10=$(new 2m < /tmp/tg-p) && wait_file $W/t10.up 60 && pod container exists task-$T10 &&
  t0=$(date +%s%N) && $B task stop --task $T10 && gone_within 5000 $T10 && clean $T10'
check "cancel with auditd stopped: container and sockets gone within 5 s" 'rm -f $W/t10.up; T11=$(new 2m < /tmp/tg-p) && wait_file $W/t10.up 60 &&
  systemctl stop agentbox-auditd.service "agentbox-auditd-*.socket" && ! systemctl is-active -q agentbox-auditd.service && [ ! -e /run/agentbox-audit/rootd.sock ] &&
  t0=$(date +%s%N) && $B task stop --task $T11 && gone_within 5000 $T11 && clean $T11'
systemctl start "agentbox-auditd-*.socket" agentbox-auditd.service
check "  ... auditd back" 'systemctl is-active -q agentbox-auditd.service'

# --- #13: broker restarts mid-task ---
cat > /tmp/tg-p <<'P'
i=0; while [ $i -lt 60 ]; do
  for s in egress/proxy llm/keys git/git; do agentbox gate call --socket /run/agentbox/$s.sock x >> /workspace/b-${s#*/} 2>/dev/null || echo DOWN >> /workspace/b-${s#*/}; done
  agentbox gate call --socket /run/agentbox/gate/gate.sock '{"jsonrpc":"2.0","id":1,"method":"file.delete","params":{}}' >> /workspace/b-gate 2>/dev/null || echo DOWN >> /workspace/b-gate
  [ $i = 2 ] && touch /workspace/b.up; [ -e /workspace/b.go ] && [ $i -gt 30 ] && break; sleep 0.3; i=$((i+1))
done
P
check "broker restart: each broker and agentboxd restarted mid-task; the running task reconnects, no relaunch" 'rm -f $W/b-* $W/b.*; T12=$(new 2m < /tmp/tg-p) &&
  wait_file $W/b.up 60 && systemctl restart agentbox-proxy-stub agentbox-keys-stub agentbox-git-stub agentboxd && touch $W/b.go && wait_end $T12 90 &&
  for s in proxy keys git; do [ "$(grep -o "\"pid\":[0-9]*" $W/b-$s | uniq | wc -l)" -ge 2 ] && tail -3 $W/b-$s | grep -q "\"ok\":true" || exit 1; done &&
  tail -3 $W/b-gate | grep -q UNKNOWN_OP && [ "$(field $T12 end_reason)" = completed ] &&
  [ "$(journalctl -b -u agentbox-rootd -o cat | grep -c "task $T12 (agent gt): launch")" = 1 ]'

# --- #14: no btrfs ioctls ---
# ioctl.py DIR CMD...: each raw ioctl(2) on DIR, with the full 64-bit cmd, prints "<cmd> <ret> <errno>"
cat > /tmp/tg-ioctl.py <<'PY'
import ctypes, os, sys
nr = {"aarch64": 29, "x86_64": 16}[os.uname().machine]
libc = ctypes.CDLL(None, use_errno=True)
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
buf = ctypes.create_string_buffer(4096 + 8)
buf[8:10] = b"sv"
for c in sys.argv[2:]:
    r = libc.syscall(ctypes.c_long(nr), ctypes.c_long(fd), ctypes.c_ulong(int(c, 16)), buf)
    print(c, r, ctypes.get_errno() if r < 0 else 0)
PY
# BTRFS_IOC_SUBVOL_CREATE, the same with the high 32 bits set, SNAP_CREATE_V2, FICLONE, GET_FEATURES (plain and high
# bits), and TCGETS, which is no btrfs ioctl
C="0x5000940e 0xffffffff5000940e 0x50009417 0x40049409 0x80189439 0xdead000080189439 0x5401"
{ echo "cat > /tmp/ioctl.py <<'PY'"; cat /tmp/tg-ioctl.py; echo PY; echo "python3 /tmp/ioctl.py /workspace $C > /workspace/t13.ioctl 2>&1"
  echo 'btrfs subvolume create /workspace/sv > /workspace/t13.btrfs 2>&1; echo $? >> /workspace/t13.btrfs'; } > /tmp/tg-p
check "a task's btrfs ioctls fail with EOPNOTSUPP (95), also with the high cmd bits set; a btrfs subvolume create fails" 'T13=$(new 2m < /tmp/tg-p) && wait_end $T13 60 &&
  cat $W/t13.ioctl && for c in 0x5000940e 0xffffffff5000940e 0x50009417 0x40049409 0x80189439 0xdead000080189439; do grep -qx "$c -1 95" $W/t13.ioctl || exit 1; done &&
  grep -q "^0x5401 -1 25$" $W/t13.ioctl && grep -qi "not supported" $W/t13.btrfs && [ ! -e $W/sv ]'
check "  ... the workspace is btrfs, and from the host (no task profile) GET_FEATURES succeeds, high bits too" '[ "$(stat -f -c %T $W)" = btrfs ] &&
  python3 /tmp/tg-ioctl.py $W 0x80189439 0xdead000080189439 > /tmp/tg-host && grep -qx "0x80189439 0 0" /tmp/tg-host && grep -qx "0xdead000080189439 0 0" /tmp/tg-host'

# --- #155: only the socket families tasks need, no namespaces ---
# sys.py: raw syscalls with full 64-bit args, each printing "<label> <ret> <errno>"; a child from clone exits at once
cat > /tmp/tg-sys.py <<'PY'
import ctypes, os
nr = {"aarch64": dict(socket=198, socketpair=199, clone=220, unshare=97, setns=268, clone3=435),
      "x86_64": dict(socket=41, socketpair=53, clone=56, unshare=272, setns=308, clone3=435)}[os.uname().machine]
libc = ctypes.CDLL(None, use_errno=True)
sv = (ctypes.c_int * 2)()
def call(label, name, *a):
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr[name]), *[x if isinstance(x, ctypes.Array) else ctypes.c_ulong(x) for x in a])
    if name == "clone" and r == 0:
        os._exit(0)
    print(label, 0 if r >= 0 else -1, ctypes.get_errno() if r < 0 else 0, flush=True)
call("unix", "socket", 1, 1, 0); call("inet", "socket", 2, 1, 0); call("inet6", "socket", 10, 2, 0)
call("route", "socket", 16, 3, 0); call("audit", "socket", 16, 3, 9); call("alg", "socket", 38, 5, 0)
call("vsock", "socket", 40, 1, 0); call("vsock-hi", "socket", 0x100000028, 1, 0)
call("pair-unix", "socketpair", 1, 1, 0, sv); call("pair-inet", "socketpair", 2, 1, 0, sv)
call("clone-fork", "clone", 17, 0, 0, 0, 0); call("clone-newuser", "clone", 0x10000000 | 17, 0, 0, 0, 0)
call("unshare-fs", "unshare", 0x200); call("unshare-newns", "unshare", 0x20000); call("unshare-newtime", "unshare", 0x80)
call("setns", "setns", 0, 0); call("clone3", "clone3", 0, 0)
PY
{ echo "cat > /tmp/sys.py <<'PY'"; cat /tmp/tg-sys.py; echo PY; echo 'python3 /tmp/sys.py > /workspace/t14.sys 2>&1'
  echo 'unshare -Ur true > /workspace/t14.unshare 2>&1; echo $? >> /workspace/t14.unshare'
  echo 'agentbox gate call --socket /run/agentbox/gate/gate.sock "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"file.delete\",\"params\":{}}" > /workspace/t14.gate 2>&1'
  echo '{ git init -q /tmp/r && git -C /tmp/r status --short && echo ok; } > /workspace/t14.go 2>&1'; } > /tmp/tg-p
check "a task can open AF_UNIX, AF_INET, AF_INET6 and NETLINK_ROUTE sockets and an AF_UNIX socketpair, fork, and unshare CLONE_FS" 'T14=$(new 2m < /tmp/tg-p) &&
  echo $T14 > /tmp/tg-t14 && wait_end $T14 60 && cat $W/t14.sys $W/t14.unshare &&
  for l in unix inet inet6 route pair-unix clone-fork unshare-fs; do grep -qx "$l 0 0" $W/t14.sys || exit 1; done'
check "  ... AF_ALG, AF_VSOCK (also with high bits set) and NETLINK_AUDIT sockets and an AF_INET socketpair get ENOSYS (38)" '
  for l in alg vsock vsock-hi audit pair-inet; do grep -qx "$l -1 38" $W/t14.sys || exit 1; done'
check "  ... clone with CLONE_NEWUSER, unshare with CLONE_NEWNS or CLONE_NEWTIME, and setns get EPERM; clone3 gets ENOSYS" '
  for l in clone-newuser unshare-newns unshare-newtime setns; do grep -qx "$l -1 1" $W/t14.sys || exit 1; done && grep -qx "clone3 -1 38" $W/t14.sys'
check "  ... unshare -Ur true fails" '[ "$(tail -1 $W/t14.unshare)" != 0 ] && grep -qi "operation not permitted" $W/t14.unshare'
check "  ... the gate socket still answers, and git still runs (the toolchains: m4-taskenv)" 'cat $W/t14.go; grep -q UNKNOWN_OP $W/t14.gate && [ "$(tail -1 $W/t14.go)" = ok ]'

# --- #106: the isolation probe, one broken layer at a time ---
# A wrapper bound over /usr/bin/podman changes only a task's `podman run` while /run/tg-break exists: its line is
# extra podman args, and /workspace/.tg-break.sh runs in the container before taskrun.
cp /usr/bin/podman /usr/local/bin/podman-real
cat > /usr/local/bin/tg-podman <<'W'
#!/bin/sh
[ "$1" = run ] && [ -e /run/tg-break ] || exec /usr/local/bin/podman-real "$@"
shift; n=$#; i=0
for a; do i=$((i+1)); [ $i -gt $((n-2)) ] || set -- "$@" "$a"; done # all but the command, agentbox taskrun
shift $n
exec /usr/local/bin/podman-real run $(cat /run/tg-break) "$@" /usr/bin/sh -c '. /workspace/.tg-break.sh; exec /usr/local/bin/agentbox taskrun'
W
chmod 0755 /usr/local/bin/tg-podman && mount --bind /usr/local/bin/tg-podman /usr/bin/podman && modprobe dummy
mkdir -p /tmp/tg-sib && python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind("/tmp/tg-sib/gate.sock")' && chown -R ag-gt /tmp/tg-sib
printf 'export PATH=/usr/sbin:/usr/bin:$PATH\nip link add tg0 type dummy\n' > /tmp/tg-b-netdev
printf 'export PATH=/usr/sbin:/usr/bin:$PATH\nip link set lo up\nip route add default dev lo\n' > /tmp/tg-b-route
: > /tmp/tg-b-sibling
cat > /tmp/tg-b-abstract <<'S'
python3 -c 'import socket, time; s = socket.socket(socket.AF_UNIX); s.bind(b"\0agentbox-proxy"); s.listen(); open("/tmp/ab", "w").close(); time.sleep(600)' &
while [ ! -e /tmp/ab ]; do sleep 0.05; done
S
# brk MODE CHECK [ARGS]: a task launched with ARGS and /tmp/tg-b-MODE stops with TASK_ISOLATION_PROBE on CHECK, and its
# prompt never runs
brk() { echo "${3:-}" > /run/tg-break && cp /tmp/tg-b-$1 $W/.tg-break.sh && rm -f $W/tb-ran && echo 'touch /workspace/tb-ran' > /tmp/tg-p &&
  T=$(new 2m < /tmp/tg-p) && wait_end $T 60 && [ "$(field $T end_reason)" = failed ] && [ ! -e $W/tb-ran ] &&
  journalctl -b -u agentbox-rootd -o cat | grep -q "ALERT task $T (agent gt): TASK_ISOLATION_PROBE: the $2 check failed" &&
  journalctl -b -u agentboxd -o cat | grep -q "task $T result: .*isolation probe [0-9]* ms \"$2\"" && echo "$T $2" >> /tmp/tg-brk; }
: > /tmp/tg-brk
check "isolation probe: a network interface (a dummy link) fails the launch with TASK_ISOLATION_PROBE, before the CLI" 'brk netdev netdev --cap-add=NET_ADMIN'
check "  ... a default route (via lo) fails it" 'brk route route --cap-add=NET_ADMIN'
check "  ... a sibling task's socket dir mounted at its host path fails it" 'brk sibling sibling_socket "-v /tmp/tg-sib:/run/agentbox-gate/t/task_01SIBLING:ro"'
check "  ... an abstract socket bound in the task's network namespace (a broker's name) fails it" 'brk abstract abstract_socket'
rm -f /run/tg-break $W/.tg-break.sh /tmp/tg-b-*; umount /usr/bin/podman; sleep 2; rm -rf /usr/local/bin/tg-podman /usr/local/bin/podman-real /tmp/tg-sib
check "  ... each one is an ALERT in auditd's chain naming its check, and an ntfy alert" 'sleep 2; cat /var/lib/agentbox/audit/seg-*.jsonl > /tmp/tg-audit &&
  [ "$(wc -l < /tmp/tg-brk)" = 4 ] && while read -r T c; do grep "\"reason\":\"TASK_ISOLATION_PROBE\"" /tmp/tg-audit | grep "\"task\":\"$T\"" | grep -q "\"check\":\"$c\"" || exit 1; done < /tmp/tg-brk &&
  python3 -c "import sqlite3,sys; c=sqlite3.connect(\"file:/var/lib/ntfy/cache.db?mode=ro\",uri=True); sys.exit(0 if c.execute(\"select count(*) from messages where topic=\x27agentbox-alerts\x27 and message like \x27%TASK_ISOLATION_PROBE%\x27\").fetchone()[0] >= 4 else 1)"'
check "  ... with the wrapper gone, a normal task passes the probe and runs its prompt" 'rm -f $W/tb-ran && echo "touch /workspace/tb-ran" > /tmp/tg-p && T=$(new 2m < /tmp/tg-p) && wait_end $T 60 &&
  [ "$(field $T end_reason)" = completed ] && [ -e $W/tb-ran ]'
cat > /tmp/tg-p <<'P'
agentbox gate call --socket /run/agentbox/gate/gate.sock '{"jsonrpc":"2.0","id":1,"method":"task.result","params":{"exit":0,"output":"","outputLen":0,"probe":"netdev","probeMs":1}}'
P
check "  ... a probe failure the CLI posts itself, after the probe passed, fails the task with no ALERT (#183)" 'T=$(new 2m < /tmp/tg-p) && wait_end $T 60 &&
  [ "$(field $T end_reason)" = failed ] && journalctl -b -u agentboxd -o cat | grep -q "task $T: a probe failure \"netdev\" after task.probed: not forwarded" &&
  sleep 2 && ! journalctl -b -u agentbox-rootd -o cat | grep -q "ALERT task $T" && ! grep -h "\"task\":\"$T\"" /var/lib/agentbox/audit/seg-*.jsonl | grep -q TASK_ISOLATION_PROBE'
check "  ... and every task that passed it took under 100 ms in the probe" 'journalctl -b -u agentboxd -o cat | sed -n "s/.* result: .*isolation probe \([0-9]*\) ms \"\"$/\1/p" > /tmp/tg-pms &&
  cat /tmp/tg-pms | tr "\n" " " && [ "$(wc -l < /tmp/tg-pms)" -ge 10 ] && [ "$(sort -n /tmp/tg-pms | tail -1)" -lt 100 ]'

# --- #13: 20 consecutive launches ---
printf '#!/bin/sh\ntouch /run/tg-motd-ran\n' > /etc/update-motd.d/00-tg-marker && chmod 0755 /etc/update-motd.d/00-tg-marker
rm -f /run/tg-motd-ran
sleep 1 # --since has 1 s steps: the last launch before it must fall outside
since=$(date "+%Y-%m-%d %H:%M:%S")
echo 'true' > /tmp/tg-p
: > /tmp/tg-20
check "20 consecutive launches" 'for i in $(seq 20); do t=$(new 2m < /tmp/tg-p) && echo $t >> /tmp/tg-20 && wait_end $t 60 || exit 1; done; [ "$(wc -l < /tmp/tg-20)" = 20 ]'
check "  ... each under 300 ms over the user bus" 'for t in $(cat /tmp/tg-20); do
    ms=$(journalctl -b -u agentbox-rootd -o cat | sed -n "s/^.* task $t (agent gt): launch \([0-9]*\) ms over the user bus: <nil>$/\1/p")
    echo "$t $ms ms"; [ -n "$ms" ] && [ "$ms" -lt 300 ] || exit 1; done'
check "  ... each opened exactly one login session for ag-gt" '[ "$(journalctl --since "$since" -o cat | grep -c "^pam_unix(login:session): session opened for user ag-gt(")" = 20 ]'
check "  ... and none ran update-motd.d" '[ ! -e /run/tg-motd-ran ]'
rm -f /etc/update-motd.d/00-tg-marker /run/tg-motd-ran

# --- #124: one storage.conf, whatever drop-ins exist ---
S="/var/lib/agentbox/data/agents/gt/storage /run/user/$U/containers overlay"
check "as the agent, through its user manager, podman info reports the GraphRoot, RunRoot and driver of the root-owned storage.conf" '
  [ "$(upod info --format "{{.Store.GraphRoot}} {{.Store.RunRoot}} {{.Store.GraphDriverName}}")" = "$S" ]'
DI="/etc/containers/storage.conf.d /etc/containers/storage.rootless.conf.d /etc/containers/storage.rootless.conf.d/$U /usr/share/containers/storage.conf.d /usr/share/containers/storage.rootless.conf.d/$U"
for d in $DI; do mkdir -p $d && printf '[storage]\ndriver = "vfs"\ngraphroot = "/var/tmp/tg-evil"\nrunroot = "/var/tmp/tg-evil-run"\n' > $d/99-tg.conf; done
check "  ... the same with storage.conf.d drop-ins planted in /etc and /usr/share, the per-UID paths too" '
  [ "$(upod info --format "{{.Store.GraphRoot}} {{.Store.RunRoot}} {{.Store.GraphDriverName}}")" = "$S" ] && [ ! -e /var/tmp/tg-evil ]'
for d in $DI; do rm -f $d/99-tg.conf; rmdir $d 2>/dev/null || :; done

# --- #149: the podman setup check runs before every launch ---
echo 'echo done > /workspace/tp.done' > /tmp/tg-p
check "#149: user@$U restarted while rootd runs; the next 3 tasks all start and stop cleanly, and no pause process is in a task unit" '
  r=$(systemctl show -P MainPID agentbox-rootd) && systemctl restart user@$U.service && systemctl is-active -q user@$U.service &&
  for i in 1 2 3; do rm -f $W/tp.done; t=$(new 2m < /tmp/tg-p) && wait_end $t 60 && [ "$(field $t end_reason)" = completed ] && [ -f $W/tp.done ] &&
    within 20 $t && pause_ok || exit 1; done && [ "$(systemctl show -P MainPID agentbox-rootd)" = $r ]'

# --- #125: a reused pause PID ---
PP=/run/user/$U/libpod/tmp/pause.pid
# kill the pause process, then start an agent-uid process with no user namespace at its PID (ns_last_pid = PID-1)
check "#125: pause process killed, and an agent-uid process outside its user namespace takes the PID" 'P=$(cat $PP) && kill -9 $P &&
  while kill -0 $P 2>/dev/null; do sleep 0.1; done && i=0 && while [ $i -lt 500 ]; do echo $((P-1)) > /proc/sys/kernel/ns_last_pid
    setpriv --reuid=$U --regid=$U --clear-groups sleep 600 </dev/null >/dev/null 2>&1 & q=$!; [ $q = $P ] && break; kill $q; i=$((i+1)); done &&
  [ "$(cat $PP)" = $P ] && [ "$(stat -c %u /proc/$P)" = $U ] && echo $P > /tmp/tg-reused'
check "  ... control: the agent's podman then fails with cannot set user namespace (the upstream bug)" '! pod info >/tmp/tg-userns 2>&1 && cat /tmp/tg-userns &&
  grep -q "cannot set user namespace" /tmp/tg-userns'
check "  ... the next task still starts and completes; rootd removed the stale pause.pid and audited PAUSE_PID_STALE" 'rm -f $W/tp.done; t=$(new 2m < /tmp/tg-p) &&
  wait_end $t 60 && [ "$(field $t end_reason)" = completed ] && [ -f $W/tp.done ] && pause_ok && [ "$(cat $PP)" != "$(cat /tmp/tg-reused)" ] &&
  cat /var/lib/agentbox/audit/seg-*.jsonl | grep "\"PAUSE_PID_STALE\"" | grep "\"agent\":\"gt\"" | grep -q "\"reason\":\"wrong_userns\""'
kill "$(cat /tmp/tg-reused 2>/dev/null)" 2>/dev/null || :

# --- #103: a snapshot at every task start, and agentbox task undo ---
WS="workspace:gt#$((U - 70000))" SN=/var/lib/agentbox/data/agents/gt/snapshots BASE=snap_00000000000000000000GATE00
asend() { $B audit send --socket /run/agentbox-audit/rootd.sock "$1"; }
# digest: every entry's type, mode, owner and link target, and every file's sha256
digest() { (cd $W && find . -mindepth 1 -printf '%y %m %U %G %p %l\n' | LC_ALL=C sort && find . -type f -exec sha256sum {} + | LC_ALL=C sort) | sha256sum | cut -c1-64; }
sql() { python3 -c 'import sqlite3,sys; c=sqlite3.connect("/var/lib/agentbox/rootd.db", timeout=10); r=c.execute(sys.argv[1], sys.argv[2:]).fetchall(); c.commit(); print("\n".join("|".join(map(str,x)) for x in r))' "$@"; }
wsepoch() { asend "{\"type\":\"taint.get\",\"holder\":\"task:$1\"}" | python3 -c 'import json,sys; v=json.load(sys.stdin)["view"]; print([s for s in v["subjects"] if s["subject"]==sys.argv[1]][0]["epoch"])' "$WS"; }
# a clean-baseline snapshot, as taint.clear will take one: rootd must never prune it
mkdir -p $SN && btrfs subvolume snapshot -r $W $SN/$BASE >/dev/null &&
  sql "INSERT INTO workspace_snapshots(id, workspace, agent, kind, created_at) VALUES(?,?,'gt','clean-baseline',1)" $BASE "$WS" >/dev/null
as() { runuser -u ag-gt -- "$@"; }
as mkdir -p $W/proj/src $W/proj/.cfg && as sh -c "echo one > $W/proj/a.txt; echo two > $W/proj/src/b.go; echo three > $W/proj/.cfg/c; ln -s src/b.go $W/proj/link; chmod 0640 $W/proj/a.txt"
D0=$(digest)
echo 'rm -rf /workspace/*; echo gone > /workspace/after' > /tmp/tg-p
check "#103: a task runs rm -rf /workspace/*; its start snapshot is a read-only subvolume in qgroup 1/$((U - 70000)), in a root-only dir" 'T=$(new 2m < /tmp/tg-p) &&
  echo $T > /tmp/tg-undo && wait_end $T 60 && [ ! -e $W/proj ] && [ "$(digest)" != "$D0" ] &&
  S=$(sql "SELECT id FROM workspace_snapshots WHERE task=? AND kind=?" $T task-start) && echo "snapshot $S" && [ -n "$S" ] &&
  [ "$(btrfs property get -ts $SN/$S ro)" = ro=true ] && [ "$(stat -c "%U %a" $SN)" = "root 700" ] &&
  id=$(btrfs inspect-internal rootid $SN/$S) && btrfs --format=json qgroup show -p /var/lib/agentbox |
  python3 -c "import json,sys; q={r[\"qgroupid\"]: r[\"parents\"] for r in json.load(sys.stdin)[\"qgroup-show\"]}; sys.exit(sys.argv[2] not in q[sys.argv[1]])" 0/$id 1/$((U - 70000))'
T=$(cat /tmp/tg-undo)
check "  ... the workspace taint is cleared after it (auditd taint.clear, as rootd), so the restore can show the snapshot's own" '
  asend "{\"type\":\"SUBJECT_ADD\",\"task\":\"task:$T\",\"subject\":\"$WS\"}" && E=$(wsepoch $T) && echo "epoch $E" &&
  asend "{\"type\":\"INTENT\",\"opId\":\"tg-clear\",\"name\":\"taint.clear\",\"origin\":\"admin\",\"signer\":\"gate\",\"args\":{\"subject\":\"$WS\",\"contentId\":\"gate\"},\"taintEpochs\":{\"$WS\":$E}}" &&
  asend "{\"type\":\"RESULT\",\"opId\":\"tg-clear\",\"status\":\"executed\"}" &&
  asend "{\"type\":\"taint.get\",\"holder\":\"task:$T\"}" | grep -q "\"subject\":\"$WS\",\"tainted\":false"'
check "  ... agentbox task undo restores a tree with the digest it had before the task" '$B task undo --task $T > /tmp/tg-undo-rep; cat /tmp/tg-undo-rep;
  grep -q "\"ok\":true" /tmp/tg-undo-rep && [ "$(digest)" = "$D0" ] && [ ! -e $W/after ] && [ "$(stat -c "%U %a" $W)" = "ag-gt 700" ]'
check "  ... the restored workspace keeps the taint the snapshot had (tainted), at a new epoch, and the next task starts tainted" '
  grep -q "\"tainted\":true" /tmp/tg-undo-rep && asend "{\"type\":\"taint.get\",\"holder\":\"task:$T\"}" | grep -q "\"subject\":\"$WS\",\"tainted\":true" &&
  echo true > /tmp/tg-p && t=$(new 2m < /tmp/tg-p) && grep -q "\"tainted\":true" /tmp/tg-new && wait_end $t 60'
check "  ... a pre-restore snapshot holds the tree the undo replaced; the audit has the signed workspace.restore" '
  P=$(sql "SELECT id FROM workspace_snapshots WHERE task=? AND kind=?" $T pre-restore) && [ -e $SN/$P/after ] &&
  cat /var/lib/agentbox/audit/seg-*.jsonl | grep "\"name\":\"workspace.restore\"" | grep "\"workspace\":\"$WS\"" | grep -q "\"signer\":\"rootd-admin:root\""'
check "  ... after 7 more tasks 5 task-start snapshots are left; the clean-baseline and pre-restore ones stay" 'for i in $(seq 7); do t=$(new 2m < /tmp/tg-p) && wait_end $t 60 || exit 1; done;
  sql "SELECT kind, count(*) FROM workspace_snapshots WHERE workspace=? GROUP BY kind ORDER BY kind" "$WS" | tee /tmp/tg-kinds &&
  [ "$(cat /tmp/tg-kinds | tr "\n" " ")" = "clean-baseline|1 pre-restore|1 task-start|5 " ] && [ "$(ls $SN | wc -l)" = 7 ] && [ -d $SN/$BASE ]'
check "  ... and undo of the pruned task now says so" '! $B task undo --task $T > /tmp/tg-undo2 2>&1; cat /tmp/tg-undo2; grep -q pruned /tmp/tg-undo2'
btrfs subvolume create $W/tg-nested >/dev/null
check "  ... a nested subvolume made on the host: task new fails with snapshot_failed and NESTED_SUBVOLUME, before any launch (#184)" '
  ! $B task new --agent gt --cli sh --deadline 2m < /tmp/tg-p > /tmp/tg-nest 2>&1; cat /tmp/tg-nest;
  grep -q "\"reason\":\"snapshot_failed\"" /tmp/tg-nest && grep -q NESTED_SUBVOLUME /tmp/tg-nest && [ -z "$(pod ps -a --format "{{.Names}}" | grep task-)" ]'
btrfs subvolume delete $W/tg-nested >/dev/null
check "  ... with it deleted by hand, the next task starts and completes" 't=$(new 2m < /tmp/tg-p) && wait_end $t 60 && [ "$(field $t end_reason)" = completed ]'

# --- #104: the offline workspace credential scan ---
# a second agent, so the token is in its workspace before its first task; the token is made here, never committed
W2=/var/lib/agentbox/data/workspaces/gs GHT=ghp_$(head -c 600 /dev/urandom | tr -dc A-Za-z0-9 | head -c 36)
scans() { journalctl -b -u agentbox-rootd -o cat | grep "secret scan $1: "; }
check "#104: agent add gs: rootd scans the new workspace in its no-network unit" '$B agent add --name gs >/dev/null && U2=$(id -u ag-gs) && i=0;
  until systemctl is-active -q user@$U2.service; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done && scans gs | grep -q "0 hits, .*netdevs \[lo\]$"'
runuser -u ag-gs -- mkdir -p $W2/notes && runuser -u ag-gs -- sh -c "printf 'x\nGH_TOKEN=%s\n' $GHT > $W2/notes/creds.txt"
echo 'echo ran > /workspace/gs.ran' > /tmp/tg-p
check "  ... a planted GitHub token blocks its first task; the block names the file and the token type, never the token" '
  ! $B task new --agent gs --cli sh --deadline 2m < /tmp/tg-p > /tmp/tg-sec 2>&1; cat /tmp/tg-sec; [ ! -e $W2/gs.ran ] &&
  grep -q "\"reason\":\"secrets_in_workspace\"" /tmp/tg-sec && grep -qF "notes/creds.txt:2 (github-pat)" /tmp/tg-sec && ! grep -qF "$GHT" /tmp/tg-sec &&
  ! journalctl -b -o cat | grep -qF "$GHT" && ! grep -rqF "$GHT" /var/lib/agentbox/audit /var/lib/agentbox/rootd.db'
check "  ... --ack-secrets 2 (not the count) is refused; --ack-secrets 1 lets the task start, and it completes" '
  ! $B task new --agent gs --cli sh --deadline 2m --ack-secrets 2 < /tmp/tg-p > /tmp/tg-sec2 2>&1; grep -q secrets_ack_mismatch /tmp/tg-sec2 &&
  $B task new --agent gs --cli sh --deadline 2m --ack-secrets 1 < /tmp/tg-p > /tmp/tg-new && t=$(sed -n "s/.*\"task\":\"\(task_[0-9A-Z]*\)\".*/\1/p" /tmp/tg-new) &&
  wait_end $t 60 && [ "$(field $t end_reason)" = completed ] && [ -e $W2/gs.ran ]'
check "  ... an egress grant for github.com:443 names the token type, agent and file; one for pypi.org:443 names none" '
  $B egress allow --svc proxy --entry github.com:443 > /tmp/tg-eg; $B egress remove --svc proxy --entry github.com:443 >/dev/null; cat /tmp/tg-eg;
  grep -qF "a github-pat in gs'"'"'s workspace (notes/creds.txt:2)" /tmp/tg-eg && ! grep -qF "$GHT" /tmp/tg-eg &&
  $B egress allow --svc proxy --entry pypi.org:443 > /tmp/tg-eg2; $B egress remove --svc proxy --entry pypi.org:443 >/dev/null; cat /tmp/tg-eg2;
  grep -q "\"ok\":true" /tmp/tg-eg2 && ! grep -q github-pat /tmp/tg-eg2'
check "  ... once the token is removed, the next task scans clean and starts" 'rm $W2/notes/creds.txt && rm -f $W2/gs.ran && t=$(newg < /tmp/tg-p) &&
  wait_end $t 60 && [ -e $W2/gs.ran ] && scans gs | tail -1 | grep -q " 0 hits, "'
check "  ... the scanner had no network: each scan saw only lo; run on the host instead it sees the NIC, which rootd would refuse (the control)" '
  scans "[a-z]*" | tee /tmp/tg-scans | tail -3; [ "$(wc -l < /tmp/tg-scans)" -ge 5 ] && ! grep -v "netdevs \[lo\]$" /tmp/tg-scans &&
  $B secretscan --dir $W2 | grep -q "\"netdevs\":\[\"lo\",\""'
$B agent remove --name gs >/dev/null 2>&1 || :

# --- the box afterwards ---
check "sockets check: the live per-task dirs and sockets match the inventory" '$B sockets check'
check "no task is left live, and no task container exists" 'sleep 5; [ "$($B task list | python3 -c "import json,sys; print(sum(1 for t in json.load(sys.stdin)[\"tasks\"] if \"end_reason\" not in t))")" = 0 ] &&
  [ -z "$(pod ps -a --format "{{.Names}}" | grep task-)" ]'
systemctl stop agentbox-proxy-stub agentbox-keys-stub agentbox-git-stub agentbox-proxy-stub.socket agentbox-keys-stub.socket agentbox-git-stub.socket
rm -f $RS/agentbox-*-stub.* $RS/agentboxd.service.d/50-tg.conf /usr/bin/claude; systemctl daemon-reload; systemctl restart agentboxd
check "the audit chain verifies" '$B audit verify'
check "no failed units" 'sleep 3; [ -z "$(systemctl --failed --no-legend --plain)" ]'
journalctl -b -u agentbox-rootd -o short-precise --no-pager | grep -E "task|ALERT" | tail -80
journalctl -b -u agentboxd -o short-precise --no-pager | tail -30
cat /tmp/tg-check.log | tail -80
echo "fails=$fails"
EOF
  ;;
*) die "unknown stage $s (install or checks)" ;;
esac; done
[ -n "${KEEP_VM:-}" ] || echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "tasks gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "tasks gate: all checks passed"

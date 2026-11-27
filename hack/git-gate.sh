#!/bin/sh
# Git service gate (PLAN.md row 7-8; ARCHITECTURE.md §5.2, §5.3, §6.3; issues #19 and #105, and the git items of
# PROPOSALS-v5.3 C-G4) on the local arm64 QEMU VM, none mode, through the real rootd, agentboxd, auditd, agentbox-git
# and rootless podman.
#   hack/git-gate.sh [install|release|checks ...]   default: install checks
# install  hack/gate.sh none: the unattended install and the release pipeline, so agentbox-git, its units, the hook
#          and git arrive the real way.
# release  installs this checkout as a new release on the running VM with its own install.sh, for iterating on a box
#          that install made.
# checks   a stub GitHub on the host (hack/git-gate/stub: TLS for github.com and api.github.com from a throwaway CA,
#          git smart HTTP over bare repos and the REST calls agentbox-git makes) on 127.0.0.1:7900+ID, which vm.sh
#          forwards to the guest as 10.0.2.2 for this boot only (AGENTBOX_VM_FWD). On the box (hack/git-gate/checks.sh):
#          the CA in the system store, a NAT rule that sends agentbox-git's https connections to the stub, and an
#          allow_private4 tuple for it in rootd.db; github.com:443 and api.github.com:443 on service.list; the stub's
#          fake token through secret set; agents gg, gt and go and their remotes (remote.set). Tasks run as sh
#          scripts (AGENTBOX_TEST_CLI=sh) and talk to the real git.sock through the in-task forwarder on :8082 and to
#          the gate with `agentbox gate call`. Covers:
#          #19: remote writes only through registry ops and only to the agent's own remotes (a direct push fails, a
#          local push reaches no remote, another agent's remote and a missing one are one NOT_FOUND_OR_NOT_OWNED,
#          nothing reaches the stub before an approval); repo.push and gh.pr.create succeed once approved, the PR body
#          ends with the op marker, and the git nft drop counters stay at 0; rootd killed between a comment POST and
#          its RESULT: reconcile finds the marker and writes RESULT, with no second comment; a tainted task's push
#          taints its ref and its commit; merging the tainted branch taints main, merging a clean one doesn't.
#          #105: the canary in the key slot, GITHUB_TOKEN, ~/.netrc and gh hosts.yml; a push with it in a file,
#          base64-encoded or split across two lines is refused with EXFIL_CANARY and stores nothing, taints the task,
#          writes audit and alerts; a gh.pr.create body with it is refused; a clean push still succeeds; a gitleaks
#          credential pattern in a push alerts; a git service restart mid-task keeps the task's socket and canary.
#          C-G4: a push to refs/heads/main prints REF_OUTSIDE_NAMESPACE and the JSON line; a push over the daily cap
#          (budget set git.push_bytes_day) prints CAP_REACHED{push_bytes_day} and stores no objects; a missing repo and another agent's give
#          byte-identical 404s 200 ms or more after receipt; a fake 422 gives REMOTE_REJECTED and its text reaches no
#          task byte. #108: the token is ciphertext at rest, and only agentbox-git reads it. A-G13: agentbox-git
#          installs the service seccomp filter. Then: the stub's token in no audit record or journal line, the audit
#          chain, sockets, fwcheck, no failed units.
# Not covered: a real GitHub repo and token, and the task's read taint on fetch (go test covers it: every task of an
# agent shares one workspace, so the box has no clean task once one is tainted).
# PASS/FAIL lines go to .vm/git-gate.txt, command output to .vm/git-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/git-gate.txt" LOG="$VM/git-gate.log"
UP_PORT=$((7900 + ${AGENTBOX_VM_ID:-0}))
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
# up: a boot with the stub's port forwarded; a VM already up with it stays
up() { [ -f "$VM/git-gate.fwd" ] && running && return 0; ! running || vm_off; rm -f "$VM/git-gate.fwd"
  { AGENTBOX_VM_FWD=$UP_PORT hack/vm.sh boot >>"$LOG" 2>&1 & }; wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"
  echo '[ "$(timeout 600 systemctl is-system-running --wait)" = running ] || systemctl --failed --no-pager' | root >>"$LOG" 2>&1 || :
  touch "$VM/git-gate.fwd"; }
# journal: the services' journals, the check output and the stub's log, for the evidence
journal() { echo 'journalctl -b -u agentbox-git -u agentbox-rootd -o short-precise --no-pager | tail -600; cat /run/gg/check.log' | root > "$VM/git-gate-journal.txt" 2>&1 || :
  cp "$VM/git-gate/stub.log" "$VM/git-gate-stub.txt" 2>/dev/null || :; }
# guest PHASE: run checks.sh PHASE on the box with the stub's port and token
guest() {
  { printf 'mkdir -p /run/gg && cat > /run/gg/checks.sh <<"GGEOF"\nUP=%s TOKEN=%s\n' "$UP_PORT" "$TOKEN"; cat hack/git-gate/checks.sh; printf 'GGEOF\nsh /run/gg/checks.sh %s\n' "$1"; } |
    root >"$VM/guest.out" 2>>"$LOG" || :
  while IFS= read -r l; do case $l in PASS*|FAIL*) log "$l" ;; *) echo "$l" >>"$LOG" ;; esac; done <"$VM/guest.out"
  grep -q '^fails=' "$VM/guest.out" || log "FAIL the $1 block on the VM did not finish (see $LOG)"
}

for s; do case $s in
install)
  rm -f "$VM/git-gate.fwd"
  hack/gate.sh none >>"$LOG" 2>&1 || die "hack/gate.sh none failed; see $VM/gate-none.txt"
  log "PASS install: hack/gate.sh none (install, release pipeline, firstboot, no failed units)" ;;
release)
  up
  V=0.0.2-dev$(date +%s)
  R=$(mktemp -d "$VM/rel.XXXXXX")
  make -s release VERSION="$V" MINISIGN_KEY="$VM/keys/minisign.key" DIST="$R" >/dev/null
  hack/vm.sh ssh 'rm -rf /tmp/rel && mkdir /tmp/rel && tar -xz -C /tmp/rel' < "$R/agentbox-$V.tgz"
  rm -rf "$R"
  # install.sh only enables: start the new sockets, restart the services on the new binary, and do reconcile's git/ step
  echo 'sh /tmp/rel/install.sh --from-firstboot && chown agentbox-git:agentbox-git /var/lib/agentbox/git && chmod 0700 /var/lib/agentbox/git &&
    systemctl restart agentbox-rootd.service agentboxd.service && systemctl start agentbox-git-svc.socket && systemctl restart agentbox-git.service' |
    root >>"$LOG" 2>&1 || die "install.sh $V failed; see $LOG"
  log "installed release $V" ;;
checks)
  K="$VM/git-gate"
  rm -rf "$K" && mkdir -p "$K/stub"
  TOKEN=gatetoken-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  go build -o "$K/stub-bin" ./hack/git-gate/stub || die "build the stub"
  "$K/stub-bin" -listen "127.0.0.1:$UP_PORT" -dir "$K/stub" -token "$TOKEN" >"$K/stub.log" 2>&1 &
  SPID=$!
  trap 'kill $SPID 2>/dev/null || :' EXIT
  i=0; until [ -f "$K/stub/ca.pem" ]; do i=$((i+1)); [ $i -lt 50 ] || die "the stub did not start (see $K/stub.log)"; sleep 0.2; done
  up
  { echo x; cat "$K/stub/ca.pem"; } | hack/vm.sh ssh 'sudo -S -p "" sh -c "mkdir -p /run/gg && cat > /run/gg/ca.pem"' || die "copy the CA"
  CHECKED=1
  guest setup
  ! grep -q '^[0-9:]* FAIL' "$OUT" || { journal; die "the box setup failed; see $OUT and $VM/git-gate-journal.txt"; }
  guest main
  journal ;;
*) die "unknown stage $s (install, release, checks)" ;;
esac; done
[ -n "${CHECKED:-}" ] || exit 0
! grep -q '^[0-9:]* FAIL' "$OUT" || die "git gate failed; see $OUT and $LOG"
log "git gate: all checks passed"

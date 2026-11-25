#!/bin/sh
# Task image integrity and config lint gate (issues #102 and #109; ARCHITECTURE.md §4.2) on the local QEMU VM, arm64
# UEFI, none mode, through the real rootd, agentboxd and auditd and rootless podman.
#   hack/image-gate.sh [install|checks ...]   default: both, in order
# install  hack/gate.sh none: the unattended install and the release pipeline, so the task image and SHA256SUMS
#          reach the box inside the signed release (install.sh).
# checks   The release's task image is the one SHA256SUMS names, the same bytes the fixture tool rebuilds; a task
#          loads it into the agent's podman under its config digest, and the agent's user manager has podman
#          auto-update masked. Then the release's image is swapped, by bind mounts over the release's file and its
#          SHA256SUMS, for each fixture of hack/image-fixtures, each in a fresh agent podman after a rootd restart:
#          - a byte appended, SHA256SUMS kept: refused IMAGE_RELEASE_SHA256;
#          - the release's index, manifest and config with other layer bytes under the pinned layer digest (the
#            GHSA-pggw-qqjf-6cxw shape): refused IMAGE_BLOB_MISMATCH;
#          - an Env entry with no '=', an io.containers.autoupdate label, a WORKDIR through a symlink, a WORKDIR
#            that is a hard link to a symlink, a USER (tasks run keep-id) and a checkpoint label: refused IMAGE_ENV,
#            IMAGE_AUTOUPDATE_LABEL, IMAGE_WORKDIR (both), IMAGE_USER and IMAGE_CHECKPOINT.
#          Each refusal is the typed task.start reply (reason image_refused, the code), the task never runs, and the
#          agent's podman holds no image afterwards: nothing reached podman load. With the release's image back, a
#          task runs again under the same image ID.
# PASS/FAIL lines go to .vm/image-gate.txt, command output to .vm/image-gate.log; exit 1 on any FAIL.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
[ $# -gt 0 ] || set -- install checks
OUT="$VM/image-gate.txt" LOG="$VM/image-gate.log"
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
  rm -rf "$VM/image-fixtures"
  go run ./hack/image-fixtures -arch arm64 -out "$VM/image-fixtures" >>"$LOG" 2>&1 || die "hack/image-fixtures failed"
  up
  tar -C "$VM/image-fixtures" -cf - . | hack/vm.sh ssh 'rm -rf /tmp/ig-fx && mkdir /tmp/ig-fx && tar -C /tmp/ig-fx -xf -' ||
    die "copying the fixtures to the VM failed"
  guest <<'EOF'
fails=0
cd /
check() { if (eval "$2") >>/tmp/ig-check.log 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
B=/var/lib/agentbox/current/bin/agentbox
REL=$(readlink -f /var/lib/agentbox/current)
IMG=$REL/image/task.oci.tar SUMS=$REL/SHA256SUMS NAME=image/linux-arm64/task.oci.tar
F=/tmp/ig-fx
W=/var/lib/agentbox/data/workspaces/gi
upod() { systemd-run --user -M ag-gi@ --wait --pipe --quiet --collect podman "$@" </dev/null; }
# cfgid ARCHIVE: its config digest, which podman uses as the image ID
cfgid() { python3 -c 'import json,sys,tarfile
t=tarfile.open(sys.argv[1]); r=lambda n: t.extractfile(n).read()
print(json.loads(r("blobs/sha256/"+json.loads(r("index.json"))["manifests"][0]["digest"][7:]))["config"]["digest"][7:])' "$1"; }
sum() { sha256sum < "$1" | cut -d" " -f1; }
field() { $B task list | python3 -c 'import json,sys; t=[x for x in json.load(sys.stdin)["tasks"] if x["task"]==sys.argv[1]]; print(t[0].get(sys.argv[2],"") if t else "")' "$1" "$2"; }
wait_end() { i=0; while [ -z "$(field "$1" end_reason)" ]; do i=$((i+1)); [ $i -lt 300 ] || return 1; sleep 0.2; done; }
# A rootd restart restarts the agent's user manager too (Requires=), which keeps systemd's default start limit of 5
# starts in 10 s (#257): at most one restart in 2.5 s. The start waits until the user manager is back.
restart_rootd() { sleep 2.5; systemctl restart agentbox-rootd.service && systemctl is-active -q agentbox-rootd.service &&
  systemctl start "user@$(id -u ag-gi).service"; }
# empty: the agent's podman answers, and holds no image
empty() { ims=$(upod images -q) && [ -z "$ims" ]; }
# fresh: the agent's podman with no image, and a rootd that has loaded nothing yet
fresh() { upod rmi -a -f >/dev/null 2>&1 || :; empty && restart_rootd; }
# runs: a task completes, as the agent uid, and the agent's podman holds only the image with ID $1
runs() { rm -f $W/ig.uid; echo 'id -u > /workspace/ig.uid' | $B task new --agent gi --cli sh --deadline 2m > /tmp/ig-new &&
  T=$(sed -n 's/.*"task":"\(task_[0-9A-Z]*\)".*/\1/p' /tmp/ig-new) && wait_end $T && [ "$(field $T end_reason)" = completed ] &&
  [ "$(cat $W/ig.uid)" = "$(id -u ag-gi)" ] && [ "$(upod images -q --no-trunc | sed 's/^sha256://' | sort -u)" = "$1" ]; }
# swap FILE: FILE in place of the release's task image, and SHA256SUMS naming it unless $2 = keep
swap() { cp $SUMS /tmp/ig-sums; [ "${2:-}" = keep ] || awk -v n=$NAME -v s=$(sum "$1") '$2 == n {$1 = s} {print $1 "  " $2}' $SUMS > /tmp/ig-sums
  mount --bind "$1" $IMG && mount --bind /tmp/ig-sums $SUMS; }
unswap() { umount $SUMS 2>/dev/null; umount $IMG 2>/dev/null; :; }
# refused CODE: task.start's reply is image_refused with CODE, no task runs, and nothing reached podman load
refused() { rm -f $W/ig.uid; echo 'id -u > /workspace/ig.uid' | $B task new --agent gi --cli sh --deadline 2m > /tmp/ig-new 2>&1; cat /tmp/ig-new
  grep -q '"reason":"image_refused"' /tmp/ig-new && grep -q "\"code\":\"$1\"" /tmp/ig-new && sleep 1 && [ ! -e $W/ig.uid ] &&
  empty && journalctl -u agentbox-rootd.service --since "-60s" | grep -q "$1"; }

mkdir -p /run/systemd/system/agentboxd.service.d && printf '[Service]\nEnvironment=AGENTBOX_TEST_CLI=sh\n' > /run/systemd/system/agentboxd.service.d/50-ig.conf
systemctl daemon-reload && systemctl restart agentboxd.service
check "agent add gi, and its user manager runs" '{ $B agent add --name gi || $B agent list | grep -q "\"name\":\"gi\""; } && U=$(id -u ag-gi) &&
  i=0; until systemctl is-active -q user@$U.service; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.2; done'
find $W -mindepth 1 -delete 2>/dev/null || :
GOOD=$(cfgid $IMG)
check "the release ships the task image under the sha256 its SHA256SUMS names (#102)" '[ -n "$GOOD" ] && [ "$(sum $IMG)" = "$(awk -v n=$NAME "\$2 == n {print \$1}" $SUMS)" ]'
check "  ... the same bytes hack/image-fixtures rebuilds from the source (task.Archive)" 'cmp $IMG $F/good.oci.tar'
check "podman auto-update is masked in the agent's user manager (#109)" '[ "$(systemctl --user -M ag-gi@ is-enabled podman-auto-update.timer)" = masked ] &&
  [ "$(systemctl --user -M ag-gi@ is-enabled podman-auto-update.service)" = masked ]'
check "a task loads the release's image and runs as the agent uid; its podman image ID is the archive's config digest" 'fresh && runs $GOOD'
check "  ... named localhost/agentbox-task:<tag> on that ID" '[ "$(upod image inspect --format "{{.Id}}" "$(upod images --format "{{.Repository}}:{{.Tag}}" | grep agentbox-task)")" = $GOOD ]'

cp $IMG /tmp/ig-plus1 && printf x >> /tmp/ig-plus1
check "a byte appended to the release's task image, SHA256SUMS unchanged: refused IMAGE_RELEASE_SHA256" 'fresh && swap /tmp/ig-plus1 keep && refused IMAGE_RELEASE_SHA256'
unswap
for f in blob:IMAGE_BLOB_MISMATCH env:IMAGE_ENV autoupdate:IMAGE_AUTOUPDATE_LABEL workdir:IMAGE_WORKDIR hardlink:IMAGE_WORKDIR user:IMAGE_USER checkpoint:IMAGE_CHECKPOINT; do
  n=${f%%:*} c=${f#*:}
  check "fixture $n, SHA256SUMS naming it: refused $c before podman load" 'fresh && swap $F/$n.oci.tar && refused $c'
  unswap
done
check "the release's image back: a task runs again under the same image ID" 'mountpoint -q $IMG && exit 1; fresh && runs $GOOD'
rm -f /run/systemd/system/agentboxd.service.d/50-ig.conf && systemctl daemon-reload
check "no failed units" '[ -z "$(systemctl --failed --no-legend --plain)" ]'
echo "fails=$fails"
EOF
  ;;
*) die "unknown scenario $s (install or checks)" ;;
esac; done
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
grep -q '^[0-9:]* FAIL' "$OUT" && { echo "image gate: FAIL; see $OUT"; exit 1; }
grep -q 'ABORT' "$OUT" && exit 1
echo "image gate: all checks passed"

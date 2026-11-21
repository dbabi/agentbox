#!/bin/sh
# Power-cut fidelity for the local QEMU VM (PLAN.md week 2 Harness; LEDGER C-dev-env-qemu-05). `vm.sh cut` keeps every
# write QEMU already handed to the Mac, so it models a disk with no volatile write cache only. Here QEMU's blklogwrites
# driver logs every guest disk write and flush in dm-log-writes format, and xfstests replay-log rebuilds the disk as it
# was after any log entry. The disk at a flush is what a power cut leaves on a disk whose write cache loses everything
# the guest has not flushed yet.
# Not modeled: subsets or reorderings of the writes since the last flush (a replay is a prefix, in the order QEMU took
# the writes), torn sectors, disks that ignore flushes, discards (-drive drops them before the log), and UEFI vars and
# TPM state (they keep their end-of-run contents). QEMU 11.1's NVMe controller drops the FUA bit, so a FUA write counts
# as durable only at the next flush; on DISKBUS=virtio the guest kernel flushes after each FUA write instead. `check`
# reads plain btrfs only (encryption none); ext4, the ESP, the btrfs log tree and data checksums are left to `boot`.
# Seen once: QEMU 11.1.3 left a 15.7 MiB hole in a 9.9 GB install log (virtio); marks, check and boot stop there.
#   hack/powercut.sh log <vm.sh command> [args]  run hack/vm.sh <command> (boot or install) with the log on; the disk as
#                                                it was before the run is the replay base
#   hack/powercut.sh writes [rounds]             in the running VM: fsynced atomic replaces and appends on btrfs and
#                                                ext4, then the grubenv replace of ARCHITECTURE §3.3 step 8 (default 50;
#                                                once per disk)
#   hack/powercut.sh marks                       the log's entry count and the entry number of every flush
#   hack/powercut.sh check [from [to [every]]]   btrfs check --readonly at every flush (or the first and every
#                                                <every>-th after it) in log entries from..to; default the whole log.
#                                                Several ranges can run at once.
#   hack/powercut.sh boot <entry>...             boot the disk as replayed to each entry: it must boot the entry GRUB
#                                                picks on that disk, clean, with the writes files consistent, and once
#                                                health has settled a trial the cut left, run the committed entry,
#                                                which saved_entry names, with no next_entry
#   hack/powercut.sh grub [from [to]]            after every log entry that writes /bootpart, read it as GRUB does
#                                                (ext4 with no journal replay): the entry GRUB boots must be in
#                                                grub.cfg, with its kernel and initrd. Catches a grub.cfg or grubenv
#                                                replace that only Linux, which replays the journal, sees as atomic.
#                                                Then lists the splits: entries next to a change of the next_entry or
#                                                saved_entry GRUB reads where Linux reads others. Boot them.
# Replays run on Linux: hack/powercut/replay.sh, as root in the agentbox-powercut container of the podman machine (built
# once; after editing hack/powercut/Containerfile, run `podman --connection podman-machine-default-root rmi
# agentbox-powercut`). The base and the log live in $TMPDIR/agentbox-powercut-ID, which the machine mounts.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh. Test seeds only: sudo uses the password "x".
set -eu
die() { echo "powercut.sh: $*" >&2; exit 1; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VM="$ROOT/.vm"
ID=${AGENTBOX_VM_ID:-0}
case $ID in [0-9]) ;; *) die "AGENTBOX_VM_ID must be 0-9" ;; esac
PC="${TMPDIR:-/tmp}/agentbox-powercut-$ID" # podman machine mounts the Mac's /var/folders and /private, not /Volumes
PODMAN="podman --connection podman-machine-default-root" # loop devices need root in the machine
running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }
# boot sets the VM disk aside as disk.qcow2.powercut; a killed run leaves it there, and a later mv would overwrite it
aside() { [ ! -e "$VM/disk.qcow2.powercut" ] || die "$VM/disk.qcow2.powercut is the disk a killed 'boot' set aside; move it back"; }
num() { for a; do case $a in ''|*[!0-9]*) die "not a number: $a" ;; esac; done; }
# No ssh-agent: with AddKeysToAgent, every checkout's .vm/id_vm piles up in it, and sshd hangs up after 6 wrong offers.
vmssh() { SSH_AUTH_SOCK='' "$ROOT/hack/vm.sh" ssh "$@"; }
root_sh() { { echo x; cat; } | vmssh 'sudo -S -p "" sh -s'; } # stdin: a script for root in the VM

# replay <replay.sh args>: replay.sh in the podman machine, with $PC as its /w
replay() {
  [ -f "$PC/log.bin" ] || die "no log in $PC; run 'powercut.sh log boot' first"
  [ -f "$PC/base.qcow2" ] || qemu-img info "$VM/disk.qcow2" | sed -n 's/^virtual size: .*(\([0-9]*\) bytes)$/\1/p' > "$PC/base.size"
  $PODMAN image exists agentbox-powercut || $PODMAN build -q -t agentbox-powercut "$ROOT/hack/powercut" >/dev/null
  $PODMAN run --rm -i --privileged -v /dev:/dev -v "$PC:/w" agentbox-powercut \
    sh -c 'cat > /tmp/replay.sh && exec sh /tmp/replay.sh "$@"' sh "$@" < "$ROOT/hack/powercut/replay.sh"
}

cmd=${1:-}; [ $# -gt 0 ] && shift
case "$cmd" in
log)
  [ $# -gt 0 ] || die "usage: powercut.sh log <vm.sh command> [args]"
  running && die "a VM is running"
  aside
  mkdir -p "$PC" && rm -f "$PC/base.qcow2" "$PC/base.size" "$PC/image.qcow2" "$PC/image.expect" "$PC/boot.txt"
  [ ! -f "$VM/disk.qcow2" ] || cp "$VM/disk.qcow2" "$PC/base.qcow2" # none before an install: the base is an empty disk
  : > "$PC/log.bin" # QEMU's file driver opens the log, it never creates it
  export AGENTBOX_BLKLOG="$PC/log.bin"
  exec "$ROOT/hack/vm.sh" "$@"
  ;;
writes)
  rounds=${1:-50}; num "$rounds"
  # Each step is durable before the next starts, so at any flush: g <= kE <= kB <= g+1, where kB and kE count the
  # records in $B/log and $E/log and g is grubenv's agentbox_powercut; each state file holds k or k+1.
  # uutils `sync FILE` (Ubuntu 26.04's sync) calls sync(2), not fsync: gnusync fsyncs, so btrfs uses its log tree.
  { echo "R=$rounds"; cat <<'EOF'; } | root_sh
set -eu
B=/var/lib/agentbox/powercut E=/bootpart/agentbox/powercut G=/boot/grub/grubenv
[ ! -e $B ] && [ ! -e $E ] || { echo "writes: already ran on this disk" >&2; exit 1; }
command -v gnusync >/dev/null || { echo "writes: needs gnusync (gnu-coreutils)" >&2; exit 1; }
mkdir $B $E
i=0
while [ $i -lt $R ]; do i=$((i + 1))
  for d in $B $E; do
    printf 'gen %06d\n' $i > $d/state.new; gnusync $d/state.new; mv $d/state.new $d/state; gnusync $d
    printf 'rec %06d\n' $i >> $d/log; gnusync $d/log
  done
  # ARCHITECTURE §3.3 step 8 as written, with the system's sync
  cp $G $G.new; grub-editenv $G.new set agentbox_powercut=$i; sync $G.new; mv $G.new $G; sync ${G%/*}
done
echo "writes: $i rounds"
EOF
  ;;
marks) replay marks ;;
grub) num "$@"; replay grub "$@" ;;
check)
  num "$@"; [ "${3:-1}" -gt 0 ] || die "every must be 1 or more"
  replay check "$@"
  ;;
boot)
  [ $# -gt 0 ] || die "usage: powercut.sh boot <entry>..."
  num "$@"
  running && die "a VM is running"
  aside
  [ -f "$VM/disk.qcow2" ] && [ ! -L "$VM/disk.qcow2" ] || die "no VM disk to set aside"
  mv "$VM/disk.qcow2" "$VM/disk.qcow2.powercut" # the disk the logged run left, back in place on exit
  trap 'kill ${q:-} 2>/dev/null || :; rm -f "$VM/disk.qcow2" "$PC/image.qcow2"; mv "$VM/disk.qcow2.powercut" "$VM/disk.qcow2"' EXIT
  trap 'exit 1' INT TERM
  failed=0
  for e in "$@"; do
    replay image "$e"
    read -r want from < "$PC/image.expect"
    case $want in *[!0-9A-Za-z.+~_-]*|-) echo "entry $e: FAIL the replayed disk names no valid entry to boot ($want)"
      failed=$((failed + 1)); continue ;; esac
    ln -s "$PC/image.qcow2" "$VM/disk.qcow2"
    "$ROOT/hack/vm.sh" boot & q=$!
    end=$(( $(date +%s) + 720 ))
    until vmssh true 2>/dev/null; do
      kill -0 $q 2>/dev/null && [ "$(date +%s)" -lt "$end" ] || break
      sleep 5
    done
    { echo "want=$want from=$from"; cat <<'EOF'; } | root_sh > "$PC/boot.txt" 2>&1 || :
fails=0
check() { if (eval "$2") >/dev/null 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi; }
# see `writes`: g <= kE <= kB <= g+1, and each state file holds k or k+1 (all 0 before writes ran)
writes() {
  env=$(grub-editenv /boot/grub/grubenv list) || return 1
  g=$(printf '%s\n' "$env" | sed -n 's/^agentbox_powercut=//p'); g=${g:-0}
  set --
  for d in /var/lib/agentbox/powercut /bootpart/agentbox/powercut; do k=0 n=0
    [ ! -f $d/log ] || k=$(awk '$0 != sprintf("rec %06d", NR) { bad = 1 } END { if (bad) exit 1; print NR }' $d/log) || return 1
    [ ! -f $d/state ] || { n=$(sed -n 's/^gen 0*\([0-9][0-9]*\)$/\1/p' $d/state); [ -n "$n" ]; } || return 1
    [ $k -le $n ] && [ $n -le $((k + 1)) ] || return 1
    set -- "$@" $k
  done
  echo "g=$g kB=$1 kE=$2"
  [ $g -le $2 ] && [ $2 -le $1 ] && [ $1 -le $((g + 1)) ]
}
g=$(findmnt -n -o FSROOT /); g=${g#/@}
echo "booted agentbox-$g-$(uname -r); GRUB's $from on the replayed disk: $want; writes: $(writes || :)"
journalctl -k -b -o cat | grep -E "recovery complete|tree-log replay" | sed 's/^/recovered: /' # a journal the cut left
check "boots the $from entry" '[ "agentbox-$g-$(uname -r)" = "$want" ]'
check "/boot is $g's boot dir" '[ "$(findmnt -n -o FSROOT /boot)" = "/agentbox/gens/$g" ]'
check "no btrfs or ext4 errors in the kernel log" '! journalctl -k -b -o cat | grep -qE "BTRFS (error|critical)|EXT4-fs error"'
check "top level holds only @* (firstboot cleanup)" 'mkdir -p /run/chk && mount -o subvolid=5 "$(findmnt -n -v -o SOURCE /)" /run/chk || exit 1; i=0; while ls -A /run/chk | grep -qv "^@"; do i=$((i+1)); [ $i -lt 36 ] || { umount /run/chk; exit 1; }; sleep 5; done; umount /run/chk'
# health settles a trial the cut left (commits it if it booted, else marks it failed). The grubenv Linux reads then is
# the one GRUB reads next: systemd-fsck replayed /bootpart's journal home before the mount, and grubenv replaces
# checkpoint.
settled() {
  i=0; while [ -e /var/lib/agentbox/os/pending.json ]; do i=$((i + 1)); [ $i -lt 60 ] || return 1; sleep 5; done
  c=$(cat /bootpart/agentbox/committed) env=$(grub-editenv /boot/grub/grubenv list) || return 1
  [ "agentbox-$g-$(uname -r)" = "$c" ] && printf '%s\n' "$env" | grep -qx "saved_entry=$c" && ! printf '%s\n' "$env" | grep -q '^next_entry=.'
}
check "settles: runs the committed entry, saved_entry names it, no next_entry, no trial pending" settled
echo "settled: committed $(cat /bootpart/agentbox/committed); $(grub-editenv /boot/grub/grubenv list | grep -e ^saved_entry= -e ^next_entry= | tr '\n' ' ')os/: $(ls /var/lib/agentbox/os 2>/dev/null | tr '\n' ' ')"
check "no failed units" '[ -z "$(systemctl --failed --no-legend --plain)" ]'
check "writes files consistent" writes
echo "fails=$fails"
EOF
    sed "s/^/entry $e: /" "$PC/boot.txt"
    grep -q '^fails=0$' "$PC/boot.txt" || { failed=$((failed + 1)); grep -q '^fails=' "$PC/boot.txt" || echo "entry $e: FAIL no SSH"; }
    echo 'systemctl poweroff' | root_sh >/dev/null 2>&1 || :
    end=$(( $(date +%s) + 120 ))
    while kill -0 $q 2>/dev/null && [ "$(date +%s)" -lt "$end" ]; do sleep 2; done
    kill $q 2>/dev/null || :; wait $q 2>/dev/null || :; q=
    rm "$VM/disk.qcow2"
  done
  echo "boot: $# entries, $failed failed"
  [ $failed -eq 0 ]
  ;;
*) die "usage: powercut.sh log <vm.sh command> [args] | writes [rounds] | marks | check [from [to [every]]] | boot <entry>... | grub [from [to]]" ;;
esac

#!/bin/sh
# Linux side of hack/powercut.sh: runs as root in the agentbox-powercut container (Containerfile next to this file), with
# the work dir at /w: log.bin (dm-log-writes format) and base.qcow2, the disk when the log started (base.size instead
# for a log that starts on an empty disk).
#   replay.sh marks                         the entry count, then the entry number of every flush
#   replay.sh check [from [to [every]]]     replay; btrfs check --readonly each btrfs partition at every <every>-th flush
#                                           in entries from..to (default 0..last, every flush)
#   replay.sh image <entry>                 /w/image.qcow2: the disk after <entry>; /w/image.expect: the entry GRUB boots
#   replay.sh grub [from [to]]              replay; after every entry in from..to that writes /bootpart, read it as GRUB
#                                           does: the entry GRUB boots must be in grub.cfg, with its kernel and initrd
# Replayed file systems are only read through read-only loop devices and never mounted, so a corrupt one can't reach
# the kernel of the podman machine that other VMs' containers share.
set -eu
die() { echo "replay.sh: $*" >&2; exit 1; }
LOG=/w/log.bin T=/var/tmp/disk.raw

if [ "${1:-}" = mark ]; then # replay-log --fsck hook, run after each flush entry: the replayed disk is at that flush
  n=$(($(cat /tmp/n) + 1)); echo "$n" > /tmp/n
  [ $((n % $2)) -eq 0 ] || { echo "mark skip"; exit 0; }
  st=ok
  for l in $(cat /tmp/btrfs); do
    blockdev --flushbufs "$l" # replay-log wrote the file under this loop device's cache
    # the superblock generation shows each check reads the disk as replayed so far
    g=$(btrfs inspect-internal dump-super "$l" | awk '$1 == "generation" { print $2 }')
    btrfs check --readonly "$l" > /tmp/out 2>&1 || { st=FAIL; sed "s|^|    $l: |" /tmp/out; }
  done
  echo "mark $st $g"
  exit 0
fi
if [ "${1:-}" = grubview ]; then # replay-log --fsck hook of grub below, run after every entry
  read -r n < /tmp/n; echo $((n + 1)) > /tmp/n
  [ -e "/tmp/e4/$n" ] || exit 0
  read -r l < /tmp/ext4
  blockdev --flushbufs "$l"
  # GRUB ignores a grubenv without its header; with no next_entry or saved_entry, 09_agentbox's fallback picks committed
  env=$(debugfs -R "cat /grub/grubenv" "$l" 2>/dev/null) || :
  case $env in "# GRUB Environment Block"*) ;; *) env= ;; esac
  cfg=$(debugfs -R "cat /grub/grub.cfg" "$l" 2>/dev/null) || :
  for v in next_entry saved_entry; do
    want=$(printf '%s\n' "$env" | sed -n "s/^$v=//p") from=$v
    [ -z "$want" ] || break
  done
  [ -n "$want" ] || want=$(printf '%s\n' "$cfg" | sed -n 's/.*set default="\(agentbox-[^"]*\)".*/\1/p') from=committed
  r=${want#agentbox-gen-}
  files() { for f in vmlinuz initrd.img; do
    debugfs -R "stat /agentbox/gens/gen-${r%%-*}/$f-${r#*-}" "$l" 2>/dev/null | grep -q 'Size: [1-9]' || return 1; done; }
  if [ -n "$want" ] && printf '%s\n' "$cfg" | grep -qF -- "--id '$want'" && files; then echo "grub ok $n"; else echo "grub FAIL $n $from ${want:--}"; fi
  exit 0
fi

: > /tmp/loops
trap 'while read -r l; do losetup -d "$l" || :; done < /tmp/loops' EXIT
trap 'exit 1' INT TERM
entries() { replay-log --log "$LOG" --num-entries; }
# the disk as it was when the log started, as a sparse raw file
base() { if [ -f /w/base.qcow2 ]; then qemu-img convert -O raw /w/base.qcow2 "$T"; else truncate -s "$(cat /w/base.size)" "$T"; fi; }
# loops <fstype>: a read-only loop device on each partition of the replayed disk that holds <fstype>
loops() {
  partx -g -o START,SECTORS "$T" | while read -r s n; do
    l=$(losetup -f --show -r -o $((s * 512)) --sizelimit $((n * 512)) "$T") || continue
    if [ "$(blkid -p -s TYPE -o value "$l")" = "$1" ]; then echo "$l" >> /tmp/loops; echo "$l"; else losetup -d "$l"; fi
  done
}

case ${1:-} in
marks)
  echo "entries $(entries)"
  # a replay onto /dev/null reads every entry and writes nothing; a malformed entry ends it early, and that must fail
  { replay-log -v --log "$LOG" --replay /dev/null && echo "rc 0" || echo "rc $?"; } | awk 'BEGIN { rc = -1 }
    $1 == "rc" { rc = $2; next }
    /FLUSH|FUA/ { t = /FLUSH/ ? "flush" : "fua"; sub(/@.*/, "", $2); print t, $2 }
    END { if (rc != 0) { print "replay-log exited " rc ": the list stops at the first unreadable entry"; exit 1 } }'
  ;;
check)
  n=$(entries) from=${2:-0}; to=${3:-$((n - 1))} every=${4:-1}
  [ "$from" -lt "$n" ] && [ "$from" -le "$to" ] || die "entries $from..$to are not in the log (entries 0..$((n - 1)))"
  base
  [ "$from" -eq 0 ] || replay-log --log "$LOG" --replay "$T" --limit "$from"
  loops btrfs > /tmp/btrfs
  [ -s /tmp/btrfs ] || die "no btrfs partition on the disk at entry $from"
  echo 0 > /tmp/n
  # replay-log runs the hook after each flush entry; -v names each entry just before, and stdbuf keeps the two in order.
  # set -e ends the { } subshell at a failing command, so its status goes through && / ||.
  { stdbuf -oL replay-log -v --log "$LOG" --replay "$T" --start-entry "$from" --limit $((to - from + 1)) \
      --check flush --fsck "sh $0 mark $every" && echo "rc 0" || echo "rc $?"; } | awk -v from="$from" -v every="$every" '
    BEGIN { rc = -1 }
    $1 == "replaying" { e = $2; sub(/@.*/, "", e); if (/FUA/ && !/FLUSH/) fua++; next }
    $1 == "mark" { m++; st[$2]++; if ($2 != "skip") print "entry " e ": btrfs check " $2 " at btrfs generation " $3; next }
    $1 == "rc" { rc = $2; next }
    { print }
    END {
      printf "entries %d..%d: %d flushes, %d checked (every %d), %d failed\n", from, e, m, st["ok"] + st["FAIL"], every, st["FAIL"]
      if (rc != 0) print "replay-log exited " rc
      if (m == 0) print "no flush in the range: nothing checked"
      if (fua > 0) print fua " FUA entries without a flush: not checked"
      exit (rc != 0 || m == 0 || fua > 0 || st["FAIL"] > 0)
    }'
  ;;
image)
  n=$(entries) e=$2
  [ "$e" -lt "$n" ] || die "entry $e is not in the log (entries 0..$((n - 1)))"
  base
  replay-log --log "$LOG" --replay "$T" --limit $((e + 1))
  qemu-img convert -O qcow2 "$T" /w/image.qcow2
  # The entry GRUB boots, read as GRUB reads ext4 (no journal replay): next_entry (a one-shot trial), else saved_entry,
  # else the committed file that 09_agentbox falls back to. GRUB ignores a grubenv without its header.
  want= from=none
  for l in $(loops ext4); do
    debugfs -R "stat /agentbox" "$l" 2>/dev/null | grep -q '^Inode:' || continue
    env=$(debugfs -R "cat /grub/grubenv" "$l" 2>/dev/null)
    case $env in "# GRUB Environment Block"*) ;; *) env= ;; esac
    for v in next_entry saved_entry; do
      x=$(printf '%s\n' "$env" | sed -n "s/^$v=//p")
      [ -z "$x" ] || { want=$x from=$v; break; }
    done
    [ -n "$want" ] || { want=$(debugfs -R "cat /agentbox/committed" "$l" 2>/dev/null) && [ -n "$want" ] && from=committed; } || :
    break
  done
  echo "${want:--} $from" > /w/image.expect
  ;;
grub)
  # GRUB reads ext4 without replaying the journal, so a cut shows it each block of /bootpart as last written home
  n=$(entries) from=${2:-0}; to=${3:-$((n - 1))}
  [ "$from" -lt "$n" ] && [ "$from" -le "$to" ] && [ "$to" -lt "$n" ] || die "entries $from..$to are not in the log (entries 0..$((n - 1)))"
  base
  [ "$from" -eq 0 ] || replay-log --log "$LOG" --replay "$T" --limit "$from"
  for l in $(loops ext4); do debugfs -R "stat /agentbox" "$l" 2>/dev/null | grep -q '^Inode:' && { echo "$l" > /tmp/ext4; break; }; done
  [ -s /tmp/ext4 ] || die "no ext4 partition with /agentbox on the disk at entry $from"
  # the entries that write /bootpart's sectors
  set -- $(losetup -l -n -O OFFSET,SIZELIMIT "$(cat /tmp/ext4)")
  mkdir /tmp/e4
  replay-log -v --log "$LOG" --replay /dev/null | awk -v s=$(($1 / 512)) -v e=$((($1 + $2) / 512)) -v from="$from" -v to="$to" '
    $1 == "replaying" { n = $2; sub(/@.*/, "", n); n += 0
      if (n >= from && n <= to && $6 + 0 > 0 && $4 + 0 < e && $4 + $6 / 512 > s) print "/tmp/e4/" n }' | xargs -r touch
  echo "$from" > /tmp/n
  { replay-log --log "$LOG" --replay "$T" --start-entry "$from" --limit $((to - from + 1)) --check 1 --fsck "sh $0 grubview" &&
      echo "rc 0" || echo "rc $?"; } | awk -v from="$from" -v to="$to" '
    $1 == "grub" { c++; if ($2 == "FAIL") { f++; print "entry " $3 ": FAIL GRUB finds no bootable " $4 " entry (" $5 ")" }; next }
    $1 == "rc" { rc = $2; next }
    { print }
    END {
      printf "entries %d..%d: %d writes to /bootpart, %d where GRUB finds no bootable entry\n", from, to, c, f
      if (rc != 0) print "replay-log exited " rc
      exit (rc != 0 || c == 0 || f > 0)
    }'
  ;;
*) die "usage: replay.sh marks | check [from [to [every]]] | image <entry> | grub [from [to]]" ;;
esac

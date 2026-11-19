#!/bin/sh
# Linux side of hack/powercut.sh: runs as root in the agentbox-powercut container (Containerfile next to this file), with
# the work dir at /w: log.bin (dm-log-writes format) and base.qcow2, the disk when the log started (base.size instead
# for a log that starts on an empty disk).
#   replay.sh marks                         the entry count, then the entry number of every flush
#   replay.sh check [from [to [every]]]     replay; btrfs check --readonly each btrfs partition at the first flush in
#                                           entries from..to and every <every>-th after it (default 0..last, every flush)
#   replay.sh image <entry>                 /w/image.qcow2: the disk after <entry>; /w/image.expect: the entry GRUB boots
#   replay.sh grub [from [to]]              replay; after every entry in from..to that writes /bootpart, read it as GRUB
#                                           does: the entry GRUB boots must be in grub.cfg, with its kernel and initrd.
#                                           Then list the splits: entries next to a change of the next_entry or
#                                           saved_entry GRUB reads where Linux, which replays the journal, reads others
# Replayed file systems are only read through read-only loop devices and never mounted, so a corrupt one can't reach
# the kernel of the podman machine that other VMs' containers share.
set -eu
die() { echo "replay.sh: $*" >&2; exit 1; }
# grubfs <debugfs command> <ext4 device>: read it as GRUB does, with no journal replay and no bitmaps or checksums (a
# cut can leave a bitmap and its group descriptor from different transactions, and plain debugfs then refuses to open)
grubfs() { debugfs -c -n -R "$1" "$2" 2>/dev/null; }
# envof <ext4 device>: ne and se, the next_entry and saved_entry in its /grub/grubenv ("-" for none). GRUB ignores a
# grubenv without its header.
envof() {
  e=$(grubfs "cat /grub/grubenv" "$1") || :
  case $e in "# GRUB Environment Block"*) ;; *) e= ;; esac
  ne=$(printf '%s\n' "$e" | sed -n 's/^next_entry=//p') se=$(printf '%s\n' "$e" | sed -n 's/^saved_entry=//p')
  ne=${ne:--} se=${se:--}
}
LOG=/w/log.bin T=/var/tmp/disk.raw

if [ "${1:-}" = mark ]; then # replay-log --fsck hook, run after each flush entry: the replayed disk is at that flush
  n=$(($(cat /tmp/n) + 1)); echo "$n" > /tmp/n
  [ $(((n - 1) % $2)) -eq 0 ] || { echo "mark skip"; exit 0; } # the first flush, then every <every>-th
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
  # with no next_entry or saved_entry, 09_agentbox's fallback picks committed
  envof "$l"
  cfg=$(grubfs "cat /grub/grub.cfg" "$l") || :
  want=$ne from=next_entry
  [ "$want" != - ] || want=$se from=saved_entry
  [ "$want" != - ] || want=$(printf '%s\n' "$cfg" | sed -n 's/.*set default="\(agentbox-[^"]*\)".*/\1/p') from=committed
  r=${want#agentbox-gen-}
  files() { for f in vmlinuz initrd.img; do
    grubfs "stat /agentbox/gens/gen-${r%%-*}/$f-${r#*-}" "$l" | grep -q 'Size: [1-9]' || return 1; done; }
  if [ -n "$want" ] && printf '%s\n' "$cfg" | grep -qF -- "--id '$want'" && files; then st=ok; else st=FAIL; fi
  echo "grub $st $n $from ${want:--} $ne $se"
  exit 0
fi
if [ "${1:-}" = splitview ]; then # replay-log --fsck hook of grub's second pass, run after every entry
  read -r n < /tmp/n; echo $((n + 1)) > /tmp/n
  [ -e "/tmp/lb/$n" ] || exit 0
  read -r l < /tmp/ext4
  blockdev --flushbufs "$l"
  envof "$l"; g="$ne $se"
  # Linux replays the journal before it mounts /bootpart (systemd-fsck): replay it on a scratch copy
  dd if="$l" of=/var/tmp/bootpart.img bs=1M conv=sparse status=none
  e2fsck -E journal_only -y /var/tmp/bootpart.img >/dev/null 2>&1 || [ $? -lt 4 ] || { echo "nojournal $n"; exit 0; }
  envof /var/tmp/bootpart.img
  [ "$g" = "$ne $se" ] || echo "split $n $g $ne $se"
  exit 0
fi

: > /tmp/loops
unloop() { while read -r l; do losetup -d "$l" || :; done < /tmp/loops; : > /tmp/loops; }
trap unloop EXIT
trap 'exit 1' INT TERM
entries() { replay-log --log "$LOG" --num-entries; }
# the disk as it was when the log started, as a sparse raw file
base() { rm -f "$T"; if [ -f /w/base.qcow2 ]; then qemu-img convert -O raw /w/base.qcow2 "$T"; else truncate -s "$(cat /w/base.size)" "$T"; fi; }
# loops <fstype>: a read-only loop device on each partition of the replayed disk that holds <fstype>
loops() {
  partx -g -o START,SECTORS "$T" | while read -r s n; do
    l=$(losetup -f --show -r -o $((s * 512)) --sizelimit $((n * 512)) "$T") || continue
    if [ "$(blkid -p -s TYPE -o value "$l")" = "$1" ]; then echo "$l" >> /tmp/loops; echo "$l"; else losetup -d "$l"; fi
  done
}
# ext4loop <entry>: /tmp/ext4 names the loop device on /bootpart, the ext4 partition that holds /agentbox
ext4loop() {
  for l in $(loops ext4); do grubfs "stat /agentbox" "$l" | grep -q '^Inode:' && { echo "$l" > /tmp/ext4; return; }; done
  die "no ext4 partition with /agentbox on the disk at entry $1"
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
      exit (rc != 0 || st["ok"] + st["FAIL"] == 0 || fua > 0 || st["FAIL"] > 0)
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
    grubfs "stat /agentbox" "$l" | grep -q '^Inode:' || continue
    env=$(grubfs "cat /grub/grubenv" "$l")
    case $env in "# GRUB Environment Block"*) ;; *) env= ;; esac
    for v in next_entry saved_entry; do
      x=$(printf '%s\n' "$env" | sed -n "s/^$v=//p")
      [ -z "$x" ] || { want=$x from=$v; break; }
    done
    [ -n "$want" ] || { want=$(grubfs "cat /agentbox/committed" "$l") && [ -n "$want" ] && from=committed; } || :
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
  ext4loop "$from"
  # the entries that write /bootpart's sectors, and the flushes
  set -- $(losetup -l -n -O OFFSET,SIZELIMIT "$(cat /tmp/ext4)")
  mkdir /tmp/e4
  : > /tmp/flushes
  replay-log -v --log "$LOG" --replay /dev/null | awk -v s=$(($1 / 512)) -v e=$((($1 + $2) / 512)) -v from="$from" -v to="$to" '
    $1 == "replaying" { n = $2; sub(/@.*/, "", n); n += 0
      if (n < from || n > to) next
      if (/FLUSH/) print n > "/tmp/flushes"
      if ($6 + 0 > 0 && $4 + 0 < e && $4 + $6 / 512 > s) print "/tmp/e4/" n }' | xargs -r touch
  echo "$from" > /tmp/n
  ok=0
  # Where the next_entry or saved_entry GRUB reads changes, the replace's journal commit can come before: back to the
  # last flush, Linux may already read the new ones. Those entries go to /tmp/lb.list for the second pass.
  { replay-log --log "$LOG" --replay "$T" --start-entry "$from" --limit $((to - from + 1)) --check 1 --fsck "sh $0 grubview" &&
      echo "rc 0" || echo "rc $?"; } | awk -v from="$from" -v to="$to" '
    BEGIN { while ((getline x < "/tmp/flushes") > 0) fl[++nf] = x + 0 }
    $1 == "grub" { n = $3 + 0; c++
      if ($2 == "FAIL") { f++; print "entry " n ": FAIL GRUB finds no bootable " $4 " entry (" $5 ")" }
      while (k < nf && fl[k + 1] < n) k++
      if (c > 1 && $6 " " $7 != pv) {
        ch++; print n > "/tmp/lb.list"; if (k) print fl[k] > "/tmp/lb.list"
        for (i = c - 1; i > 0 && (!k || w[i] > fl[k]); i--) print w[i] > "/tmp/lb.list"
      }
      pv = $6 " " $7; w[c] = n; next }
    $1 == "rc" { rc = $2; next }
    { print }
    END {
      printf "entries %d..%d: %d writes to /bootpart, %d where GRUB finds no bootable entry, %d that change the next_entry or saved_entry it reads\n", from, to, c, f, ch
      if (rc != 0) print "replay-log exited " rc
      exit (rc != 0 || c == 0 || f > 0)
    }' || ok=1
  [ -s /tmp/lb.list ] || exit $ok
  # second pass: at those entries, GRUB's view against Linux's. A split is no failure (every rename has one, until the
  # checkpoint); powercut.sh boot checks that the box settles from each.
  mkdir /tmp/lb
  sed 's|^|/tmp/lb/|' /tmp/lb.list | xargs touch
  last=$(sort -n /tmp/lb.list | tail -n 1)
  unloop
  base
  [ "$from" -eq 0 ] || replay-log --log "$LOG" --replay "$T" --limit "$from"
  ext4loop "$from"
  echo "$from" > /tmp/n
  { replay-log --log "$LOG" --replay "$T" --start-entry "$from" --limit $((last - from + 1)) --check 1 --fsck "sh $0 splitview" &&
      echo "rc 0" || echo "rc $?"; } | awk -v k="$(sort -un /tmp/lb.list | wc -l)" '
    $1 == "split" { s++; print "entry " $2 ": split: GRUB reads next_entry=" $3 " saved_entry=" $4 ", Linux reads next_entry=" $5 " saved_entry=" $6; next }
    $1 == "nojournal" { f++; print "entry " $2 ": FAIL e2fsck cannot replay the journal of /bootpart"; next }
    $1 == "rc" { rc = $2; next }
    { print }
    END {
      printf "%d entries at and before those changes: %d splits, where Linux reads another next_entry or saved_entry after journal replay\n", k, s
      if (rc != 0) print "replay-log exited " rc
      exit (rc != 0 || f > 0)
    }' || ok=1
  exit $ok
  ;;
*) die "usage: replay.sh marks | check [from [to [every]]] | image <entry> | grub [from [to]]" ;;
esac

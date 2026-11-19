#!/bin/sh
# os.apply gates (PLAN.md week 1 day 4, ARCHITECTURE.md §3.3 and the §15 row 1-2) on the local QEMU VM.
#   hack/apply-gate.sh none|tpm2|tpm2+tang [uefi|bios] [install|setup|cycles|breaks|cuts ...]   default: all five, in order
# uefi (default) is the arm64 VM, bios the amd64 one under TCG (hack/gate.sh's boot modes).
# install  hack/gate.sh's unattended install and install checks.
# setup    checks what firstboot left (gate.sh's release as /var/lib/agentbox/current, agentbox-health.timer enabled,
#          `os mark-last-good` run) and sets a boot deadline of DEADLINE s (default 300).
# cycles   holds systemd one archive version back (in place, a test fixture: the install took the newest), then gen-2
#          removes the newest kernel and gen-3 brings it back with every systemd binary upgraded (a kernel and systemd
#          change whose initrd dracut builds inside the nspawn), gen-4 prunes gen-1; then current cold-boots and previous
#          boots once. (Run again on a used box, the generation numbers are higher and the oldest one is pruned.)
# breaks   a trial broken in GRUB, in the initrd (clevis removed; btrfs in none mode), in fstab (/boot bound to the
#          parent's dir; a /boot device that never appears), and by a unit that blocks boot forever: each falls back to
#          the committed generation with no console input. After the GRUB break, health drops the kernel-less entry
#          and retention refuses to prune while a kept fstab binds the trial. Then a clean apply commits, and an
#          emptied grubenv boots that committed generation, not entry 0.
# cuts     QMP power cuts (vm.sh cut) at five points of an apply and right after it returns, then the grubenv a cut can
#          leave split between GRUB and Linux, a next_entry write that fails after its rename, and a clean apply that
#          commits and discards every interrupted build. At "boot once" a grub-editenv first on the apply's PATH holds
#          `set next_entry=`, so that cut lands with pending.json on disk and next_entry not yet written. The cuts hit a
#          bad moment for GRUB only by chance, so one more apply, trial and commit runs logged (hack/powercut.sh log),
#          and powercut.sh grub reads /bootpart as GRUB does after every write to it. Needs the podman machine.
# Every plan also checks that apt ran none of the box's update hooks: update-success-stamp stays as it was.
# Checks print PASS/FAIL to .vm/apply-gate-<mode>[-bios].txt, command output goes to .vm/apply-gate-<mode>[-bios].log;
# exit 1 on any FAIL. AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
ENC=${1:?usage: hack/apply-gate.sh none|tpm2|tpm2+tang [uefi|bios] [install|setup|cycles|breaks|cuts ...]}
case "$ENC" in none|tpm2|tpm2+tang) ;; *) echo "usage: hack/apply-gate.sh none|tpm2|tpm2+tang [uefi|bios] [scenario ...]" >&2; exit 2 ;; esac
shift
BOOT=uefi; case ${1:-} in uefi|bios) BOOT=$1; shift ;; esac
TAG=$ENC; [ "$BOOT" = uefi ] || TAG=$ENC-bios
[ $# -gt 0 ] || set -- install setup cycles breaks cuts
DEADLINE=${DEADLINE:-300}
OUT="$VM/apply-gate-$TAG.txt" LOG="$VM/apply-gate-$TAG.log"
A=/var/lib/agentbox/current/bin/agentbox
mkdir -p "$VM"
fails=0
# a laptop that idles to sleep freezes the VM and the Tang container mid-scenario, and the wall-clock waits then fail
! command -v caffeinate >/dev/null || { caffeinate -i -w $$ & }

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT"; }
die() { log "ABORT $*"; exit 1; }
# CODE names the variables it uses ("\$C" or '$C'), so eval expands what the guest reported as data, never as code
# (hack/apply_gate_test.go replays every check line with values that are shell syntax)
check() { if (eval "$2") >>"$LOG" 2>&1; then log "PASS $1"; else log "FAIL $1"; fails=$((fails+1)); fi; }
vssh() { hack/vm.sh ssh "$@"; }
root() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s'; } # stdin: a script run as root on the VM
bootid() { vssh cat /proc/sys/kernel/random/boot_id 2>/dev/null || :; }
booted() { vssh 'g=$(findmnt -no FSROOT /); echo "agentbox-${g#/@}-$(uname -r)"'; }
committed() { vssh cat /bootpart/agentbox/committed; }
# deadline_fired ENTRY: the boot before this one ended with the boot deadline rebooting ENTRY, not with a crash or the
# watchdog (-b -1: journalctl rejects /proc's dashed boot_id)
deadline_fired() { echo 'journalctl -b -1 -o cat -u agentbox-boot-deadline.service' | root | grep -qxF "agentbox: boot deadline: $1 is not committed; rebooting into the committed generation"; }
# sysd: the versions of the installed binaries built from source systemd
sysd() { root <<'EOF'
dpkg-query -W -f '${source:Package} ${Version} ${db:Status-Abbrev}\n' | awk '$1 == "systemd" && $3 == "ii" {print $2}' | sort -u
EOF
}
running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }
# wait_boot OLD SECONDS: until SSH answers from a boot other than OLD
wait_boot() {
  end=$(( $(date +%s) + $2 ))
  while :; do b=$(bootid); [ -n "$b" ] && [ "$b" != "$1" ] && return 0; [ "$(date +%s)" -lt $end ] || return 1; sleep 5; done
}
# wait_root SECONDS CMD: until CMD succeeds as root on the VM (the health timer runs every minute)
wait_root() {
  end=$(( $(date +%s) + $1 ))
  until echo "$2" | root >>"$LOG" 2>&1; do [ "$(date +%s)" -lt $end ] || return 1; sleep 10; done
}
settled() { wait_root 300 "test ! -e /var/lib/agentbox/os/pending.json"; }
up() {
  [ "$ENC" != tpm2+tang ] || hack/vm.sh tang up >>"$LOG"
  running || { hack/vm.sh boot >>"$LOG" 2>&1 & }
  wait_boot none 900 || die "no SSH (see $VM/boot-*.log)"
}
status() { echo "$A os status" | root >>"$LOG" 2>&1 || :; }
# stamp: the mtime of the file apt's 15update-stamp hook touches after every successful apt-get update
stamp() { echo 'stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || :' | root; }
# plan ARGS: plans on the VM, logs the plan, sets H. Planning runs none of the running generation's apt hooks.
plan() {
  s=$(stamp)
  H=$(echo "$A os plan $* 2>>/tmp/gate-plan.err" | root | tee -a "$LOG" | sed -n 's/^plan sha256: //p')
  [ -n "$H" ] || die "os plan $* failed: $(echo 'tail -5 /tmp/gate-plan.err' | root)"
  check "plan $*: apt ran no update hook on the running generation" '[ "$(stamp)" = "$s" ]'
}
# build: os apply --approve H --no-reboot; sets M (the new generation) and E (its entry)
build() {
  echo "$A os apply --approve $H --no-reboot" | root >"$VM/apply.out" 2>&1 || { cat "$VM/apply.out" >>"$LOG"; die "os apply failed"; }
  cat "$VM/apply.out" >>"$LOG"
  M=$(sed -n 's/^built \(gen-[0-9]*\):.*/\1/p' "$VM/apply.out") E=$(sed -n 's/.* tries \(agentbox-[^ ]*\) once.*/\1/p' "$VM/apply.out")
  [ -n "$M" ] && [ -n "$E" ] || die "no generation in the apply output"
  K=${E#agentbox-"$M"-}
}
reboot_vm() { echo 'systemctl reboot' | root >/dev/null 2>&1 || :; }
# the §3.3 build left nothing behind in the running generation
clean_root() {
  check "$1: no grub diversion, no policy-rc.d" "echo '! dpkg-divert --list | grep -q -e update-grub -e grub-install && test ! -e /usr/sbin/policy-rc.d' | root"
  check "$1: /boot is the booted generation's own dir, modules present" "echo 'g=\$(findmnt -no FSROOT /); [ \"\$(findmnt -n -o FSROOT /boot)\" = /agentbox/gens/\${g#/@} ] && test -d /lib/modules/\$(uname -r)' | root"
}
# trial NAME: reboot into the built trial E and wait for health to commit it
trial() {
  old=$(bootid); reboot_vm
  wait_boot "$old" 900 || die "$1: no SSH after the trial reboot"
  check "$1: boots $M (rootflags=subvol=@$M)" 'vssh grep -qw "rootflags=subvol=@$M" /proc/cmdline'
  wait_root 420 "[ \"\$(cat /bootpart/agentbox/committed)\" = $E ] && test ! -e /var/lib/agentbox/os/pending.json" || :
  check "$1: health committed $E" '[ "$(committed)" = "$E" ] && vssh "grub-editenv /boot/grub/grubenv list" | grep -qx "saved_entry=$E"'
  clean_root "$1"
  status
}
# wait_gen ENTRY OLD SECONDS: until a boot other than OLD runs ENTRY
wait_gen() {
  end=$(( $(date +%s) + $3 ))
  while :; do
    id=$(bootid)
    [ -n "$id" ] && [ "$id" != "$2" ] && [ "$(booted 2>/dev/null)" = "$1" ] && return 0
    [ "$(date +%s)" -lt $end ] || return 1
    sleep 5
  done
}
# fallback NAME SECONDS [TRIED]: reboot into the broken trial E; within SECONDS, with no console input, the box must run
# the committed generation C again, after GRUB took the one-shot boot of E. Settle marks a trial failed once any other
# generation boots, so the console since the reboot must also show TRIED (the trial's kernel ran). A trial that comes
# up (and so needs health plus the deadline) is logged.
fallback() {
  C=$(committed); old=$(bootid); t0=$(date +%s); seen=; TRIED=${3:-}
  S=$(ls -t "$VM"/boot-*.log | head -n 1); off=$(( $(wc -c <"$S") + 1 )) # vm.sh boot logs every reboot to one file
  I=$(vssh stat -c %i /boot/grub/grubenv)
  reboot_vm
  while :; do
    id=$(bootid) b=
    [ -z "$id" ] || [ "$id" = "$old" ] || b=$(booted 2>/dev/null) || :
    [ "$b" = "$C" ] && break
    if [ "$b" = "$E" ] && [ -z "$seen" ]; then seen=1; log "$1: the trial came up ($(vssh systemctl is-system-running)); health must refuse it"; fi
    if [ $(( $(date +%s) - t0 )) -ge "$2" ]; then # no unattended fallback: record it, power-cycle, go on
      log "FAIL $1: not back on $C within $2 s; QMP reset"; fails=$((fails+1))
      hack/vm.sh cut; wait_gen "$C" "$old" 900 || die "$1: no $C after the reset"; settled || :; return 0
    fi
    sleep 5
  done
  log "$1: back on $C after $(( $(date +%s) - t0 )) s"
  check "$1: falls back to the committed $C" '[ "$(committed)" = "$C" ]'
  # GRUB's 00_header empties next_entry when it boots it, in place (same inode); Linux replaces grubenv by rename
  check "$1: GRUB took the one-shot boot of $E" '[ -n "$I" ] && [ "$(vssh stat -c %i /boot/grub/grubenv)" = "$I" ] && vssh "grub-editenv /boot/grub/grubenv list" | grep -qx next_entry='
  [ -z "$TRIED" ] || check "$1: the console shows the trial $M ran ($TRIED)" 'tail -c +"$off" "$S" | grep -aqwF -e "$TRIED"'
  settled || :
  check "$1: trial $M marked failed" 'echo "test -e /var/lib/agentbox/os/failed/$M.json && test ! -e /var/lib/agentbox/os/pending.json" | root'
  status
}
# with_top CMDS: run CMDS as root with the btrfs top level at $T
with_top() {
  { echo 'set -e; T=/run/gate-top; mkdir -p $T; mount -o subvolid=5 "$(findmnt -n -v -o SOURCE /)" $T'; echo "$1"; echo 'umount $T'; } | root >>"$LOG" 2>&1
}

sc_install() { hack/gate.sh "$ENC" "$BOOT" >>"$LOG" 2>&1 || die "install gate failed (see $LOG and $VM/gate-$TAG.txt)"; cat "$VM/gate-$TAG.txt" >>"$OUT"; }

sc_setup() {
  up
  root >>"$LOG" 2>&1 <<EOF || die "setup failed"
set -e
mkdir -p /etc/systemd/system/agentbox-boot-deadline.service.d
printf '%s\n' '[Service]' 'Environment=AGENTBOX_BOOT_DEADLINE_SEC=$DEADLINE' > /etc/systemd/system/agentbox-boot-deadline.service.d/50-gate.conf
systemctl daemon-reload
sync # a power cut right after setup must not lose the drop-in
EOF
  check "setup: the box boots by $BOOT" '[ "$(vssh "test -d /sys/firmware/efi && echo uefi || echo bios")" = "$BOOT" ]'
  check "setup: firstboot installed the release and enabled the health timer" 'echo "test -x $A && test -e /var/lib/agentbox/.firstboot-done && systemctl is-enabled agentbox-health.timer" | root'
  check "setup: the booted generation is committed" "[ \"\$(committed)\" = \"\$(booted)\" ]"
  check "setup: boot deadline armed" "vssh systemctl is-active agentbox-boot-deadline.service"
  status
}

sc_cycles() {
  up
  # the install took the archive's newest systemd, so no closure could upgrade it: set every installed binary of source
  # systemd one archive version back, in place (os.apply itself never downgrades), and cycle 2 upgrades them for real
  root >"$VM/systemd.out" 2>&1 <<'EOF' || { cat "$VM/systemd.out" >>"$LOG"; die "cycles: could not set systemd one archive version back"; }
set -e
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1
apt-get -q update </dev/null
SN=$(apt-cache policy systemd | sed -n 's/^ *Candidate: //p') SO=
for v in $(apt-cache madison systemd | awk -F'|' '{gsub(/ /, "", $2); print $2}'); do
  dpkg --compare-versions "$v" lt "$SN" && { [ -z "$SO" ] || dpkg --compare-versions "$v" gt "$SO"; } && SO=$v
done
[ -n "$SO" ] || { echo "the archive has no systemd older than $SN"; exit 1; }
P=$(dpkg-query -W -f '${binary:Package} ${source:Package} ${db:Status-Abbrev}\n' | awk -v v="$SO" '$2 == "systemd" && $3 == "ii" {printf "%s=%s ", $1, v}')
if apt-get -s install --allow-downgrades $P </dev/null | grep '^Remv'; then exit 1; fi # it must only swap versions
apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold $P </dev/null
echo "gate: systemd $SO $SN"
EOF
  cat "$VM/systemd.out" >>"$LOG"
  SO=$(sed -n 's/^gate: systemd \([^ ]*\) .*/\1/p' "$VM/systemd.out")
  SN=$(sed -n 's/^gate: systemd [^ ]* \([^ ]*\)$/\1/p' "$VM/systemd.out")
  [ -n "$SO" ] && [ -n "$SN" ] || die "cycles: no systemd versions in $VM/systemd.out"
  old=$(bootid); reboot_vm; wait_boot "$old" 900 || die "cycles: no SSH after setting systemd back to $SO"
  check "cycles: the committed generation boots with systemd $SO (the archive has $SN)" '[ "$(sysd)" = "$SO" ] && [ "$(committed)" = "$(booted)" ]'
  KN=$(vssh uname -r)
  G0=$(vssh findmnt -no FSROOT /); G0=${G0#/@} # the generation cycles starts from: retention keeps it through cycle 2
  KO=$(vssh ls /boot | sed -n 's/^vmlinuz-//p' | grep -vx "$KN" | sort -rV | head -1)
  [ -n "$KO" ] || die "cycles: needs a second, older kernel next to $KN"
  O=$(vssh ls /bootpart/agentbox/gens | sed -n 's/^gen-\([1-9][0-9]*\)$/\1/p' | sort -n | head -1) # gen-1 on a fresh box
  log "cycles: kernels $KN (newest) and $KO; oldest generation gen-$O"
  plan --remove "linux-image-$KN" --remove "linux-modules-$KN"
  check "cycle 1: cas/ is its own btrfs subvolume (§3.2)" "echo '[ \"\$(stat -c %i /var/lib/agentbox/cas)\" = 256 ]' | root"
  build; trial "cycle 1 (remove $KN)"
  check "cycle 1: runs the older kernel $KO" '[ "$(vssh uname -r)" = "$KO" ]'
  plan --install linux-generic --install systemd
  build
  check "cycle 2: the build re-made initrd.img-$KN in the nspawn (newer than $G0's)" 'echo "test -e /bootpart/agentbox/gens/$G0/initrd.img-$KN && test /bootpart/agentbox/gens/$M/initrd.img-$KN -nt /bootpart/agentbox/gens/$G0/initrd.img-$KN" | root'
  trial "cycle 2 (kernel $KO -> $KN, systemd $SO -> $SN)"
  check "cycle 2: kernel upgraded to $KN" '[ "$(vssh uname -r)" = "$KN" ]'
  check "cycle 2: every systemd binary upgraded to $SN" '[ "$(sysd)" = "$SN" ]'
  check "cycle 2: the nspawn-built initrd loads the watchdog driver (force_drivers), PID 1 arms it" "echo 'grep -qx active /sys/class/watchdog/watchdog0/state' | root"
  [ "$ENC" = none ] || check "cycle 2: LUKS unlocked by clevis from the nspawn-built initrd" "vssh 'journalctl -b -o cat' | grep -q 'Finished systemd-cryptsetup@croot.service' && echo 'journalctl -b -t clevis-luks-askpass -o cat' | root | grep -q '^Unlocked '"
  plan --reinstall --install base-files
  build; trial "cycle 3"
  check "cycle 3: gen-$O pruned with its boot dir, gone from grub.cfg" 'echo "test ! -e /bootpart/agentbox/gens/gen-$O && ! grep -q agentbox-gen-$O- /boot/grub/grub.cfg && ! btrfs subvolume list / | grep -qw @gen-$O" | root'
  CUR=$E PREV="agentbox-gen-$(( ${M#gen-} - 1 ))-$KN"
  # current cold-boots
  echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
  while running; do sleep 2; done
  up
  check "cold boot: current $CUR" '[ "$(booted)" = "$CUR" ]'
  clean_root "cold boot"
  # previous boots once (next_entry written the §3.3 way: copy, edit, fsync, rename), then the deadline returns to current
  echo "cd /boot/grub && cp grubenv grubenv.new && grub-editenv grubenv.new set next_entry=$PREV && sync grubenv.new && mv grubenv.new grubenv && sync ." | root >>"$LOG" 2>&1
  old=$(bootid); reboot_vm; wait_boot "$old" 900 || die "previous: no SSH"
  check "previous: $PREV boots" '[ "$(booted)" = "$PREV" ]'
  clean_root "previous"
  old=$(bootid); t0=$(date +%s)
  wait_boot "$old" $((DEADLINE + 600)) || die "previous: never rebooted"
  log "previous: rebooted after $(( $(date +%s) - t0 )) s"
  check "previous: the boot deadline returned to $CUR, still committed" '[ "$(booted)" = "$CUR" ] && [ "$(committed)" = "$CUR" ] && deadline_fired "$PREV"'
  status
}

sc_breaks() {
  up
  plan --reinstall --install base-files
  build
  echo "rm /bootpart/agentbox/gens/$M/vmlinuz-$K" | root >>"$LOG" 2>&1 || die "could not delete vmlinuz-$K"
  fallback "GRUB break (vmlinuz-$K deleted after update-grub)" 600
  check "GRUB break: health drops $E, whose vmlinuz is gone, from grub.cfg" 'wait_root 180 "! grep -qF $E /boot/grub/grub.cfg"'
  plan --reinstall --install base-files
  # the build would prune the failed $M, but a kept generation's fstab (the running one's) binds its boot dir
  echo "echo '/bootpart/agentbox/gens/$M /mnt none bind,noauto 0 0' >> /etc/fstab" | root >>"$LOG" 2>&1
  check "retention guard: apply refuses to prune $M while a kept fstab binds it, and deletes nothing" 'echo "$A os apply --approve $H --no-reboot" | root 2>&1 | grep -q "retention refused" && echo "test -e /bootpart/agentbox/gens/$M/initrd.img-$K && btrfs subvolume list / | grep -qw @$M" | root'
  echo "sed -i '\\|^/bootpart/agentbox/gens/$M /mnt |d' /etc/fstab" | root >>"$LOG" 2>&1
  build
  if [ "$ENC" = none ]; then
    echo "dracut --force --omit-drivers btrfs /bootpart/agentbox/gens/$M/initrd.img-$K $K && ! lsinitrd /bootpart/agentbox/gens/$M/initrd.img-$K | grep -q /btrfs.ko" | root >>"$LOG" 2>&1 || die "could not break the initrd"
    fallback "initrd break (btrfs.ko removed)" 900 "rootflags=subvol=@$M"
  else
    echo "dracut --force --omit 'clevis clevis-pin-null clevis-pin-sss clevis-pin-tang clevis-pin-tpm2' /bootpart/agentbox/gens/$M/initrd.img-$K $K && ! lsinitrd /bootpart/agentbox/gens/$M/initrd.img-$K | grep -q clevis-luks-askpass" | root >>"$LOG" 2>&1 || die "could not break the initrd"
    fallback "initrd break (clevis removed: LUKS prompt times out)" 1200 "rootflags=subvol=@$M"
  fi
  # the clone bug the fstab rewrite prevents: systemd mounts the parent's dir (and would mkdir a missing bind source),
  # so the boot succeeds; health's /boot check refuses it and the deadline falls back
  plan --reinstall --install base-files
  build
  P=$(vssh findmnt -no FSROOT /); P=${P#/@} # the committed generation the box runs now
  with_top "sed -i 's|^/bootpart/agentbox/gens/$M /boot |/bootpart/agentbox/gens/$P /boot |' \$T/@$M/etc/fstab && grep -q '^/bootpart/agentbox/gens/$P /boot ' \$T/@$M/etc/fstab" || die "could not break fstab"
  fallback "fstab break (/boot still bound to the parent's gens/$P)" $((DEADLINE + 900)) "rootflags=subvol=@$M"
  check "fstab break: health refused $M for its /boot" "echo 'journalctl -u agentbox-health.service -o cat' | root | grep -qF \"not \$M's boot dir\""
  # a mount that can't happen: local-fs.target fails, and the emergency drop-in reboots after 120 s
  plan --reinstall --install base-files
  build
  with_top "sed -i 's|^/bootpart/agentbox/gens/$M /boot none bind[^ ]*|/dev/disk/by-uuid/00000000-0000-4000-8000-000000000000 /boot ext4 defaults|' \$T/@$M/etc/fstab && grep -q '^/dev/disk/by-uuid/00000000-0000-4000-8000-000000000000 /boot ' \$T/@$M/etc/fstab" || die "could not break fstab"
  fallback "fstab break (/boot device missing: emergency mode)" 1200 "rootflags=subvol=@$M"
  plan --reinstall --install base-files
  build
  with_top "printf '%s\n' '[Unit]' 'Description=gate: blocks boot forever' '[Service]' 'Type=oneshot' 'ExecStart=/bin/sleep infinity' 'TimeoutStartSec=infinity' > \$T/@$M/etc/systemd/system/agentbox-gate-block.service && ln -s ../agentbox-gate-block.service \$T/@$M/etc/systemd/system/multi-user.target.wants/" || die "could not add the blocking unit"
  C=$(committed); old=$(bootid); reboot_vm
  wait_gen "$E" "$old" 900 || die "blocking unit: the trial never came up"
  check "blocking unit: the trial $M boots and never finishes" "[ \"\$(vssh systemctl is-system-running)\" = starting ]"
  sleep 90
  check "blocking unit: health ran on $M and did not commit it" '[ "$(committed)" = "$C" ] && echo "journalctl -b -u agentbox-health.service -o cat" | root | grep -qF "trial $E not committed yet"'
  old=$(bootid); t0=$(date +%s)
  wait_gen "$C" "$old" $((DEADLINE + 600)) || die "blocking unit: never fell back"
  log "blocking unit: back on $C $(( $(date +%s) - t0 )) s later"
  check "blocking unit: the boot deadline fell back to the committed $C" '[ "$(committed)" = "$C" ] && deadline_fired "$E"'
  settled || :
  check "blocking unit: trial $M marked failed" 'echo "test -e /var/lib/agentbox/os/failed/$M.json" | root'
  status
  # a clean apply commits first: on a fresh box the committed gen-1 is entry 0 too (09_agentbox lists the oldest first),
  # and a GRUB that ignored the fallback below would boot it all the same
  plan --reinstall --install base-files
  build; trial "before the empty grubenv"
  # grubenv emptied (what a cut during an in-place grub-editenv leaves): GRUB boots the committed entry through
  # 09_agentbox's fallback, not entry 0 (the oldest generation), and the deadline keeps that boot up
  C=$(committed); old=$(bootid)
  Z=$(echo "awk '/^(menuentry|submenu) /{print; exit}' /boot/grub/grub.cfg" | root | sed -n "s/^menuentry .* --id '\([^']*\)'.*/\1/p")
  check "empty grubenv: entry 0 ($Z) is not the committed $C" '[ -n "$Z" ] && [ "$Z" != "$C" ]'
  echo ': > /boot/grub/grubenv && sync' | root >>"$LOG" 2>&1 || die "empty grubenv: could not empty it"
  reboot_vm; wait_boot "$old" 900 || die "empty grubenv: no SSH"
  check "empty grubenv: the boot had no saved_entry" 'vssh "test -e /boot/grub/grubenv && ! grep -qa saved_entry= /boot/grub/grubenv"'
  check "empty grubenv: boots the committed $C, not entry 0" '[ "$(booted)" = "$C" ]'
  old=$(bootid); sleep $((DEADLINE + 60))
  check "empty grubenv: the boot deadline leaves the committed boot up" '[ -n "$old" ] && [ "$(bootid)" = "$old" ]'
  echo "$A os mark-last-good" | root >>"$LOG" 2>&1
  check "empty grubenv: mark-last-good restores saved_entry" 'vssh "grub-editenv /boot/grub/grubenv list" | grep -qx "saved_entry=$C"'
}

# cut_at PHASE DELAY: power-cut the VM DELAY s after apply prints "os: PHASE" (PHASE built: its last line). At
# "boot once" the apply sets next_entry milliseconds later, so a grub-editenv first on its PATH holds `set next_entry=`:
# the cut lands with pending.json on disk and next_entry not written (powercut.sh grub covers the grubenv write itself).
cut_at() {
  plan --reinstall --install base-files
  C=$(committed); old=$(bootid); PRE=; PAT="^os: $1"
  [ "$1" != built ] || PAT='^built '
  if [ "$1" = "boot once" ]; then
    PRE='PATH=/run/gate-pause:$PATH ' # /run is tmpfs: the reset removes the pause
    root >>"$LOG" 2>&1 <<'EOF' || die "cut at boot once: could not install the grub-editenv pause"
mkdir -p /run/gate-pause
cat >/run/gate-pause/grub-editenv <<'P'
#!/bin/sh
case " $* " in *" set next_entry="*) : >/run/gate-pause/held; sleep 300 ;; esac
exec /usr/bin/grub-editenv "$@"
P
chmod 0755 /run/gate-pause/grub-editenv
EOF
  fi
  echo "$PRE$A os apply --approve $H --no-reboot" | root >"$VM/apply.out" 2>&1 &
  sp=$! end=$(( $(date +%s) + 900 ))
  until grep -q "$PAT" "$VM/apply.out"; do # the last grep: "built" comes right before the apply exits
    { [ "$(date +%s)" -lt $end ] && kill -0 $sp 2>/dev/null; } || grep -q "$PAT" "$VM/apply.out" || { cat "$VM/apply.out" >>"$LOG"; die "cut: apply never reached '$1'"; }
    sleep 0.2
  done
  [ -z "$PRE" ] || wait_root 120 "test -e /run/gate-pause/held" || { cat "$VM/apply.out" >>"$LOG"; die "cut at $1: the grub-editenv pause never held"; }
  sleep "$2"
  hack/vm.sh cut
  kill $sp 2>/dev/null || : # the reset guest never closes the session
  wait $sp 2>/dev/null || :
  cat "$VM/apply.out" >>"$LOG"
  # the reset guest prints nothing more: a "built" line means the apply had returned, and promised the one-time boot
  T=$(sed -n 's/.* tries \(agentbox-[^ ]*\) once.*/\1/p' "$VM/apply.out")
  G=$(sed -n 's/^os: clone gen-[0-9]* -> \(gen-[0-9]*\)$/\1/p' "$VM/apply.out")
  [ -n "$G" ] || die "cut at $1: no 'os: clone' line in the apply output"
  log "cut: QMP system_reset $2 s after '${PAT#^}'${PRE:+ (set next_entry held)}${T:+, after the apply returned}"
  wait_boot "$old" 900 || die "cut at $1: no SSH after the reset"
  b=$(booted)
  log "cut at $1: back on $b"
  if [ -n "$T" ]; then
    wait_root 420 "test ! -e /var/lib/agentbox/os/pending.json" || :
    check "cut at $1, after the apply returned: the trial $T boots and health commits it" '[ "$b" = "$T" ] && [ "$(committed)" = "$T" ]'
  else
    check "cut at $1: boots the committed $C" '[ "$b" = "$C" ] && [ "$(committed)" = "$C" ]'
    LEFT="$LEFT $G" # never committed: the next build must discard it
  fi
  settled || :
  [ "$1" != "boot once" ] || check "cut at boot once: pending.json was on disk, next_entry was not: health marked $G failed" 'echo "test -e /var/lib/agentbox/os/failed/$G.json" | root'
  check "cut at $1: grub.cfg intact, grubenv names the committed entry, no next_entry armed" "echo 'grub-script-check /boot/grub/grub.cfg && e=\$(grub-editenv /boot/grub/grubenv list) && echo \"\$e\" | grep -qxF \"saved_entry=\$(cat /bootpart/agentbox/committed)\" && ! echo \"\$e\" | grep -q \"^next_entry=.\"' | root"
  clean_root "cut at $1 (running $b)"
  status
}

# split_env: Linux's view after a cut inside the trial's SetGrubEnv, where GRUB booted the committed generation from the
# old grubenv while the replayed journal names the trial in next_entry and saved_entry (review-crash/both.txt). Settle
# must undo both before it marks the trial failed, or a later boot runs the failed trial.
split_env() {
  plan --reinstall --install base-files
  build
  C=$(committed)
  root >>"$LOG" 2>&1 <<EOF || die "split grubenv: could not set it up"
flock /var/lib/agentbox/os/lock sh -ec 'grub-editenv /boot/grub/grubenv set saved_entry=$E; sed -i "s/\"bootId\":\"[^\"]*\"/\"bootId\":\"gate\"/" /var/lib/agentbox/os/pending.json; grep -q "\"bootId\":\"gate\"" /var/lib/agentbox/os/pending.json'
EOF
  check "split grubenv: Settle puts back saved_entry=$C and clears next_entry, then fails $M" 'wait_root 180 "$A os health; test ! -e /var/lib/agentbox/os/pending.json" && echo "l=\$(grub-editenv /boot/grub/grubenv list) && echo \"\$l\" | grep -qx saved_entry=$C && echo \"\$l\" | grep -qx next_entry= && test -e /var/lib/agentbox/os/failed/$M.json" | root'
  status
}

# env_fail: the next_entry write fails after its rename (a grub-editenv shim fails its list check once). GRUB may boot
# gen-M, so it stays pending, as a power cut there leaves it, and the next boot tries it once.
env_fail() {
  plan --reinstall --install base-files
  root >>"$LOG" 2>&1 <<'EOF' || die "next_entry write: could not install the grub-editenv shim"
mkdir -p /run/gate-shim
printf '%s\n' '#!/bin/sh' 'if [ "$2" = list ] && grep -q "^next_entry=agentbox-" "$1" && rm /run/gate-shim/once 2>/dev/null; then exit 1; fi' \
  'exec /usr/bin/grub-editenv "$@"' > /run/gate-shim/grub-editenv
chmod 0755 /run/gate-shim/grub-editenv
touch /run/gate-shim/once
EOF
  ! echo "PATH=/run/gate-shim:\$PATH $A os apply --approve $H --no-reboot" | root >"$VM/apply.out" 2>&1 || die "next_entry write: the apply did not fail"
  cat "$VM/apply.out" >>"$LOG"
  echo 'rm -r /run/gate-shim' | root >>"$LOG" 2>&1
  E=$(sed -n 's/^os: boot once: //p' "$VM/apply.out") M=$(sed -n 's/^os: boot once: agentbox-\(gen-[0-9]*\)-.*/\1/p' "$VM/apply.out")
  [ -n "$M" ] || die "next_entry write: the apply never reached boot once"
  check "next_entry write fails after its rename: $M stays pending and armed, not discarded" 'grep -q "stays pending" "$VM/apply.out" && echo "test -e /var/lib/agentbox/os/pending.json && test -d /bootpart/agentbox/gens/$M && grub-editenv /boot/grub/grubenv list | grep -qx next_entry=$E" | root'
  trial "next_entry write failed"
}

sc_cuts() {
  up
  LEFT=
  cut_at clone 0
  cut_at "nspawn: apt-get install" 3
  cut_at "initrd gate" 0
  cut_at update-grub 0
  cut_at "boot once" 0
  cut_at built 0
  split_env
  env_fail
  plan --reinstall --install base-files
  build; trial "after the cuts"
  check "after the cuts: the interrupted builds$LEFT are gone (subvolume, boot dir, grub.cfg entry)" '[ -n "$LEFT" ] && echo "btrfs subvolume list / | grep -qw @$M || exit 1; for g in $LEFT; do ! btrfs subvolume list / | grep -qw @\$g && test ! -e /bootpart/agentbox/gens/\$g && ! grep -q \"agentbox-\$g-\" /boot/grub/grub.cfg || exit 1; done" | root'
  check "after the cuts: at most three generations (boot dirs and subvolumes)" '[ "$(echo "ls -d /bootpart/agentbox/gens/gen-[1-9]* | wc -l" | root)" -le 3 ] && [ "$(echo "btrfs subvolume list / | grep -cx \".* path @gen-[1-9][0-9]*\"" | root)" -le 3 ]'
  echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
  while running; do sleep 2; done
  hack/powercut.sh log boot >>"$LOG" 2>&1 &
  wait_boot none 900 || die "logged apply: no SSH (see $VM/boot-*.log)"
  plan --reinstall --install base-files
  build; trial "logged apply"
  echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
  while running; do sleep 2; done
  check "logged apply: after every write to /bootpart, GRUB finds its entry, kernel and initrd (powercut.sh grub)" "hack/powercut.sh grub"
}

: >"$LOG"
[ "$1" != install ] || : >"$OUT"
[ "$ENC" != tpm2+tang ] || trap 'hack/vm.sh tang down >/dev/null 2>&1 || :' EXIT
for s; do
  case "$s" in install|setup|cycles|breaks|cuts) log "== $s ($TAG)"; "sc_$s" ;; *) die "unknown scenario $s" ;; esac
done
{ echo "== journal: agentbox-health, agentbox-boot-deadline (every boot; @var_log persists across generations)"
  echo 'journalctl --no-pager -o short-iso -u agentbox-health.service -u agentbox-boot-deadline.service | grep -v -e "Starting agentbox-health" -e "Deactivated successfully" -e "Finished agentbox-health"' | root
} >>"$LOG" 2>&1 || :
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
while running; do sleep 2; done
log "fails=$fails"
[ "$fails" -eq 0 ]

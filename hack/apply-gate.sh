#!/bin/sh
# os.apply gates (PLAN.md week 1 day 4, ARCHITECTURE.md §3.3 and the §15 row 1-2) on the local QEMU VM.
#   hack/apply-gate.sh none|tpm2|tpm2+tang [install|setup|cycles|breaks|cuts ...]   default: all five, in order
# install  hack/gate.sh's unattended install and install checks.
# setup    checks what firstboot left (gate.sh's release as /var/lib/agentbox/current, agentbox-health.timer enabled,
#          `os mark-last-good` run) and sets a boot deadline of DEADLINE s (default 300).
# cycles   gen-2 removes the newest kernel, gen-3 brings it back with systemd re-installed (a kernel change whose
#          initrd dracut builds inside the nspawn), gen-4 prunes gen-1; then current cold-boots and previous boots once.
#          (Run again on a used box, the generation numbers are higher and the oldest one is pruned.)
# breaks   a trial broken in GRUB, in the initrd (clevis removed; btrfs in none mode), in fstab (/boot bound to the
#          parent's dir; a /boot device that never appears), and by a unit that blocks boot forever: each falls back to
#          the committed generation with no console input. Then an emptied grubenv boots the committed generation.
# cuts     QMP power cuts (vm.sh cut) at five points of an apply, then a clean apply that commits.
# Checks print PASS/FAIL to .vm/apply-gate-<mode>.txt, command output goes to .vm/apply-gate-<mode>.log; exit 1 on
# any FAIL. AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh and gate.sh. Test VMs only (password "x").
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
ENC=${1:?usage: hack/apply-gate.sh none|tpm2|tpm2+tang [install|setup|cycles|breaks|cuts ...]}
case "$ENC" in none|tpm2|tpm2+tang) ;; *) echo "usage: hack/apply-gate.sh none|tpm2|tpm2+tang [scenario ...]" >&2; exit 2 ;; esac
shift
[ $# -gt 0 ] || set -- install setup cycles breaks cuts
DEADLINE=${DEADLINE:-300}
OUT="$VM/apply-gate-$ENC.txt" LOG="$VM/apply-gate-$ENC.log"
A=/var/lib/agentbox/current/bin/agentbox
mkdir -p "$VM"
fails=0
# a laptop that idles to sleep freezes the VM and the Tang container mid-scenario, and the wall-clock waits then fail
! command -v caffeinate >/dev/null || { caffeinate -i -w $$ & }

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT"; }
die() { log "ABORT $*"; exit 1; }
check() { if (eval "$2") >>"$LOG" 2>&1; then log "PASS $1"; else log "FAIL $1"; fails=$((fails+1)); fi; }
vssh() { hack/vm.sh ssh "$@"; }
root() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s'; } # stdin: a script run as root on the VM
bootid() { vssh cat /proc/sys/kernel/random/boot_id 2>/dev/null || :; }
booted() { vssh 'g=$(findmnt -no FSROOT /); echo "agentbox-${g#/@}-$(uname -r)"'; }
committed() { vssh cat /bootpart/agentbox/committed; }
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
# plan ARGS: plans on the VM, logs the plan, sets H
plan() {
  H=$(echo "$A os plan $* 2>>/tmp/gate-plan.err" | root | tee -a "$LOG" | sed -n 's/^plan sha256: //p')
  [ -n "$H" ] || die "os plan $* failed: $(echo 'tail -5 /tmp/gate-plan.err' | root)"
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
  check "$1: boots $M (rootflags=subvol=@$M)" "vssh grep -qw rootflags=subvol=@$M /proc/cmdline"
  wait_root 420 "[ \"\$(cat /bootpart/agentbox/committed)\" = $E ] && test ! -e /var/lib/agentbox/os/pending.json" || :
  check "$1: health committed $E" "[ \"\$(committed)\" = $E ] && vssh 'grub-editenv /boot/grub/grubenv list' | grep -qx saved_entry=$E"
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
# fallback NAME SECONDS: reboot into the broken trial E; within SECONDS, with no console input, the box must run the
# committed generation C again. A trial that comes up (and so needs health plus the deadline) is logged.
fallback() {
  C=$(committed); old=$(bootid); t0=$(date +%s); seen=; reboot_vm
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
  check "$1: falls back to the committed $C" "[ \"\$(committed)\" = '$C' ]"
  settled || :
  check "$1: trial $M marked failed" "echo 'test -e /var/lib/agentbox/os/failed/$M.json && test ! -e /var/lib/agentbox/os/pending.json' | root"
  status
}
# with_top CMDS: run CMDS as root with the btrfs top level at $T
with_top() {
  { echo 'set -e; T=/run/gate-top; mkdir -p $T; mount -o subvolid=5 "$(findmnt -n -v -o SOURCE /)" $T'; echo "$1"; echo 'umount $T'; } | root >>"$LOG" 2>&1
}

sc_install() { hack/gate.sh "$ENC" >>"$LOG" 2>&1 || die "install gate failed (see $LOG and $VM/gate-$ENC.txt)"; cat "$VM/gate-$ENC.txt" >>"$OUT"; }

sc_setup() {
  up
  root >>"$LOG" 2>&1 <<EOF || die "setup failed"
set -e
mkdir -p /etc/systemd/system/agentbox-boot-deadline.service.d
printf '%s\n' '[Service]' 'Environment=AGENTBOX_BOOT_DEADLINE_SEC=$DEADLINE' > /etc/systemd/system/agentbox-boot-deadline.service.d/50-gate.conf
systemctl daemon-reload
sync # a power cut right after setup must not lose the drop-in
EOF
  check "setup: firstboot installed the release and enabled the health timer" "echo 'test -x $A && test -e /var/lib/agentbox/.firstboot-done && systemctl is-enabled agentbox-health.timer' | root"
  check "setup: the booted generation is committed" "[ \"\$(committed)\" = \"\$(booted)\" ]"
  check "setup: boot deadline armed" "vssh systemctl is-active agentbox-boot-deadline.service"
  status
}

sc_cycles() {
  up
  KN=$(vssh uname -r)
  KO=$(vssh ls /boot | sed -n 's/^vmlinuz-//p' | grep -vx "$KN" | sort -rV | head -1)
  [ -n "$KO" ] || die "cycles: needs a second, older kernel next to $KN"
  O=$(vssh ls /bootpart/agentbox/gens | sed -n 's/^gen-\([1-9][0-9]*\)$/\1/p' | sort -n | head -1) # gen-1 on a fresh box
  log "cycles: kernels $KN (newest) and $KO; oldest generation gen-$O"
  plan --remove "linux-image-$KN" --remove "linux-modules-$KN"
  build; trial "cycle 1 (remove $KN)"
  check "cycle 1: runs the older kernel $KO" "[ \"\$(vssh uname -r)\" = $KO ]"
  plan --reinstall --install linux-generic --install systemd
  build
  check "cycle 2: the build re-made initrd.img-$KN in the nspawn" "echo 'test /bootpart/agentbox/gens/$M/initrd.img-$KN -nt /bootpart/agentbox/gens/gen-1/initrd.img-$KN' | root"
  trial "cycle 2 (kernel $KO -> $KN, systemd re-installed)"
  check "cycle 2: kernel upgraded to $KN" "[ \"\$(vssh uname -r)\" = $KN ]"
  [ "$ENC" = none ] || check "cycle 2: LUKS unlocked by clevis from the nspawn-built initrd" "vssh 'journalctl -b -o cat' | grep -q 'Finished systemd-cryptsetup@croot.service' && echo 'journalctl -b -t clevis-luks-askpass -o cat' | root | grep -q '^Unlocked '"
  plan --reinstall --install base-files
  build; trial "cycle 3"
  check "cycle 3: gen-$O pruned with its boot dir, gone from grub.cfg" "echo 'test ! -e /bootpart/agentbox/gens/gen-$O && ! grep -q \"agentbox-gen-$O-\" /boot/grub/grub.cfg && ! btrfs subvolume list / | grep -qw @gen-$O' | root"
  CUR=$E PREV="agentbox-gen-$(( ${M#gen-} - 1 ))-$KN"
  # current cold-boots
  echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
  while running; do sleep 2; done
  up
  check "cold boot: current $CUR" "[ \"\$(booted)\" = $CUR ]"
  clean_root "cold boot"
  # previous boots once (next_entry written the §3.3 way: copy, edit, fsync, rename), then the deadline returns to current
  echo "cd /boot/grub && cp grubenv grubenv.new && grub-editenv grubenv.new set next_entry=$PREV && sync grubenv.new && mv grubenv.new grubenv && sync ." | root >>"$LOG" 2>&1
  old=$(bootid); reboot_vm; wait_boot "$old" 900 || die "previous: no SSH"
  check "previous: $PREV boots" "[ \"\$(booted)\" = $PREV ]"
  clean_root "previous"
  old=$(bootid); t0=$(date +%s)
  wait_boot "$old" $((DEADLINE + 600)) || die "previous: the deadline never rebooted it"
  log "previous: rebooted by the deadline after $(( $(date +%s) - t0 )) s"
  check "previous: the boot deadline returned to $CUR, still committed" "[ \"\$(booted)\" = $CUR ] && [ \"\$(committed)\" = $CUR ]"
  status
}

sc_breaks() {
  up
  plan --reinstall --install base-files
  build
  echo "rm /bootpart/agentbox/gens/$M/vmlinuz-$K" | root >>"$LOG" 2>&1
  fallback "GRUB break (vmlinuz-$K deleted after update-grub)" 600
  plan --reinstall --install base-files
  build
  if [ "$ENC" = none ]; then
    echo "dracut --force --omit-drivers btrfs /bootpart/agentbox/gens/$M/initrd.img-$K $K && ! lsinitrd /bootpart/agentbox/gens/$M/initrd.img-$K | grep -q /btrfs.ko" | root >>"$LOG" 2>&1 || die "could not break the initrd"
    fallback "initrd break (btrfs.ko removed)" 900
  else
    echo "dracut --force --omit 'clevis clevis-pin-null clevis-pin-sss clevis-pin-tang clevis-pin-tpm2' /bootpart/agentbox/gens/$M/initrd.img-$K $K && ! lsinitrd /bootpart/agentbox/gens/$M/initrd.img-$K | grep -q clevis-luks-askpass" | root >>"$LOG" 2>&1 || die "could not break the initrd"
    fallback "initrd break (clevis removed: LUKS prompt times out)" 1200
  fi
  # the clone bug the fstab rewrite prevents: systemd mounts the parent's dir (and would mkdir a missing bind source),
  # so the boot succeeds; health's /boot check refuses it and the deadline falls back
  plan --reinstall --install base-files
  build
  P=$(vssh findmnt -no FSROOT /); P=${P#/@} # the committed generation the box runs now
  with_top "sed -i 's|^/bootpart/agentbox/gens/$M /boot |/bootpart/agentbox/gens/$P /boot |' \$T/@$M/etc/fstab && grep -q '^/bootpart/agentbox/gens/$P /boot ' \$T/@$M/etc/fstab" || die "could not break fstab"
  fallback "fstab break (/boot still bound to the parent's gens/$P)" $((DEADLINE + 900))
  # a mount that can't happen: local-fs.target fails, and the emergency drop-in reboots after 120 s
  plan --reinstall --install base-files
  build
  with_top "sed -i 's|^/bootpart/agentbox/gens/$M /boot none bind[^ ]*|/dev/disk/by-uuid/00000000-0000-4000-8000-000000000000 /boot ext4 defaults|' \$T/@$M/etc/fstab && grep -q '^/dev/disk/by-uuid/00000000-0000-4000-8000-000000000000 /boot ' \$T/@$M/etc/fstab" || die "could not break fstab"
  fallback "fstab break (/boot device missing: emergency mode)" 1200
  plan --reinstall --install base-files
  build
  with_top "printf '%s\n' '[Unit]' 'Description=gate: blocks boot forever' '[Service]' 'Type=oneshot' 'ExecStart=/bin/sleep infinity' 'TimeoutStartSec=infinity' > \$T/@$M/etc/systemd/system/agentbox-gate-block.service && ln -s ../agentbox-gate-block.service \$T/@$M/etc/systemd/system/multi-user.target.wants/" || die "could not add the blocking unit"
  C=$(committed); old=$(bootid); reboot_vm
  wait_gen "$E" "$old" 900 || die "blocking unit: the trial never came up"
  check "blocking unit: the trial $M boots and never finishes" "[ \"\$(vssh systemctl is-system-running)\" = starting ]"
  sleep 90
  check "blocking unit: health does not commit it" "[ \"\$(committed)\" = $C ]"
  old=$(bootid); t0=$(date +%s)
  wait_gen "$C" "$old" $((DEADLINE + 600)) || die "blocking unit: the deadline never fell back"
  log "blocking unit: back on $C $(( $(date +%s) - t0 )) s later (boot deadline)"
  check "blocking unit: falls back to the committed $C" "[ \"\$(committed)\" = $C ]"
  settled || :
  check "blocking unit: trial $M marked failed" "echo 'test -e /var/lib/agentbox/os/failed/$M.json' | root"
  status
  # grubenv emptied (what a cut during an in-place grub-editenv leaves): GRUB boots the committed entry through
  # 09_agentbox's fallback, not entry 0 (the oldest generation), and the deadline keeps that boot up
  C=$(committed); old=$(bootid)
  echo ': > /boot/grub/grubenv && sync' | root >>"$LOG" 2>&1
  reboot_vm; wait_boot "$old" 900 || die "empty grubenv: no SSH"
  check "empty grubenv: boots the committed $C, not entry 0" "[ \"\$(booted)\" = $C ]"
  old=$(bootid); sleep $((DEADLINE + 60))
  check "empty grubenv: the boot deadline leaves the committed boot up" "[ \"\$(bootid)\" = $old ]"
  echo "$A os mark-last-good" | root >>"$LOG" 2>&1
  check "empty grubenv: mark-last-good restores saved_entry" "vssh 'grub-editenv /boot/grub/grubenv list' | grep -qx saved_entry=$C"
}

# cut_at PHASE DELAY: power-cut the VM DELAY s after apply prints "os: PHASE"
cut_at() {
  plan --reinstall --install base-files
  C=$(committed); old=$(bootid)
  echo "$A os apply --approve $H --no-reboot" | root >"$VM/apply.out" 2>&1 &
  sp=$! end=$(( $(date +%s) + 900 ))
  until grep -q "^os: $1" "$VM/apply.out"; do
    [ "$(date +%s)" -lt $end ] && kill -0 $sp 2>/dev/null || { cat "$VM/apply.out" >>"$LOG"; die "cut: apply never reached '$1'"; }
    sleep 0.2
  done
  sleep "$2"
  hack/vm.sh cut
  log "cut: QMP system_reset $2 s after 'os: $1'"
  kill $sp 2>/dev/null || : # the reset guest never closes the session
  wait $sp 2>/dev/null || :
  cat "$VM/apply.out" >>"$LOG"
  wait_boot "$old" 900 || die "cut at $1: no SSH after the reset"
  b=$(booted)
  log "cut at $1: back on $b"
  if [ "$1" = "boot once" ] && [ "$b" != "$C" ]; then # next_entry was already set: the complete trial boots
    wait_root 420 "test ! -e /var/lib/agentbox/os/pending.json" || :
    check "cut at $1: the complete trial $b boots and health commits it" "[ \"\$(committed)\" = '$b' ]"
  else
    check "cut at $1: boots the committed $C" "[ '$b' = '$C' ] && [ \"\$(committed)\" = '$C' ]"
  fi
  check "cut at $1: grub.cfg and grubenv intact" "echo 'grub-script-check /boot/grub/grub.cfg && grub-editenv /boot/grub/grubenv list | grep -q ^saved_entry=agentbox-' | root"
  settled || :
  clean_root "cut at $1"
  status
}

sc_cuts() {
  up
  cut_at clone 0
  cut_at "nspawn: apt-get install" 3
  cut_at "initrd gate" 0
  cut_at update-grub 0
  cut_at "boot once" 0
  plan --reinstall --install base-files
  build; trial "after the cuts"
  check "after the cuts: leftovers pruned, at most three generations" "[ \$(echo 'ls -d /bootpart/agentbox/gens/gen-[1-9]* | wc -l' | root) -le 3 ]"
}

: >"$LOG"
[ "$1" != install ] || : >"$OUT"
[ "$ENC" != tpm2+tang ] || trap 'hack/vm.sh tang down >/dev/null 2>&1 || :' EXIT
for s; do
  case "$s" in install|setup|cycles|breaks|cuts) log "== $s ($ENC)"; "sc_$s" ;; *) die "unknown scenario $s" ;; esac
done
{ echo "== journal: agentbox-health, agentbox-boot-deadline (every boot; @var_log persists across generations)"
  echo 'journalctl --no-pager -o short-iso -u agentbox-health.service -u agentbox-boot-deadline.service | grep -v -e "Starting agentbox-health" -e "Deactivated successfully" -e "Finished agentbox-health"' | root
} >>"$LOG" 2>&1 || :
echo 'systemctl poweroff' | root >/dev/null 2>&1 || :
while running; do sleep 2; done
log "fails=$fails"
[ "$fails" -eq 0 ]

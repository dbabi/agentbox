#!/bin/sh
# Week-1 install gates (PLAN.md week 1, ARCHITECTURE.md §15) on the local QEMU VM.
#   hack/gate.sh none|tpm2|tpm2+tang   render a test seed, install unattended, boot, check every gate item, power off
#   hack/gate.sh dup-serial            two disks with the same ID_SERIAL: the install must stop before any disk write
# tpm2+tang runs a throwaway Tang container (vm.sh tang) on 127.0.0.1:7500+ID; the VM reaches it as 10.0.2.2:7500+ID. It then
# boots with Tang down: no unlock and a reboot after the LUKS prompt times out, a typed recovery key unlocks, and the box
# unlocks by itself once Tang is back.
# AGENTBOX_VM_ID, AGENTBOX_ISO_DIR and DISKBUS (nvme or virtio) pass through to vm.sh: gates that run at once need
# distinct IDs and separate checkouts.
# Test seeds only: the admin password is "x" and the recovery key lives in .vm/keys. Never use them for a real box.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
mkdir -p "$VM" # a fresh worktree has no .vm yet
MODE=${1:?usage: hack/gate.sh none|tpm2|tpm2+tang|dup-serial}
case "$MODE" in none|tpm2|tpm2+tang|dup-serial) ;; *) echo "usage: hack/gate.sh none|tpm2|tpm2+tang|dup-serial" >&2; exit 2 ;; esac
ENC=$MODE; [ "$MODE" = dup-serial ] && ENC=none
die() { echo "gate.sh: $*" >&2; exit 1; }
case ${AGENTBOX_VM_ID:-0} in [0-9]) ;; *) die "AGENTBOX_VM_ID must be 0-9" ;; esac
TANG_URL=http://10.0.2.2:$((7500 + ${AGENTBOX_VM_ID:-0})) # vm.sh tang up serves this instance on 127.0.0.1:7500+ID
# the disk's udev ID_SERIAL, and the loadable modules of its driver chain that the seed records (virtio is built in)
case ${DISKBUS:-nvme} in
  nvme) SER=QEMU_NVMe_Ctrl_QM00001_1 DRV=" nvme" ;;
  virtio) SER=QM00001 DRV= ;;
  *) die "DISKBUS must be nvme or virtio" ;;
esac
# libxcrypt crypt("x"): yescrypt (Ubuntu's default) and sha512-crypt at the 100000-round floor, so both forms get installed
PW='$y$j9T$agentboxgatesalt0000$nVjZH1ZaNBH.vEdKjhLQLZVUy6bJDJKQOxEO8qRil23'
[ "$ENC" = tpm2 ] && PW='$6$rounds=100000$gatesalt$PJzNps4L0wTr6EuAOurqVB/VEVeGKeSEpNIR4BLw3eJyf2vEAyw2ETSqg5VBL1fNrlHAQO7p7ZzCYTHME6iRp1'
OUT="$VM/gate-$MODE.txt"
vmroot() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s'; } # stdin runs as root in the VM
ssh_up() { e=$(( $(date +%s) + $1 )); until hack/vm.sh ssh true 2>/dev/null; do [ "$(date +%s)" -lt "$e" ] || return 1; sleep 3; done; }
# vm_off: power the VM off; a box stuck in the initrd has no SSH, so kill QEMU after 90 s
vm_off() { echo 'systemctl poweroff' | vmroot >/dev/null 2>&1 || :; i=0
  while [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; do i=$((i+1)); [ $i -lt 45 ] || kill "$(cat "$VM/qemu.pid")"; sleep 2; done
  wait 2>/dev/null || :; }
verdict() { ! grep -q '^FAIL' "$OUT" || die "gate $MODE failed; see $OUT"
  grep -q '^fails=0$' "$OUT" || die "gate $MODE did not finish its checks; see $OUT"
  echo "gate $MODE: all checks passed"; }

go build -o bin/agentbox ./cmd/agentbox
[ -f "$VM/id_vm" ] || ssh-keygen -q -t ed25519 -N "" -C agentbox-vm -f "$VM/id_vm"
[ -f "$VM/keys/recovery.pub" ] || ./bin/agentbox recovery keygen --out "$VM/keys" >/dev/null
SEED="$VM/gate-seed-$MODE"
[ -d "$SEED" ] && rm -r "$SEED"
set -- --disk-serial "$SER" --ssh-key "$(cat "$VM/id_vm.pub")" \
  --password-hash "$PW" --minisign-pubkey "RWQ$(printf 'A%.0s' $(seq 53))" \
  --release-url https://releases.invalid.example/agentbox-dev.tgz --encryption "$ENC" --out "$SEED"
[ "$ENC" = none ] || set -- "$@" --recovery-pub "$VM/keys/recovery.pub"
if [ "$ENC" = tpm2+tang ]; then
  trap 'hack/vm.sh tang down >/dev/null 2>&1 || :' EXIT
  hack/vm.sh tang up
  THP=$(hack/vm.sh tang thp)
  [ -n "$THP" ] || die "could not read the Tang signing-key thumbprint"
  set -- "$@" --tang-url "$TANG_URL" --tang-thp "$THP"
fi
./bin/agentbox seed "$@" >/dev/null 2>&1 || ./bin/agentbox seed "$@"

hack/vm.sh reset >/dev/null
if [ "$MODE" = dup-serial ]; then
  # early-commands[0], the disk guard, must stop subiquity before storage runs: nothing may land on either disk
  ! INSTALL_TIMEOUT=900 DUP_DISK=1 hack/vm.sh install "$SEED" || die "the install with two same-serial disks went through"
  vm_off # QEMU must let go of the images before qemu-img reads them
  { n=0
    if grep -aqF "agentbox: --disk-serial $SER matched 2 disks, need exactly 1" "$VM/install.log"; then echo "PASS the disk guard refused two disks with ID_SERIAL=$SER"; else echo "FAIL no disk-guard refusal in install.log"; n=1; fi
    for d in disk disk2; do # qemu-img map shows every written extent as data
      if m=$(qemu-img map --output=json "$VM/$d.qcow2") && ! echo "$m" | grep -q '"data": true'; then echo "PASS $d.qcow2 never written"; else echo "FAIL $d.qcow2 written or unreadable"; n=1; fi
    done
    echo "fails=$n"; } | tee "$OUT"
  verdict; exit 0
fi
hack/vm.sh install "$SEED"
hack/vm.sh boot &
ssh_up 720 || die "no SSH after boot (LUKS or boot failure); see $VM/boot-*.log"

# Every check prints PASS/FAIL; the script exits 1 if any fails.
{ cat <<EOF; } | vmroot | tee "$OUT"
fails=0
# subshell: a check that calls exit must not end the run
check() { if (eval "\$2") >/dev/null 2>&1; then echo "PASS \$1"; else echo "FAIL \$1"; fails=\$((fails+1)); fi; }
check "root is @gen-1"                   '[ "\$(findmnt -n -o FSROOT /)" = /@gen-1 ]'
check "booted via 09_agentbox"           'grep -q "BOOT_IMAGE=/agentbox/gens/gen-1/vmlinuz-" /proc/cmdline'
check "rootflags pick @gen-1"            'grep -q "rootflags=subvol=@gen-1" /proc/cmdline'
check "/boot is gen-1's boot dir"        '[ "\$(findmnt -n -o FSROOT /boot)" = /agentbox/gens/gen-1 ]'
check "/boot/grub is shared /grub"       '[ "\$(findmnt -n -o FSROOT /boot/grub)" = /grub ]'
check "agent data has its own subvol"    '[ "\$(findmnt -n -o FSROOT /var/lib/agentbox/data)" = /@var_lib_agentbox_data ]'
check "saved_entry is gen-1"             'grub-editenv /boot/grub/grubenv list | grep -q "^saved_entry=agentbox-gen-1-"'
check "committed names the booted gen-1" '[ "\$(cat /bootpart/agentbox/committed)" = "agentbox-gen-1-\$(uname -r)" ]'
check "grub.cfg boots committed on an empty grubenv" 'grep -qF "then set default=\"agentbox-gen-1-\$(uname -r)\"; fi" /boot/grub/grub.cfg'
check "boot deadline armed"              'systemctl is-active agentbox-boot-deadline.service'
# subiquity writes usr/ and var/ into the top level after late-commands; agentbox-firstboot removes them, so allow it 180 s
check "top level holds only @* (firstboot cleanup)" 'mkdir -p /run/chk && mount -o subvolid=5 "\$(findmnt -n -v -o SOURCE /)" /run/chk || exit 1; i=0; while ls -A /run/chk | grep -qv "^@"; do i=\$((i+1)); [ \$i -lt 36 ] || { umount /run/chk; exit 1; }; sleep 5; done; umount /run/chk'
check "no nested subvolumes"             '[ -z "\$(btrfs subvolume list / | awk "{print \\\$NF}" | grep /)" ]'
check "initramfs bakes no root flags"    '! journalctl -b -o cat | grep -q "rootflags=[^ ]*subvolid=5"'
check "zram swap"                        'swapon --show=NAME --noheadings | grep -q zram0'
check "apt timers masked"                '[ "\$(systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer | sort -u)" = masked ]'
check "nftables, snapd, lxd-installer, secureboot-db masked" '[ "\$(systemctl is-enabled nftables.service snapd.socket snapd.service snapd.seeded.service snapd.snap-repair.timer lxd-installer.socket secureboot-db.service | sort -u)" = masked ]'
check "fwupd only refreshes metadata"    '[ "\$(systemctl is-enabled fwupd-refresh.timer)" = enabled ] && systemctl cat fwupd-refresh.service | grep -qx "ExecStart=/usr/bin/fwupdmgr refresh"'
check "kdump-tools purged, no grub.d snippet" '! dpkg -s kdump-tools && [ ! -e /etc/default/grub.d/kdump-tools.cfg ]'
check "no crashkernel= on the cmdline"   '! grep -q crashkernel= /proc/cmdline'
check "emergency reboots"                'grep -q FailureAction=reboot-force /etc/systemd/system/emergency.service.d/90-agentbox.conf'
check "watchdog: PID 1 drives the i6300esb, 60 s" '[ "\$(cat /sys/class/watchdog/watchdog0/identity /sys/class/watchdog/watchdog0/state /sys/class/watchdog/watchdog0/timeout | paste -sd,)" = "i6300ESB timer,active,60" ]'
check "dracut: hostonly, forced modules, driver chain [$DRV ], watchdog driver" 'f=/etc/dracut.conf.d/90-agentbox.conf; grep -qx "hostonly=\"yes\"" \$f && grep -qx "hostonly_cmdline=\"no\"" \$f && grep -q "^add_dracutmodules+=\" btrfs " \$f && grep -qx "add_drivers+=\"$DRV \"" \$f && grep -qx "force_drivers+=\" i6300esb \"" \$f'
check "every kernel's initrd has btrfs$DRV i6300esb" 'for k in \$(ls /boot | sed -n "s/^vmlinuz-//p"); do l=\$(lsinitrd /boot/initrd.img-\$k) || exit 1; for m in btrfs $DRV i6300esb; do echo "\$l" | grep -q "/\$m\.ko" || exit 1; done; done'
check "installer logs persist in @var_log" '[ "\$(findmnt -n -o FSROOT -T /var/log/installer)" = /@var_log ] && [ -s /var/log/installer/installer-journal.txt ] && [ -s /var/log/installer/subiquity-server-debug.log ] && [ -s /var/log/installer/cloud-init.log ]'
check "no password hash under /var/log (installer, subiquity, cloud-init, journal)" '! grep -rlF gatesalt /var/log && ! grep -rlF -e "\\\$6\\\$" -e "\\\$y\\\$" /var/log/installer /var/log/cloud-init.log /var/log/cloud-init-output.log'
check "seed copy scrubbed"               '[ ! -e /var/log/installer/autoinstall-user-data ]'
check "disk guard saw exactly one $SER"  '[ "\$(grep -c "agentbox: disk [^ ]* ID_SERIAL=$SER\\\$" /var/log/installer/installer-journal.txt)" = 1 ]'
check "umount -R left the live installer's /dev/pts and /sys/fs/cgroup" 'grep -q "+ mountpoint -q /sys/fs/cgroup" /var/log/installer/installer-journal.txt'
check "firstboot script installed from stdin, 0755" '[ "\$(stat -c %a /usr/local/sbin/agentbox-firstboot)" = 755 ] && grep -q "touch /var/lib/agentbox/.firstboot-done" /usr/local/sbin/agentbox-firstboot'
check "no failed units"                  '[ -z "\$(systemctl --failed --no-legend --plain)" ]'
check "firstboot leaves no /run copies"  '[ "\$(ls -d /run/agentbox-firstboot* 2>/dev/null | wc -l)" -le 1 ]'
check "dracut builds the initramfs"      'dpkg -s dracut | grep -q "Status: install ok installed"'
if [ "$ENC" != none ]; then
  check "root on LUKS (croot)"           'findmnt -n -o SOURCE / | grep -q "^/dev/mapper/croot"'
  check "LUKS has a clevis token"        'cryptsetup luksDump "\$(cryptsetup status croot | awk "/device:/{print \\\$2}")" | grep -q ": clevis"'
  check "unlocked by clevis"             'journalctl -b -o cat | grep -q "Finished systemd-cryptsetup@croot.service" && journalctl -b -t clevis-luks-askpass -o cat | grep -q "^Unlocked "'
  check "recovery.bin present"           '[ -s /bootpart/agentbox/recovery.bin ]'
  check "09_agentbox sets rd.luks.uuid"  'u=\$(grep -o "rd.luks.uuid=[^ ]*" /proc/cmdline) && grep -q "^croot UUID=\${u#rd.luks.uuid=} " /etc/crypttab'
  check "installer keyfile gone"         '[ ! -e /run/agentbox-luks.key ]'
fi
if [ "$ENC" = tpm2+tang ]; then
  # sss with t=2 needs both pins, so "unlocked by clevis" above also proves the initramfs reached Tang. Every instance's
  # Tang serves the same keys, so the URL proves it was this instance's Tang.
  check "clevis binding is sss tpm2+tang at $TANG_URL" 'd=\$(cryptsetup status croot | awk "/device:/{print \\\$2}"); l=\$(clevis luks list -d "\$d"); echo "\$l" | grep -q sss && echo "\$l" | grep -q tpm2 && echo "\$l" | grep -qF "$TANG_URL\""'
  check "initramfs brings up network"     'grep -q "rd.neednet=1" /proc/cmdline'
fi
echo "fails=\$fails"
EOF

if [ "$ENC" != none ]; then # the offline recovery path: recovery.bin -> key -> opens LUKS
  W=$(mktemp -d "$VM/recov.XXXX")
  hack/vm.sh ssh cat /bootpart/agentbox/recovery.bin > "$W/recovery.bin"
  ./bin/agentbox recovery decrypt --key "$VM/keys/recovery.key" --in "$W/recovery.bin" --out "$W/luks.key" >/dev/null
  # tr -dc 0-9 | head -c 48 ran under the live installer's uutils: the key must be exactly 48 digits, typeable at the prompt
  if grep -qxE '[0-9]{48}' "$W/luks.key"; then echo "PASS the LUKS key is 48 digits"; else echo "FAIL the LUKS key is not 48 digits"; fi | tee -a "$OUT"
  { echo x; cat "$W/luks.key"; } | hack/vm.sh ssh 'sudo -S -p "" sh -c "umask 077; head -c 48 > /run/rk.key; d=\$(cryptsetup status croot | awk \"/device:/{print \\\$2}\"); cryptsetup open --test-passphrase --key-file /run/rk.key \$d && echo PASS recovery key opens LUKS || echo FAIL recovery key opens LUKS; shred -u /run/rk.key"' | tee -a "$OUT"
fi
vm_off

if [ "$ENC" = tpm2+tang ]; then
  # Tang down, no input: clevis can't unlock, so the LUKS prompt waits out crypttab's timeout=300s, dracut's rd.retry
  # (180 s) runs out and rd.emergency=reboot reboots. Type the recovery key at the next prompt. Then reboot and bring Tang
  # back while the prompt waits: clevis keeps retrying and unlocks with no input.
  result() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fi | tee -a "$OUT"; }
  seen() { e=$(( $(date +%s) + $3 )); until [ "$(grep -ac "$1" "$LOG")" -ge "$2" ]; do [ "$(date +%s)" -lt "$e" ] || return 1; sleep 2; done; }
  P='Please enter passphrase for disk'
  hack/vm.sh tang down
  last=$(ls -t "$VM"/boot-*.log | head -n 1)
  hack/vm.sh boot &
  until LOG=$(ls -t "$VM"/boot-*.log | head -n 1) && [ "$LOG" != "$last" ]; do sleep 1; done
  t1=0 t2=0
  seen "$P" 1 180 && t1=$(date +%s) && seen 'reboot: Restarting system' 1 720 && t2=$(date +%s)
  result "Tang down: no unlock; the box rebooted $((t2 - t1)) s after the LUKS prompt (timeout=300s, then rd.retry)" \
    '[ "$t1" -gt 0 ] && [ $((t2 - t1)) -ge 300 ] && grep -aq "Could not boot" "$LOG"'
  if seen "$P" 2 180; then sleep 2; { cat "$W/luks.key"; printf '\r'; sleep 3; } | nc -U "$VM/console.sock" >/dev/null 2>&1 & k=$!; sleep 6; kill "$k" 2>/dev/null || :; fi
  ssh_up 240 || :
  result "typed recovery key unlocks (Tang down, clevis did not)" '! podman container exists "agentbox-tang-${AGENTBOX_VM_ID:-0}" &&
    echo "journalctl -b -o cat" | vmroot | grep -q "Finished systemd-cryptsetup@croot.service" &&
    ! echo "journalctl -b -t clevis-luks-askpass -o cat" | vmroot | grep -q "^Unlocked " && ! grep -aqF -f "$W/luks.key" "$LOG"'
  echo 'systemctl reboot' | vmroot >/dev/null 2>&1 || :
  seen "$P" 3 300 && hack/vm.sh tang up >/dev/null
  ssh_up 240 || :
  result "unlocks once Tang is back (clevis, no input, no reboot)" 'echo "journalctl -b -t clevis-luks-askpass -o cat" | vmroot | grep -q "^Unlocked " &&
    [ "$(grep -ac "reboot: Restarting system" "$LOG")" -eq 2 ]'
  vm_off
fi
[ "$ENC" = none ] || { rm -P "$W/luks.key" 2>/dev/null || rm -f "$W/luks.key"; }
verdict

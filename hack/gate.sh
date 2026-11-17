#!/bin/sh
# Week-1 install gates (PLAN.md weeks 1-2, ARCHITECTURE.md §15) on the local QEMU VM.
#   hack/gate.sh none|tpm2|tpm2+tang [uefi|bios]   render a test seed, install unattended, boot, check every gate item, power off
# uefi (default) is the arm64 VM with Secure Boot on (SECUREBOOT=0 turns it off); bios is the amd64 VM under TCG, about
# five times slower. The installer boots the zero-touch ISO through the firmware unless DIRECT_KERNEL=1 (see vm.sh).
# tpm2+tang runs a throwaway Tang container (vm.sh tang) on 127.0.0.1:7500+ID; the VM reaches it as 10.0.2.2:7500+ID.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh: gates that run at once need distinct IDs and separate checkouts.
# Test seeds only: the admin password is "x" and the recovery key lives in .vm/keys. Never use them for a real box.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
mkdir -p "$VM" # a fresh worktree has no .vm yet
ENC=${1:?usage: hack/gate.sh none|tpm2|tpm2+tang [uefi|bios]} BOOT=${2:-uefi}
case "$ENC/$BOOT" in none/uefi|none/bios|tpm2/uefi|tpm2/bios|tpm2+tang/uefi|tpm2+tang/bios) ;;
  *) echo "usage: hack/gate.sh none|tpm2|tpm2+tang [uefi|bios]" >&2; exit 2 ;; esac
die() { echo "gate.sh: $*" >&2; exit 1; }
case ${AGENTBOX_VM_ID:-0} in [0-9]) ;; *) die "AGENTBOX_VM_ID must be 0-9" ;; esac
TANG_URL=http://10.0.2.2:$((7500 + ${AGENTBOX_VM_ID:-0})) # vm.sh tang up serves this instance on 127.0.0.1:7500+ID
# vm.sh's default disk per boot mode, and the factor for the waits below
case $BOOT in uefi) DISK_SERIAL=QEMU_NVMe_Ctrl_QM00001_1 SLOW=1 TAG=$ENC ;; bios) DISK_SERIAL=QEMU_HARDDISK_QM00001 SLOW=5 TAG=$ENC-bios ;; esac
SB=${SECUREBOOT:-1}

go build -o bin/agentbox ./cmd/agentbox
[ -f "$VM/id_vm" ] || ssh-keygen -q -t ed25519 -N "" -C agentbox-vm -f "$VM/id_vm"
[ -f "$VM/keys/recovery.pub" ] || ./bin/agentbox recovery keygen --out "$VM/keys" >/dev/null
SEED="$VM/gate-seed-$TAG"
[ -d "$SEED" ] && rm -r "$SEED"
set -- --disk-serial "$DISK_SERIAL" --boot "$BOOT" --ssh-key "$(cat "$VM/id_vm.pub")" \
  --password-hash "$(openssl passwd -6 -salt gatesalt x)" --minisign-pubkey "RWQ$(printf 'A%.0s' $(seq 53))" \
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
hack/vm.sh install "$SEED"
hack/vm.sh boot &
end=$(( $(date +%s) + 720 * SLOW ))
until hack/vm.sh ssh true 2>/dev/null; do [ "$(date +%s)" -lt "$end" ] || die "no SSH after boot (LUKS or boot failure); see $VM/boot-*.log"; sleep 5; done

# Every check prints PASS/FAIL; the script exits 1 if any fails.
{ echo x; cat <<EOF; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' | tee "$VM/gate-$TAG.txt"
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
# subiquity writes usr/ and var/ into the top level after late-commands; agentbox-firstboot removes them, so allow it 180 s * SLOW
check "top level holds only @* (firstboot cleanup)" 'mkdir -p /run/chk && mount -o subvolid=5 "\$(findmnt -n -v -o SOURCE /)" /run/chk || exit 1; i=0; while ls -A /run/chk | grep -qv "^@"; do i=\$((i+1)); [ \$i -lt $((36 * SLOW)) ] || { umount /run/chk; exit 1; }; sleep 5; done; umount /run/chk'
check "initramfs bakes no root flags"    '! journalctl -b -o cat | grep -q "rootflags=[^ ]*subvolid=5"'
check "zram swap"                        'swapon --show=NAME --noheadings | grep -q zram0'
check "apt timers masked"                '[ "\$(systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer | sort -u)" = masked ]'
check "emergency reboots"                'grep -q FailureAction=reboot-force /etc/systemd/system/emergency.service.d/90-agentbox.conf'
check "no password hash in installer logs" '! grep -rlF "\\\$6\\\$" /var/log/installer'
check "seed copy scrubbed"               '[ ! -e /var/log/installer/autoinstall-user-data ]'
check "no failed units"                  '[ -z "\$(systemctl --failed --no-legend --plain)" ]'
check "firstboot leaves no /run copies"  '[ "\$(ls -d /run/agentbox-firstboot* 2>/dev/null | wc -l)" -le 1 ]'
check "dracut builds the initramfs"      'dpkg -s dracut | grep -q "Status: install ok installed"'
if [ "$BOOT" = bios ]; then
  check "booted by BIOS (no EFI)"        '[ ! -d /sys/firmware/efi ]'
elif [ "$SB" = 1 ]; then
  check "Secure Boot on (mokutil)"       'mokutil --sb-state | grep -q "SecureBoot enabled"'
else
  check "Secure Boot off (mokutil)"      'mokutil --sb-state | grep -q "SecureBoot disabled"'
fi
if [ "$ENC" != none ]; then
  check "root on LUKS (croot)"           'findmnt -n -o SOURCE / | grep -q "^/dev/mapper/croot"'
  check "LUKS has a clevis token"        'cryptsetup luksDump "\$(cryptsetup status croot | awk "/device:/{print \\\$2}")" | grep -q ": clevis"'
  check "unlocked by clevis"             'journalctl -b -o cat | grep -q "Finished systemd-cryptsetup@croot.service"'
  check "recovery.bin present"           '[ -s /bootpart/agentbox/recovery.bin ]'
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
  { echo x; cat "$W/luks.key"; } | hack/vm.sh ssh 'sudo -S -p "" sh -c "umask 077; head -c 48 > /run/rk.key; d=\$(cryptsetup status croot | awk \"/device:/{print \\\$2}\"); cryptsetup open --test-passphrase --key-file /run/rk.key \$d && echo PASS recovery key opens LUKS || echo FAIL recovery key opens LUKS; shred -u /run/rk.key"' | tee -a "$VM/gate-$TAG.txt"
  rm -P "$W/luks.key" 2>/dev/null || rm -f "$W/luks.key"
fi

{ echo x; echo 'systemctl poweroff'; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' 2>/dev/null || :
wait 2>/dev/null || :
! grep -q '^FAIL' "$VM/gate-$TAG.txt" || die "gate $TAG failed; see $VM/gate-$TAG.txt"
grep -q '^fails=0$' "$VM/gate-$TAG.txt" || die "gate $TAG did not finish its checks; see $VM/gate-$TAG.txt"
echo "gate $TAG: all checks passed"

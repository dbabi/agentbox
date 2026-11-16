#!/bin/sh
# Week-1 install gates (PLAN.md week 1, ARCHITECTURE.md §15) on the local QEMU VM.
#   hack/gate.sh none|tpm2     render a test seed, install unattended, boot, check every gate item, power off
# Test seeds only: the admin password is "x" and the recovery key lives in .vm/keys. Never use them for a real box.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
ENC=${1:?usage: hack/gate.sh none|tpm2}
case "$ENC" in none|tpm2) ;; *) echo "gate.sh: only none and tpm2 run on this Mac (tpm2+tang needs podman)" >&2; exit 2 ;; esac
die() { echo "gate.sh: $*" >&2; exit 1; }

go build -o bin/agentbox ./cmd/agentbox
[ -f "$VM/id_vm" ] || ssh-keygen -q -t ed25519 -N "" -C agentbox-vm -f "$VM/id_vm"
[ -f "$VM/keys/recovery.pub" ] || ./bin/agentbox recovery keygen --out "$VM/keys" >/dev/null
SEED="$VM/gate-seed-$ENC"
[ -d "$SEED" ] && rm -r "$SEED"
set -- --disk-serial QEMU_NVMe_Ctrl_QM00001_1 --ssh-key "$(cat "$VM/id_vm.pub")" \
  --password-hash "$(openssl passwd -6 -salt gatesalt x)" --minisign-pubkey "RWQ$(printf 'A%.0s' $(seq 53))" \
  --release-url https://releases.invalid.example/agentbox-dev.tgz --encryption "$ENC" --out "$SEED"
[ "$ENC" = none ] || set -- "$@" --recovery-pub "$VM/keys/recovery.pub"
./bin/agentbox seed "$@" >/dev/null 2>&1 || ./bin/agentbox seed "$@"

hack/vm.sh reset >/dev/null
hack/vm.sh install "$SEED"
hack/vm.sh boot &
end=$(( $(date +%s) + 720 ))
until hack/vm.sh ssh true 2>/dev/null; do [ "$(date +%s)" -lt "$end" ] || die "no SSH after boot (LUKS or boot failure); see $VM/boot-*.log"; sleep 5; done

# Every check prints PASS/FAIL; the script exits 1 if any fails.
{ echo x; cat <<EOF; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' | tee "$VM/gate-$ENC.txt"
fails=0
check() { if eval "\$2" >/dev/null 2>&1; then echo "PASS \$1"; else echo "FAIL \$1"; fails=\$((fails+1)); fi; }
check "root is @gen-1"                   '[ "\$(findmnt -n -o FSROOT /)" = /@gen-1 ]'
check "booted via 09_agentbox"           'grep -q "BOOT_IMAGE=/agentbox/gens/gen-1/vmlinuz-" /proc/cmdline'
check "rootflags pick @gen-1"            'grep -q "rootflags=subvol=@gen-1" /proc/cmdline'
check "/boot is gen-1's boot dir"        '[ "\$(findmnt -n -o FSROOT /boot)" = /agentbox/gens/gen-1 ]'
check "/boot/grub is shared /grub"       '[ "\$(findmnt -n -o FSROOT /boot/grub)" = /grub ]'
check "agent data has its own subvol"    '[ "\$(findmnt -n -o FSROOT /var/lib/agentbox/data)" = /@var_lib_agentbox_data ]'
check "saved_entry is gen-1"             'grub-editenv /boot/grub/grubenv list | grep -q "^saved_entry=agentbox-gen-1-"'
check "top level holds only @*"          'mkdir -p /run/chk && mount -o subvolid=5 "\$(findmnt -n -v -o SOURCE /)" /run/chk && ! ls -A /run/chk | grep -qv "^@"; r=\$?; umount /run/chk; exit \$r'
check "zram swap"                        'swapon --show=NAME --noheadings | grep -q zram0'
check "apt timers masked"                '[ "\$(systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer | sort -u)" = masked ]'
check "emergency reboots"                'grep -q FailureAction=reboot-force /etc/systemd/system/emergency.service.d/90-agentbox.conf'
check "no password hash in installer logs" '! grep -rlF "\\\$6\\\$" /var/log/installer'
check "seed copy scrubbed"               '[ ! -e /var/log/installer/autoinstall-user-data ]'
check "no failed units"                  '[ -z "\$(systemctl --failed --no-legend --plain)" ]'
check "firstboot leaves no /run copies"  '[ "\$(ls -d /run/agentbox-firstboot* 2>/dev/null | wc -l)" -le 1 ]'
check "dracut builds the initramfs"      'dpkg -s dracut | grep -q "Status: install ok installed"'
if [ "$ENC" = tpm2 ]; then
  check "root on LUKS (croot)"           'findmnt -n -o SOURCE / | grep -q "^/dev/mapper/croot"'
  check "LUKS has a clevis token"        'cryptsetup luksDump "\$(cryptsetup status croot | awk "/device:/{print \\\$2}")" | grep -q ": clevis"'
  check "unlocked by clevis"             'journalctl -b -o cat | grep -q "Finished systemd-cryptsetup@croot.service"'
  check "recovery.bin present"           '[ -s /bootpart/agentbox/recovery.bin ]'
  check "installer keyfile gone"         '[ ! -e /run/agentbox-luks.key ]'
fi
echo "fails=\$fails"
EOF

if [ "$ENC" = tpm2 ]; then # the offline recovery path: recovery.bin -> key -> opens LUKS
  W=$(mktemp -d "$VM/recov.XXXX")
  scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$VM/id_vm" -P 2222 \
    boxadmin@127.0.0.1:/bootpart/agentbox/recovery.bin "$W/"
  ./bin/agentbox recovery decrypt --key "$VM/keys/recovery.key" --in "$W/recovery.bin" --out "$W/luks.key" >/dev/null
  { echo x; cat "$W/luks.key"; } | hack/vm.sh ssh 'sudo -S -p "" sh -c "umask 077; head -c 48 > /run/rk.key; d=\$(cryptsetup status croot | awk \"/device:/{print \\\$2}\"); cryptsetup open --test-passphrase --key-file /run/rk.key \$d && echo PASS recovery key opens LUKS || echo FAIL recovery key opens LUKS; shred -u /run/rk.key"' | tee -a "$VM/gate-$ENC.txt"
  rm -P "$W/luks.key" 2>/dev/null || rm -f "$W/luks.key"
fi

{ echo x; echo 'systemctl poweroff'; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' 2>/dev/null || :
wait 2>/dev/null || :
! grep -q '^FAIL' "$VM/gate-$ENC.txt" || die "gate $ENC failed; see $VM/gate-$ENC.txt"
echo "gate $ENC: all checks passed"

#!/bin/sh
# Week-1 install gates (PLAN.md week 1, ARCHITECTURE.md §15) on the local QEMU VM.
#   hack/gate.sh none|tpm2|tpm2+tang   render a test seed, install unattended, boot, check every gate item, power off
# tpm2+tang runs a throwaway Tang container (vm.sh tang) on 127.0.0.1:7500+ID; the VM reaches it as 10.0.2.2:7500+ID.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh: gates that run at once need distinct IDs and separate checkouts.
# Test seeds only: the admin password is "x" and the recovery key lives in .vm/keys. Never use them for a real box.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
mkdir -p "$VM" # a fresh worktree has no .vm yet
ENC=${1:?usage: hack/gate.sh none|tpm2|tpm2+tang}
case "$ENC" in none|tpm2|tpm2+tang) ;; *) echo "usage: hack/gate.sh none|tpm2|tpm2+tang" >&2; exit 2 ;; esac
die() { echo "gate.sh: $*" >&2; exit 1; }
case ${AGENTBOX_VM_ID:-0} in [0-9]) ;; *) die "AGENTBOX_VM_ID must be 0-9" ;; esac
TANG_URL=http://10.0.2.2:$((7500 + ${AGENTBOX_VM_ID:-0})) # vm.sh tang up serves this instance on 127.0.0.1:7500+ID

go build -o bin/agentbox ./cmd/agentbox
[ -f "$VM/id_vm" ] || ssh-keygen -q -t ed25519 -N "" -C agentbox-vm -f "$VM/id_vm"
[ -f "$VM/keys/recovery.pub" ] || ./bin/agentbox recovery keygen --out "$VM/keys" >/dev/null
SEED="$VM/gate-seed-$ENC"
[ -d "$SEED" ] && rm -r "$SEED"
set -- --disk-serial QEMU_NVMe_Ctrl_QM00001_1 --ssh-key "$(cat "$VM/id_vm.pub")" \
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
end=$(( $(date +%s) + 720 ))
until hack/vm.sh ssh true 2>/dev/null; do [ "$(date +%s)" -lt "$end" ] || die "no SSH after boot (LUKS or boot failure); see $VM/boot-*.log"; sleep 5; done

# Every check prints PASS/FAIL; the script exits 1 if any fails.
{ echo x; cat <<EOF; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' | tee "$VM/gate-$ENC.txt"
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
check "initramfs bakes no root flags"    '! journalctl -b -o cat | grep -q "rootflags=[^ ]*subvolid=5"'
check "zram swap"                        'swapon --show=NAME --noheadings | grep -q zram0'
check "apt timers masked"                '[ "\$(systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer | sort -u)" = masked ]'
check "emergency reboots"                'grep -q FailureAction=reboot-force /etc/systemd/system/emergency.service.d/90-agentbox.conf'
check "no password hash in installer logs" '! grep -rlF "\\\$6\\\$" /var/log/installer'
check "seed copy scrubbed"               '[ ! -e /var/log/installer/autoinstall-user-data ]'
check "no failed units"                  '[ -z "\$(systemctl --failed --no-legend --plain)" ]'
check "firstboot leaves no /run copies"  '[ "\$(ls -d /run/agentbox-firstboot* 2>/dev/null | wc -l)" -le 1 ]'
check "dracut builds the initramfs"      'dpkg -s dracut | grep -q "Status: install ok installed"'
if [ "$ENC" != none ]; then
  check "root on LUKS (croot)"           'findmnt -n -o SOURCE / | grep -q "^/dev/mapper/croot"'
  check "LUKS has a clevis token"        'cryptsetup luksDump "\$(cryptsetup status croot | awk "/device:/{print \\\$2}")" | grep -q ": clevis"'
  check "unlocked by clevis"             'journalctl -b -o cat | grep -q "Finished systemd-cryptsetup@croot.service"'
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
  { echo x; cat "$W/luks.key"; } | hack/vm.sh ssh 'sudo -S -p "" sh -c "umask 077; head -c 48 > /run/rk.key; d=\$(cryptsetup status croot | awk \"/device:/{print \\\$2}\"); cryptsetup open --test-passphrase --key-file /run/rk.key \$d && echo PASS recovery key opens LUKS || echo FAIL recovery key opens LUKS; shred -u /run/rk.key"' | tee -a "$VM/gate-$ENC.txt"
  rm -P "$W/luks.key" 2>/dev/null || rm -f "$W/luks.key"
fi

{ echo x; echo 'systemctl poweroff'; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' 2>/dev/null || :
wait 2>/dev/null || :
! grep -q '^FAIL' "$VM/gate-$ENC.txt" || die "gate $ENC failed; see $VM/gate-$ENC.txt"
grep -q '^fails=0$' "$VM/gate-$ENC.txt" || die "gate $ENC did not finish its checks; see $VM/gate-$ENC.txt"
echo "gate $ENC: all checks passed"

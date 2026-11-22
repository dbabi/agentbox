#!/bin/sh
# Install gates (PLAN.md weeks 1-2, ARCHITECTURE.md §15) on the local QEMU VM.
#   hack/gate.sh none|tpm2|tpm2+tang [uefi|bios]   build and serve test releases, render a test seed, install unattended,
#                                                  boot, check every gate item (bad releases refused, firstboot), reboot,
#                                                  check, power off
#   hack/gate.sh dup-serial                        two disks with the same ID_SERIAL: the install must stop before any
#                                                  disk write
# uefi (default) is the arm64 VM with Secure Boot on (SECUREBOOT=0 turns it off); bios is the amd64 VM under TCG, about
# five times slower. The installer boots the zero-touch ISO through the firmware unless DIRECT_KERNEL=1 (see vm.sh).
# tpm2+tang runs a throwaway Tang container (vm.sh tang) on 127.0.0.1:7500+ID; the VM reaches it as 10.0.2.2:7500+ID. It then
# boots with Tang down: no unlock and a reboot after the LUKS prompt times out, a typed recovery key unlocks, and the box
# unlocks by itself once Tang is back.
# hack/release-serve serves the test releases on 127.0.0.1:7600+ID; the --dev seed fetches from 10.0.2.2:7600+ID.
# vm.sh forwards only those two ports to the host's loopback: a listener on 127.0.0.1 and ::1 port 7700+ID, which has no
# forward, must see nothing from the guest.
# AGENTBOX_VM_ID, AGENTBOX_ISO_DIR and DISKBUS (nvme, sata or virtio) pass through to vm.sh: gates that run at once need
# distinct IDs and separate checkouts.
# Test seeds only: the admin password is "x"; the recovery and release-signing keys live in .vm/keys. Never use them for a real box.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VM="$ROOT/.vm"
mkdir -p "$VM" # a fresh worktree has no .vm yet
MODE=${1:?usage: hack/gate.sh none|tpm2|tpm2+tang [uefi|bios] | dup-serial} BOOT=${2:-uefi}
case "$MODE/$BOOT" in none/uefi|none/bios|tpm2/uefi|tpm2/bios|tpm2+tang/uefi|tpm2+tang/bios|dup-serial/uefi) ;;
  *) echo "usage: hack/gate.sh none|tpm2|tpm2+tang [uefi|bios] | dup-serial" >&2; exit 2 ;; esac
ENC=$MODE; [ "$MODE" = dup-serial ] && ENC=none
die() { echo "gate.sh: $*" >&2; exit 1; }
case ${AGENTBOX_VM_ID:-0} in [0-9]) ;; *) die "AGENTBOX_VM_ID must be 0-9" ;; esac
TANG_URL=http://10.0.2.2:$((7500 + ${AGENTBOX_VM_ID:-0})) # vm.sh tang up serves this instance on 127.0.0.1:7500+ID
RPORT=$((7600 + ${AGENTBOX_VM_ID:-0})) LPORT=$((7700 + ${AGENTBOX_VM_ID:-0})) REL="$VM/release" V=0.0.1-gate V0=0.0.0-gate
command -v minisign >/dev/null || die "minisign not installed (brew install minisign)"
# vm.sh's default disk per boot mode, the factor for the waits below, and the watchdog the seed must find: vm.sh gives
# only the amd64 VM an i6300esb, so the arm64 one boots the softdog fallback
case $BOOT in uefi) SLOW=1 TAG=$MODE B=${DISKBUS:-nvme} WD=softdog WDID="Software Watchdog" ;;
  bios) SLOW=5 TAG=$MODE-bios B=${DISKBUS:-sata} WD=i6300esb WDID="i6300ESB timer" ;; esac
# the disk's udev ID_SERIAL, and the loadable modules of its driver chain that the seed records (virtio_blk is built in;
# on amd64 sd_mod and libata are too, ahci is not)
case $B in
  nvme) SER=QEMU_NVMe_Ctrl_QM00001_1 DRV=" nvme" ;;
  sata) SER=QEMU_HARDDISK_QM00001 DRV=" ahci" ;;
  virtio) SER=QM00001 DRV= ;;
  *) die "DISKBUS must be nvme, sata or virtio" ;;
esac
SB=${SECUREBOOT:-1}
# libxcrypt crypt("x"): yescrypt (Ubuntu's default) and sha512-crypt at the 100000-round floor, so both forms get installed
PW='$y$j9T$agentboxgatesalt0000$nVjZH1ZaNBH.vEdKjhLQLZVUy6bJDJKQOxEO8qRil23'
[ "$ENC" = tpm2 ] && PW='$6$rounds=100000$gatesalt$PJzNps4L0wTr6EuAOurqVB/VEVeGKeSEpNIR4BLw3eJyf2vEAyw2ETSqg5VBL1fNrlHAQO7p7ZzCYTHME6iRp1'
OUT="$VM/gate-$TAG.txt" QEMU=
vmroot() { { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s'; } # stdin runs as root in the VM
ssh_up() { e=$(( $(date +%s) + $1 )); until hack/vm.sh ssh true 2>/dev/null; do [ "$(date +%s)" -lt "$e" ] || return 1; sleep 3; done; }
# vm_off: power the VM off; a box stuck in the initrd has no SSH, so kill QEMU after 90 s * SLOW
vm_off() { echo 'systemctl poweroff' | vmroot >/dev/null 2>&1 || :; i=0
  while [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; do i=$((i+1)); [ $i -lt $((45 * SLOW)) ] || kill "$(cat "$VM/qemu.pid")"; sleep 2; done
  [ -z "$QEMU" ] || wait "$QEMU" 2>/dev/null || :; } # not plain wait: release-serve runs until the trap
# verdict N: no FAIL line, and each of the N check blocks reached fails=0
verdict() { ! grep -q '^FAIL' "$OUT" || die "gate $TAG failed; see $OUT"
  [ "$(grep -c '^fails=0$' "$OUT")" -eq "$1" ] || die "gate $TAG did not finish its checks; see $OUT"
  echo "gate $TAG: all checks passed"; }

go build -o bin/agentbox ./cmd/agentbox
go build -o bin/release-serve ./hack/release-serve
[ -f "$VM/id_vm" ] || ssh-keygen -q -t ed25519 -N "" -C agentbox-vm -f "$VM/id_vm"
[ -f "$VM/keys/recovery.pub" ] || ./bin/agentbox recovery keygen --out "$VM/keys" >/dev/null
[ -f "$VM/keys/minisign.key" ] || minisign -G -W -p "$VM/keys/minisign.pub" -s "$VM/keys/minisign.key" >/dev/null

# Test releases: V under test; V0, older and validly signed (a rollback that only the sha256 pin refuses); a tampered
# V whose install.sh would leave a marker; and V signed by another key.
[ -d "$REL" ] && rm -r "$REL"
mkdir -p "$REL/www/r" "$REL/x"
make -s release VERSION=$V0 MINISIGN_KEY="$VM/keys/minisign.key" DIST="$REL" >/dev/null
SHA=$(make -s release VERSION=$V MINISIGN_KEY="$VM/keys/minisign.key" DIST="$REL" | sed -n 's/.*--release-sha256 //p')
[ -n "$SHA" ] || die "make release printed no --release-sha256"
minisign -Vqm "$REL/agentbox-$V0.tgz" -p "$VM/keys/minisign.pub" || die "V0 must verify, so that only the pin refuses it"
tar -xzf "$REL/agentbox-$V.tgz" -C "$REL/x"
{ head -n 1 "$REL/x/install.sh"; echo 'touch /run/agentbox-tampered-ran'; tail -n +2 "$REL/x/install.sh"; } > "$REL/i"
mv "$REL/i" "$REL/x/install.sh" && chmod 0755 "$REL/x/install.sh"
tar -czf "$REL/tampered.tgz" -C "$REL/x" .
minisign -G -W -p "$REL/other.pub" -s "$REL/other.key" >/dev/null
minisign -S -s "$REL/other.key" -m "$REL/agentbox-$V.tgz" -x "$REL/other.minisig" -t "agentbox $V" >/dev/null
cp "$REL/agentbox-$V0.tgz" "$REL/agentbox-$V.tgz" "$REL/www/r/" # fetched by the current/previous check
sha() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
# serve <tgz> <minisig>: what the VM gets at the seed's release URL
serve() { cp "$1" "$REL/www/.t" && cp "$2" "$REL/www/.m" && mv "$REL/www/.t" "$REL/www/agentbox-$V.tgz" && mv "$REL/www/.m" "$REL/www/agentbox-$V.tgz.minisig"; }
serve "$REL/tampered.tgz" "$REL/agentbox-$V.tgz.minisig" # firstboot's first attempt at boot gets the tampered tarball
SRV='' LSN=''
cleanup() {
  [ -z "$SRV" ] || kill "$SRV" 2>/dev/null || :
  [ -z "$LSN" ] || kill "$LSN" 2>/dev/null || :
  [ "$ENC" != tpm2+tang ] || hack/vm.sh tang down >/dev/null 2>&1 || :
}
trap cleanup EXIT
bin/release-serve -dir "$REL/www" -port "$RPORT" 2>"$REL/serve.log" &
SRV=$!
i=0; until curl -sf -o /dev/null "http://127.0.0.1:$RPORT/agentbox-$V.tgz.minisig"; do i=$((i+1)); [ $i -lt 20 ] || die "release-serve not answering on 127.0.0.1:$RPORT; see $REL/serve.log"; sleep 0.5; done
# the loopback probe: one log line per TCP connection or UDP datagram on 127.0.0.1 or ::1 port LPORT
probes() { echo $(($(wc -l < "$REL/probe.log"))); }
: > "$REL/probe.log"
python3 -c 'import select, socket as S, sys
p, log = int(sys.argv[1]), open(sys.argv[2], "a", buffering=1)
ss = []
for f, a in ((S.AF_INET, "127.0.0.1"), (S.AF_INET6, "::1")):
  for t in (S.SOCK_STREAM, S.SOCK_DGRAM):
    s = S.socket(f, t); s.setsockopt(S.SOL_SOCKET, S.SO_REUSEADDR, 1); s.bind((a, p)); t == S.SOCK_STREAM and s.listen(); ss.append(s)
while True:
  for s in select.select(ss, [], [])[0]:
    if s.type == S.SOCK_STREAM: c, a = s.accept(); c.close()
    else: a = s.recvfrom(512)[1]
    log.write("%s %s\n" % (s.type, a[0]))' "$LPORT" "$REL/probe.log" 2>"$REL/probe.err" &
LSN=$!
i=0; until [ "$(probes)" -ge 2 ]; do
  curl -s -m 1 -o /dev/null "http://127.0.0.1:$LPORT/" "http://[::1]:$LPORT/" || :
  i=$((i+1)); [ $i -lt 20 ] || die "loopback probe not answering on 127.0.0.1 and ::1 port $LPORT; see $REL/probe.err"; sleep 0.5; done

SEED="$VM/gate-seed-$TAG"
[ -d "$SEED" ] && rm -r "$SEED"
set -- --disk-serial "$SER" --boot "$BOOT" --ssh-key "$(cat "$VM/id_vm.pub")" \
  --password-hash "$PW" --minisign-pubkey "$(sed -n 2p "$VM/keys/minisign.pub")" \
  --dev --release-url "http://10.0.2.2:$RPORT/agentbox-$V.tgz" --release-sha256 "$SHA" --encryption "$ENC" --out "$SEED"
[ "$ENC" = none ] || set -- "$@" --recovery-pub "$VM/keys/recovery.pub"
if [ "$ENC" = tpm2+tang ]; then
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
    for d in disk disk2; do # every extent the guest wrote is "present", a zero write ("data": false) too; a map with no "present": false can't tell
      if m=$(qemu-img map --output=json "$VM/$d.qcow2") && echo "$m" | grep -q '"present": false' && ! echo "$m" | grep -q '"present": true'; then echo "PASS $d.qcow2 never written"; else echo "FAIL $d.qcow2 written or unreadable"; n=1; fi
    done
    echo "fails=$n"; } | tee "$OUT"
  verdict 1; exit 0
fi
hack/vm.sh install "$SEED"
hack/vm.sh boot &
QEMU=$!
# booted <boot_id>: wait until SSH answers from any other boot, then print its boot_id
booted() {
  end=$(( $(date +%s) + 720 * SLOW ))
  until b=$(hack/vm.sh ssh cat /proc/sys/kernel/random/boot_id 2>/dev/null) && [ "$b" != "$1" ]; do
    [ "$(date +%s)" -lt "$end" ] || die "no SSH after boot (LUKS or boot failure); see $VM/boot-*.log"; sleep 5; done
  echo "$b"
}
reboot_vm() { echo 'systemctl reboot' | vmroot >/dev/null 2>&1 || :; BID=$(booted "$BID"); }
BID=$(booted none)

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
# subiquity writes usr/ and var/ into the top level after late-commands; agentbox-firstboot removes them, so allow it 180 s * SLOW
check "top level holds only @* (firstboot cleanup)" 'mkdir -p /run/chk && mount -o subvolid=5 "\$(findmnt -n -v -o SOURCE /)" /run/chk || exit 1; i=0; while ls -A /run/chk | grep -qv "^@"; do i=\$((i+1)); [ \$i -lt $((36 * SLOW)) ] || { umount /run/chk; exit 1; }; sleep 5; done; umount /run/chk'
check "no nested subvolumes"             '[ -z "\$(btrfs subvolume list / | awk "{print \\\$NF}" | grep /)" ]'
check "initramfs bakes no root flags"    '! journalctl -b -o cat | grep -q "rootflags=[^ ]*subvolid=5"'
check "zram swap"                        'swapon --show=NAME --noheadings | grep -q zram0'
check "apt timers masked"                '[ "\$(systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer | sort -u)" = masked ]'
check "nftables, snapd, lxd-installer, secureboot-db masked" '[ "\$(systemctl is-enabled nftables.service snapd.socket snapd.service snapd.seeded.service snapd.snap-repair.timer lxd-installer.socket secureboot-db.service | sort -u)" = masked ]'
# is-enabled says masked for any masked name, unit file or not: the vendor files pin the names, so a rename fails here
check "grub2-common, grub-initrd-fallback masked (no in-place grubenv rewrites)" '[ -f /usr/lib/systemd/system/grub2-common.service ] && [ -f /usr/lib/systemd/system/grub-initrd-fallback.service ] && [ "\$(systemctl is-enabled grub2-common.service grub-initrd-fallback.service | sort -u)" = masked ]'
check "fwupd only refreshes metadata"    '[ "\$(systemctl is-enabled fwupd-refresh.timer)" = enabled ] && systemctl cat fwupd-refresh.service | grep -qx "ExecStart=/usr/bin/fwupdmgr refresh"'
check "kdump-tools purged, no grub.d snippet" '! dpkg -s kdump-tools && [ ! -e /etc/default/grub.d/kdump-tools.cfg ]'
check "no crashkernel= on the cmdline"   '! grep -q crashkernel= /proc/cmdline'
check "emergency reboots"                'grep -q FailureAction=reboot-force /etc/systemd/system/emergency.service.d/90-agentbox.conf'
check "watchdog: PID 1 drives $WD, 60 s" '[ "\$(cat /sys/class/watchdog/watchdog0/identity /sys/class/watchdog/watchdog0/state /sys/class/watchdog/watchdog0/timeout | paste -sd,)" = "$WDID,active,60" ]'
check "dracut: hostonly, forced modules, driver chain [$DRV ], watchdog driver" 'f=/etc/dracut.conf.d/90-agentbox.conf; grep -qx "hostonly=\"yes\"" \$f && grep -qx "hostonly_cmdline=\"no\"" \$f && grep -q "^add_dracutmodules+=\" btrfs " \$f && grep -qx "add_drivers+=\"$DRV \"" \$f && grep -qx "force_drivers+=\" $WD \"" \$f'
check "every kernel's initrd has btrfs$DRV $WD" 'for k in \$(ls /boot | sed -n "s/^vmlinuz-//p"); do l=\$(lsinitrd /boot/initrd.img-\$k) || exit 1; for m in btrfs $DRV $WD; do echo "\$l" | grep -q "/\$m\.ko" || exit 1; done; done'
check "installer logs persist in @var_log" '[ "\$(findmnt -n -o FSROOT -T /var/log/installer)" = /@var_log ] && [ -s /var/log/installer/installer-journal.txt ] && [ -s /var/log/installer/subiquity-server-debug.log ] && [ -s /var/log/installer/cloud-init.log ]'
# grep exits 2 on a missing path or a read error even after a match: PASS only on 1 (read everything, matched nothing)
check "no password hash under /var/log (installer, subiquity, cloud-init, journal)" 'grep -rqF gatesalt /var/log; [ \$? = 1 ] && { grep -rqF -e "\\\$6\\\$" -e "\\\$y\\\$" /var/log/installer /var/log/cloud-init.log /var/log/cloud-init-output.log; [ \$? = 1 ]; }'
check "seed copy scrubbed"               '[ ! -e /var/log/installer/autoinstall-user-data ]'
check "disk guard saw exactly one $SER"  '[ "\$(grep -c "agentbox: disk [^ ]* ID_SERIAL=$SER\\\$" /var/log/installer/installer-journal.txt)" = 1 ]'
check "umount -R left the live installer's /dev/pts and /sys/fs/cgroup" 'grep -q "+ mountpoint -q /sys/fs/cgroup" /var/log/installer/installer-journal.txt'
check "firstboot script installed from stdin, 0755" '[ "\$(stat -c %a /usr/local/sbin/agentbox-firstboot)" = 755 ] && grep -q "touch /var/lib/agentbox/.firstboot-done" /usr/local/sbin/agentbox-firstboot'
check "no failed units"                  '[ -z "\$(systemctl --failed --no-legend --plain)" ]'
check "dracut builds the initramfs"      'dpkg -s dracut | grep -q "Status: install ok installed"'
if [ "$BOOT" = bios ]; then
  check "booted by BIOS (no EFI)"        '[ ! -d /sys/firmware/efi ]'
elif [ "$SB" = 1 ]; then
  check "Secure Boot on (mokutil)"       'mokutil --sb-state | grep -q "SecureBoot enabled"'
else
  check "Secure Boot off (mokutil)"      'mokutil --sb-state | grep -q "SecureBoot disabled"'
fi
# under Secure Boot shim refuses an unsigned kernel, so its menu entries can't boot (ARCHITECTURE §3.3 post-commit step 1)
[ "$BOOT" = bios ] || check "shim accepts every kernel (is-not-revoked)" 'for k in /bootpart/agentbox/gens/*/vmlinuz-*; do /usr/lib/shim/is-not-revoked "\$k" || exit 1; done'
if [ "$ENC" != none ]; then
  check "root on LUKS (croot)"           'findmnt -n -o SOURCE / | grep -q "^/dev/mapper/croot"'
  check "LUKS has a clevis token"        'cryptsetup luksDump "\$(cryptsetup status croot | awk "/device:/{print \\\$2}")" | grep -q ": clevis"'
  check "unlocked by clevis"             'journalctl -b -o cat | grep -q "Finished systemd-cryptsetup@croot.service" && journalctl -b -t clevis-luks-askpass -o cat | grep -q "^Unlocked "'
  check "recovery.bin present"           '[ -s /bootpart/agentbox/recovery.bin ]'
  check "09_agentbox sets rd.luks.uuid"  'u=\$(grep -o "rd.luks.uuid=[^ ]*" /proc/cmdline) && grep -q "^croot UUID=\${u#rd.luks.uuid=} " /etc/crypttab'
  check "crypttab: croot names no keyfile" 'grep -qE "^croot [^ ]+ none " /etc/crypttab'
  check "late-commands shredded the installer keyfile" 'grep -qF "+ shred -u /run/agentbox-luks.key" /var/log/installer/installer-journal.txt'
fi
if [ "$ENC" = tpm2+tang ]; then
  # sss with t=2 needs both pins, so "unlocked by clevis" above also proves the initramfs reached Tang. Every instance's
  # Tang serves the same keys, so the URL proves it was this instance's Tang.
  check "clevis binding is sss tpm2+tang at $TANG_URL" 'd=\$(cryptsetup status croot | awk "/device:/{print \\\$2}"); l=\$(clevis luks list -d "\$d"); echo "\$l" | grep -q sss && echo "\$l" | grep -q tpm2 && echo "\$l" | grep -qF "$TANG_URL\""'
  check "initramfs brings up network"     'grep -q "rd.neednet=1" /proc/cmdline'
fi
echo "fails=\$fails"
EOF

# useradd -U fails on any user or group name the box has, after the disk is wiped: the seed must refuse every one of
# them (ARCHITECTURE §3.1), including what an ISO bump or a seed package adds. "$@" still holds the gate seed's flags.
names=$(hack/vm.sh ssh 'cut -d: -f1 /etc/passwd /etc/group' | sort -u | grep -vx boxadmin) || :
took=
for u in $names; do ./bin/agentbox seed "$@" --admin "$u" --out "$VM/taken-seed" 2>&1 | grep -qF "admin user \"$u\"" || took="$took $u"; done
rm -rf "$VM/taken-seed"
if [ -n "$names" ] && [ -z "$took" ]; then echo "PASS the seed refuses --admin for every other user and group on the box"
else echo "FAIL the seed takes --admin${took:- (read no users from the box)}"; fi | tee -a "$OUT"

if [ "$ENC" != none ]; then # the offline recovery path: recovery.bin -> key -> opens LUKS
  W=$(mktemp -d "$VM/recov.XXXX")
  hack/vm.sh ssh cat /bootpart/agentbox/recovery.bin > "$W/recovery.bin"
  ./bin/agentbox recovery decrypt --key "$VM/keys/recovery.key" --in "$W/recovery.bin" --out "$W/luks.key" >/dev/null
  # tr -dc 0-9 | head -c 48 ran under the live installer's uutils: the key must be exactly 48 digits, typeable at the prompt
  if grep -qxE '[0-9]{48}' "$W/luks.key"; then echo "PASS the LUKS key is 48 digits"; else echo "FAIL the LUKS key is not 48 digits"; fi | tee -a "$OUT"
  # PASS/FAIL from the exit status, printed here: a failed ssh or sudo can't drop the line, and the key file goes either way
  if { echo x; cat "$W/luks.key"; } | hack/vm.sh ssh 'sudo -S -p "" sh -c "umask 077; head -c 48 > /run/rk.key; d=\$(cryptsetup status croot | awk \"/device:/{print \\\$2}\"); cryptsetup open --test-passphrase --key-file /run/rk.key \$d; r=\$?; shred -u /run/rk.key; exit \$r"'; then echo "PASS recovery key opens LUKS"; else echo "FAIL recovery key opens LUKS"; fi | tee -a "$OUT"
  # the key goes on stdin, never on a command line: no file the installer or the box wrote may hold it (THREAT-MODEL 7)
  g=$({ echo x; cat "$W/luks.key"; } | hack/vm.sh ssh 'sudo -S -p "" sh -c "grep -rqaF -f - /var/log /etc /bootpart /boot; echo grep=\$?"' || :)
  if [ "$g" = grep=1 ]; then echo "PASS the LUKS key is in no file under /var/log, /etc, /bootpart or /boot"; else echo "FAIL the LUKS key is in a file under /var/log, /etc, /bootpart or /boot, or the search failed ($g)"; fi | tee -a "$OUT"
fi

: > "$VM/gate-$TAG.log"
# vm_check <name>: run stdin as root in the VM (sudo's password "x" is a test-seed value); PASS if it exits 0
vm_check() {
  if vmroot >>"$VM/gate-$TAG.log" 2>&1; then r=PASS; else r=FAIL; fi
  echo "$r $1" | tee -a "$OUT"
}
# refused <what> <tgz> <minisig> <journal line>: a firstboot attempt on that release logs the line, installs nothing and
# leaves nothing in /run (systemd removes the RuntimeDirectory before the restart job returns; the next try is 60 s off)
refused() {
  serve "$2" "$3"
  vm_check "firstboot refuses $1" <<EOF
t=\$(date +%s)
if timeout $((300 * SLOW)) systemctl restart agentbox-firstboot.service; then exit 1; fi # returns when this attempt ends
journalctl -u agentbox-firstboot.service --since @\$t -o cat | grep -F "$4" &&
  [ ! -e /var/lib/agentbox/releases ] && [ ! -e /var/lib/agentbox/current ] && [ ! -e /etc/systemd/system/agentbox-reconcile.service ] && [ ! -e /run/agentbox-tampered-ran ] &&
  ! ls -d /run/agentbox-firstboot* 2>/dev/null
EOF
}
refused "a tampered tarball" "$REL/tampered.tgz" "$REL/agentbox-$V.tgz.minisig" "release sha256 $(sha "$REL/tampered.tgz") does not match"
refused "an older signed release (sha256 pin)" "$REL/agentbox-$V0.tgz" "$REL/agentbox-$V0.tgz.minisig" "release sha256 $(sha "$REL/agentbox-$V0.tgz") does not match"
refused "a signature by another key" "$REL/agentbox-$V.tgz" "$REL/other.minisig" "release signature does not verify"

# The good release, in a real boot: firstboot's nested `systemctl start agentbox-reconcile.service` runs inside the boot
# transaction, so a reconcile unit ordered after multi-user.target or firstboot would keep the boot from finishing.
echo 'systemctl stop agentbox-firstboot.service' | vmroot # no retry before the reboot
serve "$REL/agentbox-$V.tgz" "$REL/agentbox-$V.tgz.minisig"
reboot_vm
{ cat <<EOF; } | vmroot | tee -a "$OUT"
fails=0
check() { if (eval "\$2") >/dev/null 2>&1; then echo "PASS \$1"; else echo "FAIL \$1"; fails=\$((fails+1)); fi; }
check "boot finishes: firstboot's nested reconcile start returned" '[ "\$(timeout $((600 * SLOW)) systemctl is-system-running --wait)" = running ] && [ "\$(systemctl show -P SubState agentbox-firstboot.service)" != start ]'
check "firstboot installed release $V"   '[ "\$(readlink /var/lib/agentbox/current)" = releases/$V ] && [ ! -e /var/lib/agentbox/previous ]'
check "a non-root uid runs current/bin/agentbox" '[ "\$(runuser -u nobody -- /var/lib/agentbox/current/bin/agentbox version)" = $V ]'
check "reconcile ran, enabled for multi-user.target" '[ "\$(systemctl is-active agentbox-reconcile.service)" = active ] && [ "\$(systemctl is-enabled agentbox-reconcile.service)" = enabled ]'
# systemd-analyze verify passes even with either ordering (both tried by hand on 26.04.1), so check After= itself
check "reconcile not ordered after multi-user.target or firstboot" '! systemctl show -P After agentbox-reconcile.service | grep -Eq "multi-user.target|agentbox-firstboot"'
check "systemd-analyze verify: reconcile and firstboot units" 'systemd-analyze verify agentbox-reconcile.service agentbox-firstboot.service'
check "firstboot done, no retry loop"    '[ -e /var/lib/agentbox/.firstboot-done ] && [ "\$(systemctl show -P Result agentbox-firstboot.service)" = success ] && [ "\$(systemctl show -P SubState agentbox-firstboot.service)" = dead ]'
check "firstboot leaves no /run copies"  '! ls -d /run/agentbox-firstboot*'
check "no failed units"                  '[ -z "\$(systemctl --failed --no-legend --plain)" ]'
# the boot has finished (first check), so any unit that rewrites grubenv in place has run; GRUB's own save_env moves no mtime
check "nothing rewrote grubenv during this boot" '[ "\$(stat -c %Y /boot/grub/grubenv)" -lt "\$(awk "/^btime/{print \\\$2}" /proc/stat)" ]'
echo "fails=\$fails"
EOF
vm_check "install.sh switches current/previous by rename, reruns cleanly, refuses changed content" <<EOF
systemctl stop agentbox-firstboot.service # its retries would run install.sh at the same time
A=/var/lib/agentbox x=\$(mktemp -d)
for v in $V0 $V; do mkdir "\$x/\$v" && curl -fsS "http://10.0.2.2:$RPORT/r/agentbox-\$v.tgz" | tar -xz -C "\$x/\$v" || exit 1; done
l() { [ "\$(readlink \$A/current)" = "releases/\$1" ] && [ "\$(readlink \$A/previous)" = "releases/\$2" ]; }
"\$x/$V0/install.sh" --from-firstboot && l $V0 $V && "\$x/$V/install.sh" --from-firstboot && l $V $V0 &&
  "\$x/$V/install.sh" --from-firstboot && l $V $V0 || exit 1
echo '# changed' >> "\$x/$V/systemd/agentbox-reconcile.service"
! "\$x/$V/install.sh" --from-firstboot && l $V $V0 && [ "\$(ls -A \$A/releases | tr '\n' ' ')" = "$V0 $V " ] && [ -z "\$(ls -A \$A | grep '^\.' | grep -v '^\.firstboot-done\$')" ]
EOF
# The guest tries the probe port on every address slirp maps to the host's loopback, TCP and UDP. A failed connect is
# expected; a line in probe.log is the failure. It must still reach release-serve, so the check can't pass on no network.
n=$(probes)
vm_check "the guest reaches release-serve at 10.0.2.2:$RPORT and no other host loopback port (TCP/UDP $LPORT)" <<EOF
curl -fsS -o /dev/null "http://10.0.2.2:$RPORT/agentbox-$V.tgz.minisig" || exit 1
python3 - <<'PY'
import socket as S
for f, a in ((S.AF_INET, "10.0.2.2"), (S.AF_INET, "255.255.255.255"), (S.AF_INET6, "fec0::2")):
  for t in (S.SOCK_STREAM, S.SOCK_DGRAM):
    s = S.socket(f, t); s.settimeout(5)
    if f == S.AF_INET: s.setsockopt(S.SOL_SOCKET, S.SO_BROADCAST, 1)
    try:
      if t == S.SOCK_STREAM: s.connect((a, $LPORT)); s.sendall(b"x")
      else: s.sendto(b"x", (a, $LPORT))
    except OSError as e: print(a, t, e)
    s.close()
PY
sleep 2
EOF
if [ "$(probes)" = "$n" ]; then echo "PASS the host's loopback probe saw nothing from the guest"
else echo "FAIL the guest reached the host's loopback probe on $LPORT:"; tail -n +$((n + 1)) "$REL/probe.log"; fi | tee -a "$OUT"
reboot_vm
vm_check "next boot finishes, reconcile started by multi-user.target, no failed units" <<EOF
[ "\$(timeout $((600 * SLOW)) systemctl is-system-running --wait)" = running ] && [ "\$(systemctl is-active agentbox-reconcile.service)" = active ]
EOF
vm_check "firstboot does not run again" <<'EOF'
[ "$(systemctl show -P ConditionResult agentbox-firstboot.service)" = no ]
EOF
echo 'journalctl -u agentbox-firstboot.service -u agentbox-reconcile.service -u multi-user.target -o short-precise --no-pager' |
  vmroot > "$VM/gate-$TAG-journal.txt" 2>&1 || :
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
  QEMU=$!
  until LOG=$(ls -t "$VM"/boot-*.log | head -n 1) && [ "$LOG" != "$last" ]; do sleep 1; done
  t1=0 t2=0
  seen "$P" 1 $((180 * SLOW)) && t1=$(date +%s) && seen 'reboot: Restarting system' 1 $((720 * SLOW)) && t2=$(date +%s)
  result "Tang down: no unlock; the box rebooted $((t2 - t1)) s after the LUKS prompt (timeout=300s, then rd.retry)" \
    '[ "$t1" -gt 0 ] && [ $((t2 - t1)) -ge 300 ] && grep -aq "Could not boot" "$LOG"'
  if seen "$P" 2 $((180 * SLOW)); then sleep 2; { cat "$W/luks.key"; printf '\r'; sleep 3; } | nc -U "$VM/console.sock" >/dev/null 2>&1 & k=$!; sleep 6; kill "$k" 2>/dev/null || :; fi
  ssh_up $((240 * SLOW)) || :
  result "typed recovery key unlocks (Tang down, clevis did not)" '! podman container exists "agentbox-tang-${AGENTBOX_VM_ID:-0}" &&
    echo "journalctl -b -o cat" | vmroot | grep -q "Finished systemd-cryptsetup@croot.service" &&
    ! echo "journalctl -b -t clevis-luks-askpass -o cat" | vmroot | grep -q "^Unlocked " && ! grep -aqF -f "$W/luks.key" "$LOG"'
  echo 'systemctl reboot' | vmroot >/dev/null 2>&1 || :
  seen "$P" 3 $((300 * SLOW)) && hack/vm.sh tang up >/dev/null
  ssh_up $((240 * SLOW)) || :
  result "unlocks once Tang is back (clevis, no input, no reboot)" 'echo "journalctl -b -t clevis-luks-askpass -o cat" | vmroot | grep -q "^Unlocked " &&
    [ "$(grep -ac "reboot: Restarting system" "$LOG")" -eq 2 ]'
  vm_off
fi
[ "$ENC" = none ] || { rm -P "$W/luks.key" 2>/dev/null || rm -f "$W/luks.key"; }
verdict 2

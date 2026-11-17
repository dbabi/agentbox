#!/bin/sh
# Week-1 install gates (PLAN.md week 1, ARCHITECTURE.md §15) on the local QEMU VM.
#   hack/gate.sh none|tpm2|tpm2+tang   build and serve test releases, render a test seed, install unattended, boot,
#                                      check every gate item (bad releases refused, firstboot), reboot, check, power off
# tpm2+tang runs a throwaway Tang container (vm.sh tang) on 127.0.0.1:7500+ID; the VM reaches it as 10.0.2.2:7500+ID.
# hack/release-serve serves the test releases on 127.0.0.1:7600+ID; the --dev seed fetches from 10.0.2.2:7600+ID.
# AGENTBOX_VM_ID and AGENTBOX_ISO_DIR pass through to vm.sh: gates that run at once need distinct IDs and separate checkouts.
# Test seeds only: the admin password is "x"; the recovery and release-signing keys live in .vm/keys. Never use them for a real box.
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
RPORT=$((7600 + ${AGENTBOX_VM_ID:-0})) REL="$VM/release" V=0.0.1-gate V0=0.0.0-gate
command -v minisign >/dev/null || die "minisign not installed (brew install minisign)"

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
SRV=
cleanup() {
  [ -z "$SRV" ] || kill "$SRV" 2>/dev/null || :
  [ "$ENC" != tpm2+tang ] || hack/vm.sh tang down >/dev/null 2>&1 || :
}
trap cleanup EXIT
bin/release-serve -dir "$REL/www" -port "$RPORT" 2>"$REL/serve.log" &
SRV=$!
i=0; until curl -sf -o /dev/null "http://127.0.0.1:$RPORT/agentbox-$V.tgz.minisig"; do i=$((i+1)); [ $i -lt 20 ] || die "release-serve not answering on 127.0.0.1:$RPORT; see $REL/serve.log"; sleep 0.5; done

SEED="$VM/gate-seed-$ENC"
[ -d "$SEED" ] && rm -r "$SEED"
set -- --disk-serial QEMU_NVMe_Ctrl_QM00001_1 --ssh-key "$(cat "$VM/id_vm.pub")" \
  --password-hash "$(openssl passwd -6 -salt gatesalt x)" --minisign-pubkey "$(sed -n 2p "$VM/keys/minisign.pub")" \
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
hack/vm.sh install "$SEED"
hack/vm.sh boot &
QEMU=$!
# booted <boot_id>: wait until SSH answers from any other boot, then print its boot_id
booted() {
  end=$(( $(date +%s) + 720 ))
  until b=$(hack/vm.sh ssh cat /proc/sys/kernel/random/boot_id 2>/dev/null) && [ "$b" != "$1" ]; do
    [ "$(date +%s)" -lt "$end" ] || die "no SSH after boot (LUKS or boot failure); see $VM/boot-*.log"; sleep 5; done
  echo "$b"
}
reboot_vm() { { echo x; echo 'systemctl reboot'; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' 2>/dev/null || :; BOOT=$(booted "$BOOT"); }
BOOT=$(booted none)

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

: > "$VM/gate-$ENC.log"
# vm_check <name>: run stdin as root in the VM (sudo's password "x" is a test-seed value); PASS if it exits 0
vm_check() {
  if { echo x; cat; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' >>"$VM/gate-$ENC.log" 2>&1; then r=PASS; else r=FAIL; fi
  echo "$r $1" | tee -a "$VM/gate-$ENC.txt"
}
# refused <what> <tgz> <minisig> <journal line>: a firstboot attempt on that release logs the line and installs nothing
refused() {
  serve "$2" "$3"
  vm_check "firstboot refuses $1" <<EOF
t=\$(date +%s)
if timeout 300 systemctl restart agentbox-firstboot.service; then exit 1; fi # returns when this attempt ends
journalctl -u agentbox-firstboot.service --since @\$t -o cat | grep -F "$4" &&
  [ ! -e /var/lib/agentbox/releases ] && [ ! -e /var/lib/agentbox/current ] && [ ! -e /etc/systemd/system/agentbox-reconcile.service ] && [ ! -e /run/agentbox-tampered-ran ]
EOF
}
refused "a tampered tarball" "$REL/tampered.tgz" "$REL/agentbox-$V.tgz.minisig" "release sha256 $(sha "$REL/tampered.tgz") does not match"
refused "an older signed release (sha256 pin)" "$REL/agentbox-$V0.tgz" "$REL/agentbox-$V0.tgz.minisig" "release sha256 $(sha "$REL/agentbox-$V0.tgz") does not match"
refused "a signature by another key" "$REL/agentbox-$V.tgz" "$REL/other.minisig" "release signature does not verify"

# The good release, in a real boot: firstboot's nested `systemctl start agentbox-reconcile.service` runs inside the boot
# transaction, so a reconcile unit ordered after multi-user.target or firstboot would keep the boot from finishing.
{ echo x; echo 'systemctl stop agentbox-firstboot.service'; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' # no retry before the reboot
serve "$REL/agentbox-$V.tgz" "$REL/agentbox-$V.tgz.minisig"
reboot_vm
{ echo x; cat <<EOF; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' | tee -a "$VM/gate-$ENC.txt"
fails=0
check() { if (eval "\$2") >/dev/null 2>&1; then echo "PASS \$1"; else echo "FAIL \$1"; fails=\$((fails+1)); fi; }
check "boot finishes: firstboot's nested reconcile start returned" '[ "\$(timeout 600 systemctl is-system-running --wait)" = running ] && [ "\$(systemctl show -P SubState agentbox-firstboot.service)" != start ]'
check "firstboot installed release $V"   '[ "\$(readlink /var/lib/agentbox/current)" = releases/$V ] && [ ! -e /var/lib/agentbox/previous ]'
check "a non-root uid runs current/bin/agentbox" '[ "\$(runuser -u nobody -- /var/lib/agentbox/current/bin/agentbox version)" = $V ]'
check "reconcile ran, enabled for multi-user.target" '[ "\$(systemctl is-active agentbox-reconcile.service)" = active ] && [ "\$(systemctl is-enabled agentbox-reconcile.service)" = enabled ]'
# systemd-analyze verify passes even with either ordering (both tried by hand on 26.04.1), so check After= itself
check "reconcile not ordered after multi-user.target or firstboot" '! systemctl show -P After agentbox-reconcile.service | grep -Eq "multi-user.target|agentbox-firstboot"'
check "systemd-analyze verify: reconcile and firstboot units" 'systemd-analyze verify agentbox-reconcile.service agentbox-firstboot.service'
check "firstboot done, no retry loop"    '[ -e /var/lib/agentbox/.firstboot-done ] && [ "\$(systemctl show -P Result agentbox-firstboot.service)" = success ] && [ "\$(systemctl show -P SubState agentbox-firstboot.service)" = dead ]'
check "no failed units"                  '[ -z "\$(systemctl --failed --no-legend --plain)" ]'
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
reboot_vm
vm_check "next boot finishes, reconcile started by multi-user.target, no failed units" <<'EOF'
[ "$(timeout 600 systemctl is-system-running --wait)" = running ] && [ "$(systemctl is-active agentbox-reconcile.service)" = active ]
EOF
vm_check "firstboot does not run again" <<'EOF'
[ "$(systemctl show -P ConditionResult agentbox-firstboot.service)" = no ]
EOF
{ echo x; echo 'journalctl -u agentbox-firstboot.service -u agentbox-reconcile.service -o short-precise --no-pager'; } |
  hack/vm.sh ssh 'sudo -S -p "" sh -s' > "$VM/gate-$ENC-journal.txt" 2>&1 || :

{ echo x; echo 'systemctl poweroff'; } | hack/vm.sh ssh 'sudo -S -p "" sh -s' 2>/dev/null || :
wait "$QEMU" 2>/dev/null || : # not plain wait: release-serve runs until the trap
! grep -q '^FAIL' "$VM/gate-$ENC.txt" || die "gate $ENC failed; see $VM/gate-$ENC.txt"
[ "$(grep -c '^fails=0$' "$VM/gate-$ENC.txt")" -eq 2 ] || die "gate $ENC did not finish its checks; see $VM/gate-$ENC.txt"
echo "gate $ENC: all checks passed"

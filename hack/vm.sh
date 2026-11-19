#!/bin/sh
# Local QEMU test VM for agentbox (PLAN.md weeks 1-2). The seed's boot mode picks the machine:
#   uefi: arm64 virt + HVF on Apple Silicon, resolute's AAVMF with Secure Boot on (SECUREBOOT=0: no keys enrolled)
#   bios: amd64 q35 + SeaBIOS under TCG (KVM where the host has it), SATA disk; slow on the Mac
#   hack/vm.sh install <seed-dir>   unattended install; fails on installer errors or after INSTALL_TIMEOUT s
#                                   (DUP_DISK=1: also attach a second disk with the same serial; nvme or virtio)
#   hack/vm.sh boot                 boot the installed disk (SSH on 127.0.0.1:2222+ID; console also on .vm/console.sock)
#   hack/vm.sh tang up|down|thp     Tang for tpm2+tang seeds on 127.0.0.1:7500+ID, guest URL http://10.0.2.2:7500+ID (needs podman)
#   hack/vm.sh ssh [cmd]            SSH into the VM as boxadmin with the throwaway key in .vm/id_vm
#   hack/vm.sh cut                  power-cut the running VM (QMP system_reset)
#   hack/vm.sh reset                delete the VM disk, UEFI vars and TPM state
# install boots the zero-touch ISO (hack/remaster-iso.sh, built once into .vm) through the firmware, as real hardware
# does: shim and GRUB on UEFI, GRUB on BIOS. DIRECT_KERNEL=1 boots the stock ISO's kernel with -kernel instead; on UEFI
# it needs SECUREBOOT=0, because Secure Boot refuses a kernel that shim did not load.
# AAVMF comes from resolute's qemu-efi-aarch64 .deb, fetched into .vm/fw once and checked against hack/SHA256SUMS on
# every install. SeaBIOS is QEMU's own.
# AGENTBOX_VM_ID (0-9, default 0) picks the host ports and the Tang container agentbox-tang-ID. Everything else lives in
# this checkout's .vm, so VMs that run at once need distinct IDs and separate checkouts (git worktrees).
# AGENTBOX_ISO_DIR (default .vm) holds the stock ISOs, so worktrees can share one copy. Every install checks its stock
# ISO against hack/SHA256SUMS, with or without DIRECT_KERNEL.
# AGENTBOX_BLKLOG=<file>: QEMU logs every guest disk write and flush to <file>, dm-log-writes format (hack/powercut.sh).
# A TPM is attached in both phases whenever the seed is encrypted. Logs go to .vm/<phase>*.log (serial console).
# Host ports listen on 127.0.0.1 only, but the guest can reach every Mac service on 127.0.0.1 through 10.0.2.2.
set -eu
die() { echo "vm.sh: $*" >&2; exit 1; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VM="$ROOT/.vm"
ID=${AGENTBOX_VM_ID:-0}
case $ID in [0-9]) ;; *) die "AGENTBOX_VM_ID must be 0-9" ;; esac
SSH_PORT=$((2222 + ID)) TANG_PORT=$((7500 + ID)) TANG=agentbox-tang-$ID
DISK="$VM/disk.qcow2"
SERIAL=QM00001
FWDEB=qemu-efi-aarch64_2025.11-3ubuntu7.3_all.deb # resolute-updates
mkdir -p "$VM"

running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }
# QEMU splits key=value options (-drive file=, path=, unix:) on single commas and reads ",," as one.
# -serial file:, -pidfile, -kernel and -initrd take the path as is.
qopt() { printf '%s' "$1" | sed 's/,/,,/g'; }
tang_thp() { podman exec "$TANG" tang-show-keys 7500 | head -1; }
pinned() { [ -f "$1" ] && [ "$(sha256sum < "$1" | cut -d' ' -f1)" = "$(awk -v f="${1##*/}" '$2 == f {print $1}' "$ROOT/hack/SHA256SUMS")" ]; }

# fw: resolute's AAVMF in .vm/fw. CODE.ms.fd is the Secure Boot build; VARS.ms.fd enrolls Microsoft's keys and turns
# Secure Boot on, VARS.fd enrolls none.
fw() {
  set -- AAVMF_CODE.ms.fd AAVMF_VARS.ms.fd AAVMF_VARS.fd
  ok=1; for f; do pinned "$VM/fw/$f" || ok=; done
  [ -n "$ok" ] && return 0
  t=$(mktemp -d "$VM/fw.XXXXXX")
  curl -fsSL --retry 3 -o "$t/$FWDEB" "https://launchpad.net/ubuntu/+archive/primary/+files/$FWDEB" || die "could not download $FWDEB"
  pinned "$t/$FWDEB" || die "$FWDEB does not match hack/SHA256SUMS"
  (cd "$t" && ar x "$FWDEB" data.tar.zst && tar -xf data.tar.zst ./usr/share/AAVMF) || die "could not unpack $FWDEB"
  mkdir -p "$VM/fw"
  for f; do cp "$t/usr/share/AAVMF/$f" "$VM/fw/$f"; pinned "$VM/fw/$f" || die "$VM/fw/$f does not match hack/SHA256SUMS"; done
  rm -rf "$t"
}

tpm_start() {
  [ -f "$VM/tpm.on" ] || return 0
  command -v swtpm >/dev/null || die "swtpm not installed (brew install swtpm)"
  mkdir -p "$VM/tpm"
  pkill -F "$VM/tpm/pid" -x swtpm 2>/dev/null || : # only a process that is really swtpm
  while pgrep -F "$VM/tpm/pid" -x swtpm >/dev/null 2>&1; do sleep 0.2; done
  # terminate: swtpm exits with QEMU instead of holding the state lock.
  # Relative paths: swtpm splits its options on every comma, with no escape, and keeps this working directory.
  (cd "$VM/tpm" && swtpm socket --tpm2 --tpmstate dir=. --ctrl type=unixio,path=sock,terminate --pid file=pid --daemon)
}

# run_qemu <phase args>: QEMU for $ARCH with this instance's firmware, disk, network and TPM. It execs, so after
# `run_qemu ... &`, $! is QEMU.
run_qemu() {
  case "$DISKBUS" in nvme) dev=nvme ;; sata) dev=ide-hd,bus=ide.0 ;; virtio) dev=virtio-blk-pci ;; *) die "DISKBUS must be nvme, sata or virtio" ;; esac
  if [ -f "$VM/tpm.on" ]; then
    case $ARCH in
    # ppi=off: the 0x400-byte PPI RAM region is not 16 KiB aligned, and HVF refuses to map it (QEMU aborts)
    arm64) set -- -device tpm-tis-device,tpmdev=tpm0,ppi=off "$@" ;;
    amd64) set -- -device tpm-tis,tpmdev=tpm0 "$@" ;;
    esac
    set -- -chardev "socket,id=chrtpm,path=$(qopt "$VM/tpm/sock")" -tpmdev emulator,id=tpm0,chardev=chrtpm "$@"
  fi
  if [ -f "$VM/disk2.qcow2" ]; then
    case "$DISKBUS" in
      # its own NVMe subsystem: with the default NQN (made from the serial) Linux would reject the second controller
      nvme) set -- -device nvme-subsys,id=dupsys,nqn=nqn.2019-08.org.qemu:agentbox-dup -device "nvme,id=dupctl,serial=$SERIAL,subsys=dupsys" \
              -drive "if=none,id=d1,format=qcow2,file=$(qopt "$VM/disk2.qcow2")" -device nvme-ns,drive=d1,bus=dupctl,nsid=1 "$@" ;;
      virtio) set -- -drive "if=none,id=d1,format=qcow2,file=$(qopt "$VM/disk2.qcow2")" -device "virtio-blk-pci,drive=d1,serial=$SERIAL" "$@" ;;
    esac
  fi
  disk="format=qcow2,file=$(qopt "$DISK")"
  [ -z "${AGENTBOX_BLKLOG:-}" ] ||
    disk="driver=blklogwrites,file.driver=qcow2,file.file.filename=$(qopt "$DISK"),log.driver=file,log.filename=$(qopt "$AGENTBOX_BLKLOG")"
  set -- -smp 4 -m 4096 -display none \
    -drive "if=none,id=d0,$disk" -device "$dev,drive=d0,serial=$SERIAL" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" -device virtio-net-pci,netdev=n0 \
    -device virtio-rng-pci -pidfile "$VM/qemu.pid" -qmp "unix:$(qopt "$VM/qmp.sock"),server=on,wait=off" "$@"
  case $ARCH in
  # virt-11.0: from 11.1 on, virt under HVF uses the in-kernel GICv3, where resolute's AAVMF hangs before its boot
  # manager runs. 11.0 keeps QEMU's emulated GICv2.
  arm64) exec qemu-system-aarch64 -machine virt-11.0 -accel hvf -cpu host \
    -drive "if=pflash,format=raw,readonly=on,file=$(qopt "$VM/fw/AAVMF_CODE.ms.fd")" \
    -drive "if=pflash,format=raw,file=$(qopt "$VM/vars.fd")" "$@" ;;
  # SeaBIOS is QEMU's default x86 firmware. KVM where the host has it (Linux CI), else TCG. The i6300esb is amd64's
  # only: arm64 virt has no watchdog device, so that VM boots the seed's softdog fallback (ARCHITECTURE §3.3)
  amd64) exec qemu-system-x86_64 -machine q35 -accel kvm -accel tcg -cpu max -device i6300esb "$@" ;;
  *) die "unknown VM arch $ARCH" ;;
  esac
}

cmd=${1:-}; [ $# -gt 0 ] && shift
case "$cmd" in
install)
  SEED=${1:-}; [ -n "$SEED" ] || die "usage: vm.sh install <seed-dir>"
  [ -f "$SEED/user-data" ] && [ -f "$SEED/meta-data" ] || die "$SEED needs user-data and meta-data (agentbox seed --out)"
  [ -f "$DISK" ] && die "$DISK exists; run 'vm.sh reset' first"
  running && die "a VM is running"
  MODE=$(sed -n 3p "$SEED/user-data") DK=${DIRECT_KERNEL:-0}
  case $DK in 0|1) ;; *) die "DIRECT_KERNEL must be 0 or 1" ;; esac
  # nvme shows the model-prefixed udev ID_SERIAL that real NVMe disks have, sata the one of the old PC's SATA disk;
  # virtio hides it. SeaBIOS cannot read NVMe once q35 maps RAM above 4 GiB, which it does from 2.75 GiB of RAM.
  case $MODE in
  *boot=bios*) ARCH=amd64 CONSOLE=ttyS0 DISKBUS=${DISKBUS:-sata} T=14400 ;;
  *) ARCH=arm64 CONSOLE=ttyAMA0 DISKBUS=${DISKBUS:-nvme} T=5400 ;;
  esac
  case $ARCH/$DISKBUS in amd64/nvme) die "the BIOS VM needs DISKBUS=sata or virtio: SeaBIOS cannot read NVMe here" ;;
    arm64/sata) die "DISKBUS=sata needs a BIOS seed (q35's AHCI)" ;; esac
  case $DISKBUS in nvme) WANT="QEMU_NVMe_Ctrl_${SERIAL}_1" ;; sata) WANT="QEMU_HARDDISK_$SERIAL" ;; virtio) WANT=$SERIAL ;;
    *) die "DISKBUS must be nvme, sata or virtio" ;; esac
  /usr/bin/grep -q "serial: \"$WANT\"" "$SEED/user-data" || die "seed --disk-serial must be $WANT for DISKBUS=$DISKBUS"
  ISO="${AGENTBOX_ISO_DIR:-$VM}/ubuntu-26.04.1-live-server-$ARCH.iso"
  [ -f "$ISO" ] || die "missing $ISO"
  pinned "$ISO" || die "$ISO does not match hack/SHA256SUMS"
  case $MODE in *encryption=none*) rm -f "$VM/tpm.on" ;; *) : > "$VM/tpm.on" ;; esac
  command -v xorriso >/dev/null || die "xorriso not installed (brew install xorriso)"
  if [ "$ARCH" = arm64 ]; then
    case ${SECUREBOOT:-1} in 1) VARS=AAVMF_VARS.ms.fd ;; 0) VARS=AAVMF_VARS.fd ;; *) die "SECUREBOOT must be 0 or 1" ;; esac
    [ "$DK" = 0 ] || [ "$VARS" = AAVMF_VARS.fd ] ||
      die "DIRECT_KERNEL=1 needs SECUREBOOT=0: Secure Boot refuses a kernel that shim did not load"
    fw
    cp "$VM/fw/$VARS" "$VM/vars.fd"
  fi
  xorriso -as mkisofs -quiet -o "$VM/seed.iso" -V cidata -J -r "$SEED/user-data" "$SEED/meta-data"
  if [ "$DK" = 1 ]; then
    # The stock ISO boots without `autoinstall` on the kernel command line, and subiquity then waits for a typed "yes".
    xorriso -osirrox on -indev "$ISO" -extract /casper/vmlinuz "$VM/vmlinuz" -extract /casper/initrd "$VM/initrd" >/dev/null
    set -- -drive "if=virtio,format=raw,readonly=on,file=$(qopt "$ISO")" \
      -kernel "$VM/vmlinuz" -initrd "$VM/initrd" -append "autoinstall ds=nocloud console=$CONSOLE"
  else
    ZT="$VM/autoinstall-$ARCH.iso" # rebuilt when the stock ISO or the remaster script is newer
    { [ "$ZT" -nt "$ISO" ] && [ "$ZT" -nt "$ROOT/hack/remaster-iso.sh" ]; } ||
      "$ROOT/hack/remaster-iso.sh" "$ISO" "$ZT" "console=$CONSOLE" >/dev/null
    set -- -drive "if=none,id=iso,format=raw,readonly=on,file=$(qopt "$ZT")" -device virtio-blk-pci,drive=iso,bootindex=0
  fi
  echo "$ARCH" > "$VM/arch"
  echo "$DISKBUS" > "$VM/diskbus"
  tpm_start
  qemu-img create -q -f qcow2 "$DISK" 40G
  [ "${DUP_DISK:-0}" = 1 ] && qemu-img create -q -f qcow2 "$VM/disk2.qcow2" 40G
  : > "$VM/install.log"
  run_qemu -no-reboot "$@" -drive "if=virtio,format=raw,readonly=on,file=$(qopt "$VM/seed.iso")" -serial "file:$VM/install.log" &
  q=$!; end=$(( $(date +%s) + ${INSTALL_TIMEOUT:-$T} ))
  while kill -0 "$q" 2>/dev/null; do
    if /usr/bin/grep -aqE 'An error occurred|Continue with autoinstall' "$VM/install.log" || [ "$(date +%s)" -gt "$end" ]; then
      kill "$q" 2>/dev/null || :; die "install failed or timed out; see $VM/install.log"
    fi
    sleep 5
  done
  wait "$q" || die "qemu failed; see $VM/install.log"
  /usr/bin/grep -aq 'reboot: Restarting system' "$VM/install.log" || die "QEMU exited without the installer reboot; see $VM/install.log"
  # BOOT_IMAGE= is set by GRUB, never by -kernel
  [ "$DK" = 1 ] || /usr/bin/grep -aq 'Kernel command line: BOOT_IMAGE=/casper/vmlinuz .*autoinstall ds=nocloud' "$VM/install.log" ||
    die "the installer kernel did not come from the zero-touch ISO's GRUB; see $VM/install.log"
  echo "install ok"
  ;;
boot)
  [ -f "$DISK" ] || die "no disk; run install first"
  running && die "a VM is running"
  [ -f "$VM/arch" ] || die "no $VM/arch: this disk predates the pinned firmware; run 'vm.sh reset' and install again"
  ARCH=$(cat "$VM/arch") DISKBUS=$(cat "$VM/diskbus")
  tpm_start
  # the console log is also a socket, so a gate can type at the boot prompts (the recovery key at the LUKS prompt)
  run_qemu -chardev "socket,id=con,path=$(qopt "$VM/console.sock"),server=on,wait=off,logfile=$(qopt "$VM/boot-$(date +%Y%m%dT%H%M%S).log")" \
    -serial chardev:con
  ;;
tang)
  command -v podman >/dev/null || die "podman not installed (brew install podman && podman machine init && podman machine start)"
  case "${1:-}" in
  up)
    # Built once, keys included: they survive tang down/up and every instance serves the same ones. After editing
    # hack/tang/Containerfile, run `podman rmi agentbox-tang`.
    podman image exists agentbox-tang || podman build -q -t agentbox-tang "$ROOT/hack/tang" >/dev/null
    podman run -d --replace --name "$TANG" -p "127.0.0.1:$TANG_PORT:7500" agentbox-tang >/dev/null # loopback only
    i=0; until curl -sf "http://127.0.0.1:$TANG_PORT/adv" >/dev/null; do i=$((i+1)); [ $i -lt 20 ] || die "Tang not answering on 127.0.0.1:$TANG_PORT"; sleep 1; done
    echo "seed flags: --tang-url http://10.0.2.2:$TANG_PORT --tang-thp $(tang_thp)"
    ;;
  thp) tang_thp ;;
  down) podman rm -f "$TANG" >/dev/null ;;
  *) die "usage: vm.sh tang up|down|thp" ;;
  esac
  ;;
cut)
  # Models a disk with no volatile write cache only: writes QEMU already handed to the host survive the reset.
  printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"system_reset"}' | nc -w 2 -U "$VM/qmp.sock" >/dev/null
  ;;
ssh)
  # Every reinstall makes a new host key, so this throwaway VM never records one. IdentitiesOnly: an agent holding
  # other checkouts' VM keys would otherwise use up sshd's MaxAuthTries before .vm/id_vm is offered. ServerAlive:
  # a guest that reboots or is reset under a session never closes it, and slirp keeps the host side open.
  exec ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=6 -o IdentitiesOnly=yes -o AddKeysToAgent=no \
    -i "$VM/id_vm" -p "$SSH_PORT" "${VM_USER:-boxadmin}@127.0.0.1" "$@"
  ;;
reset)
  running && die "a VM is running"
  pkill -F "$VM/tpm/pid" -x swtpm 2>/dev/null || :
  rm -rf "$DISK" "$VM/disk2.qcow2" "$VM/vars.fd" "$VM/tpm" "$VM/tpm.on" "$VM/diskbus" "$VM/arch" "$VM/seed.iso" "$VM/vmlinuz" "$VM/initrd"
  echo "reset: removed VM disk, UEFI vars and TPM state (ISOs and firmware kept)"
  ;;
*) die "usage: vm.sh install <seed-dir> | boot | ssh [cmd] | tang up|down|thp | cut | reset" ;;
esac

#!/bin/sh
# Local QEMU test VM for agentbox (PLAN.md week 1). arm64 + HVF on Apple Silicon, UEFI.
#   hack/vm.sh install <seed-dir>   unattended install from the stock ISO; fails on installer errors or after INSTALL_TIMEOUT s
#   hack/vm.sh boot                 boot the installed disk (SSH on 127.0.0.1:2222)
#   hack/vm.sh tang up|down         Tang for tpm2+tang seeds: guest URL http://10.0.2.2:7500 (needs podman)
#   hack/vm.sh ssh [cmd]            SSH into the VM as boxadmin with the throwaway key in .vm/id_vm
#   hack/vm.sh cut                  power-cut the running VM (QMP system_reset)
#   hack/vm.sh reset                delete the VM disk, UEFI vars and TPM state
# A TPM is attached in both phases whenever the seed is encrypted. Logs go to .vm/<phase>*.log (serial console).
# Host ports listen on 127.0.0.1 only, but the guest can reach every Mac service on 127.0.0.1 through 10.0.2.2.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VM="$ROOT/.vm"
ISO="$VM/ubuntu-26.04.1-live-server-arm64.iso"
DISK="$VM/disk.qcow2"
SERIAL=QM00001
DISKBUS=${DISKBUS:-nvme} # nvme shows the model-prefixed udev ID_SERIAL that real SATA/NVMe disks have; virtio hides it
FW=/opt/homebrew/share/qemu/edk2-aarch64-code.fd
VARS_TEMPLATE=/opt/homebrew/share/qemu/edk2-arm-vars.fd
mkdir -p "$VM"

die() { echo "vm.sh: $*" >&2; exit 1; }
running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }

tpm_args() {
  [ -f "$VM/tpm.on" ] || return 0
  command -v swtpm >/dev/null || die "swtpm not installed (brew install swtpm)"
  mkdir -p "$VM/tpm"
  pkill -F "$VM/tpm/pid" -x swtpm 2>/dev/null || : # only a process that is really swtpm
  while pgrep -F "$VM/tpm/pid" -x swtpm >/dev/null 2>&1; do sleep 0.2; done
  # terminate: swtpm exits with QEMU instead of holding the state lock
  swtpm socket --tpm2 --tpmstate dir="$VM/tpm" --ctrl type=unixio,path="$VM/tpm/sock",terminate \
    --pid file="$VM/tpm/pid" --daemon
  # ppi=off: the 0x400-byte PPI RAM region is not 16 KiB aligned, and HVF refuses to map it (QEMU aborts)
  echo "-chardev socket,id=chrtpm,path=$VM/tpm/sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0,ppi=off"
}

disk_dev() {
  case "$DISKBUS" in
    nvme) echo "-device nvme,drive=d0,serial=$SERIAL" ;;
    virtio) echo "-device virtio-blk-pci,drive=d0,serial=$SERIAL" ;;
    *) die "DISKBUS must be nvme or virtio" ;;
  esac
}

common() {
  echo "-machine virt -accel hvf -cpu host -smp 4 -m 4096 -display none \
    -drive if=pflash,format=raw,readonly=on,file=$FW -drive if=pflash,format=raw,file=$VM/vars.fd \
    -drive if=none,id=d0,format=qcow2,file=$DISK $(disk_dev) \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
    -device virtio-rng-pci -device i6300esb -pidfile $VM/qemu.pid -qmp unix:$VM/qmp.sock,server=on,wait=off"
}

cmd=${1:-}; [ $# -gt 0 ] && shift
case "$cmd" in
install)
  SEED=${1:-}; [ -n "$SEED" ] || die "usage: vm.sh install <seed-dir>"
  [ -f "$SEED/user-data" ] && [ -f "$SEED/meta-data" ] || die "$SEED needs user-data and meta-data (agentbox seed --out)"
  [ -f "$ISO" ] || die "missing $ISO"
  [ -f "$DISK" ] && die "$DISK exists; run 'vm.sh reset' first"
  running && die "a VM is running"
  case $DISKBUS in nvme) WANT="QEMU_NVMe_Ctrl_${SERIAL}_1" ;; *) WANT=$SERIAL ;; esac
  /usr/bin/grep -q "serial: \"$WANT\"" "$SEED/user-data" || die "seed --disk-serial must be $WANT for DISKBUS=$DISKBUS"
  case "$(sed -n 3p "$SEED/user-data")" in
    *boot=bios*) die "BIOS seeds need an x86 VM or the old PC" ;;
    *encryption=none*) rm -f "$VM/tpm.on" ;;
    *) : > "$VM/tpm.on" ;;
  esac
  command -v xorriso >/dev/null || die "xorriso not installed (brew install xorriso)"
  xorriso -as mkisofs -quiet -o "$VM/seed.iso" -V cidata -J -r "$SEED/user-data" "$SEED/meta-data"
  # The stock ISO boots without `autoinstall` on the kernel command line, and subiquity then waits for a typed "yes":
  # boot its kernel directly with `autoinstall` so the install is unattended.
  xorriso -osirrox on -indev "$ISO" -extract /casper/vmlinuz "$VM/vmlinuz" -extract /casper/initrd "$VM/initrd" >/dev/null
  [ -f "$VM/vars.fd" ] || cp "$VARS_TEMPLATE" "$VM/vars.fd"
  echo "$DISKBUS" > "$VM/diskbus"
  TPM=$(tpm_args)
  qemu-img create -q -f qcow2 "$DISK" 40G
  : > "$VM/install.log"
  # shellcheck disable=SC2046,SC2086
  qemu-system-aarch64 $(common) $TPM -no-reboot \
    -drive if=virtio,format=raw,readonly=on,file="$ISO" -drive if=virtio,format=raw,readonly=on,file="$VM/seed.iso" \
    -kernel "$VM/vmlinuz" -initrd "$VM/initrd" -append "autoinstall ds=nocloud console=ttyAMA0" \
    -serial file:"$VM/install.log" &
  q=$!; end=$(( $(date +%s) + ${INSTALL_TIMEOUT:-5400} ))
  while kill -0 "$q" 2>/dev/null; do
    if /usr/bin/grep -aqE 'An error occurred|Continue with autoinstall' "$VM/install.log" || [ "$(date +%s)" -gt "$end" ]; then
      kill "$q" 2>/dev/null || :; die "install failed or timed out; see $VM/install.log"
    fi
    sleep 5
  done
  wait "$q" || die "qemu failed; see $VM/install.log"
  /usr/bin/grep -aq 'reboot: Restarting system' "$VM/install.log" || die "QEMU exited without the installer reboot; see $VM/install.log"
  echo "install ok"
  ;;
boot)
  [ -f "$DISK" ] || die "no disk; run install first"
  running && die "a VM is running"
  DISKBUS=$(cat "$VM/diskbus")
  TPM=$(tpm_args)
  # shellcheck disable=SC2046,SC2086
  exec qemu-system-aarch64 $(common) $TPM -serial file:"$VM/boot-$(date +%Y%m%dT%H%M%S).log"
  ;;
tang)
  command -v podman >/dev/null || die "podman not installed (brew install podman && podman machine init && podman machine start)"
  case "${1:-}" in
  up)
    mkdir -p "$VM/tang"
    podman run -d --replace --name agentbox-tang -p 127.0.0.1:7500:7500 -v "$VM/tang:/var/db/tang" ubuntu:26.04 sh -c \
      'apt-get update -qq && apt-get install -y -qq tang curl >/dev/null && { ls /var/db/tang/*.jwk >/dev/null 2>&1 || /usr/libexec/tangd-keygen /var/db/tang; } && exec /usr/libexec/tangd -l -p 7500 /var/db/tang'
    echo "seed flags: --tang-url http://10.0.2.2:7500 --tang-thp \"\$(podman exec agentbox-tang tang-show-keys 7500)\""
    ;;
  down) podman stop agentbox-tang ;;
  *) die "usage: vm.sh tang up|down" ;;
  esac
  ;;
cut)
  # Models a disk with no volatile write cache only: writes QEMU already handed to the host survive the reset.
  printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"system_reset"}' | nc -w 2 -U "$VM/qmp.sock" >/dev/null
  ;;
ssh)
  # Every reinstall makes a new host key, so this throwaway VM never records one.
  exec ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    -i "$VM/id_vm" -p 2222 "${VM_USER:-boxadmin}@127.0.0.1" "$@"
  ;;
reset)
  running && die "a VM is running"
  pkill -F "$VM/tpm/pid" -x swtpm 2>/dev/null || :
  rm -rf "$DISK" "$VM/vars.fd" "$VM/tpm" "$VM/tpm.on" "$VM/diskbus" "$VM/seed.iso" "$VM/vmlinuz" "$VM/initrd"
  echo "reset: removed VM disk, UEFI vars and TPM state (ISO kept)"
  ;;
*) die "usage: vm.sh install <seed-dir> | boot | ssh [cmd] | tang up|down | cut | reset" ;;
esac

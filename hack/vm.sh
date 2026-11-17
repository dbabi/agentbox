#!/bin/sh
# Local QEMU test VM for agentbox (PLAN.md week 1). arm64 + HVF on Apple Silicon, UEFI.
#   hack/vm.sh install <seed-dir>   unattended install from the stock ISO; fails on installer errors or after INSTALL_TIMEOUT s
#   hack/vm.sh boot                 boot the installed disk (SSH on 127.0.0.1:2222+ID)
#   hack/vm.sh tang up|down|thp     Tang for tpm2+tang seeds on 127.0.0.1:7500+ID, guest URL http://10.0.2.2:7500+ID (needs podman)
#   hack/vm.sh ssh [cmd]            SSH into the VM as boxadmin with the throwaway key in .vm/id_vm
#   hack/vm.sh cut                  power-cut the running VM (QMP system_reset)
#   hack/vm.sh reset                delete the VM disk, UEFI vars and TPM state
# AGENTBOX_VM_ID (0-9, default 0) picks the host ports and the Tang container agentbox-tang-ID. Everything else lives in
# this checkout's .vm, so VMs that run at once need distinct IDs and separate checkouts (git worktrees).
# AGENTBOX_ISO_DIR (default .vm) holds the ISO, so worktrees can share one copy.
# A TPM is attached in both phases whenever the seed is encrypted. Logs go to .vm/<phase>*.log (serial console).
# Host ports listen on 127.0.0.1 only, but the guest can reach every Mac service on 127.0.0.1 through 10.0.2.2.
set -eu
die() { echo "vm.sh: $*" >&2; exit 1; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VM="$ROOT/.vm"
ID=${AGENTBOX_VM_ID:-0}
case $ID in [0-9]) ;; *) die "AGENTBOX_VM_ID must be 0-9" ;; esac
SSH_PORT=$((2222 + ID)) TANG_PORT=$((7500 + ID)) TANG=agentbox-tang-$ID
ISO="${AGENTBOX_ISO_DIR:-$VM}/ubuntu-26.04.1-live-server-arm64.iso"
DISK="$VM/disk.qcow2"
SERIAL=QM00001
DISKBUS=${DISKBUS:-nvme} # nvme shows the model-prefixed udev ID_SERIAL that real SATA/NVMe disks have; virtio hides it
FW=/opt/homebrew/share/qemu/edk2-aarch64-code.fd
VARS_TEMPLATE=/opt/homebrew/share/qemu/edk2-arm-vars.fd
mkdir -p "$VM"

running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }
# QEMU splits key=value options (-drive file=, path=, unix:) on single commas and reads ",," as one.
# -serial file:, -pidfile, -kernel and -initrd take the path as is.
qopt() { printf '%s' "$1" | sed 's/,/,,/g'; }
tang_thp() { podman exec "$TANG" tang-show-keys 7500 | head -1; }

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

# run_qemu <phase args>: QEMU with this instance's firmware, disk, network and TPM. It execs, so after `run_qemu ... &`, $! is QEMU.
run_qemu() {
  case "$DISKBUS" in nvme) dev=nvme ;; virtio) dev=virtio-blk-pci ;; *) die "DISKBUS must be nvme or virtio" ;; esac
  if [ -f "$VM/tpm.on" ]; then
    # ppi=off: the 0x400-byte PPI RAM region is not 16 KiB aligned, and HVF refuses to map it (QEMU aborts)
    set -- -chardev "socket,id=chrtpm,path=$(qopt "$VM/tpm/sock")" -tpmdev emulator,id=tpm0,chardev=chrtpm \
      -device tpm-tis-device,tpmdev=tpm0,ppi=off "$@"
  fi
  exec qemu-system-aarch64 -machine virt -accel hvf -cpu host -smp 4 -m 4096 -display none \
    -drive "if=pflash,format=raw,readonly=on,file=$(qopt "$FW")" -drive "if=pflash,format=raw,file=$(qopt "$VM/vars.fd")" \
    -drive "if=none,id=d0,format=qcow2,file=$(qopt "$DISK")" -device "$dev,drive=d0,serial=$SERIAL" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" -device virtio-net-pci,netdev=n0 \
    -device virtio-rng-pci -device i6300esb -pidfile "$VM/qemu.pid" -qmp "unix:$(qopt "$VM/qmp.sock"),server=on,wait=off" "$@"
}

cmd=${1:-}; [ $# -gt 0 ] && shift
case "$cmd" in
install)
  SEED=${1:-}; [ -n "$SEED" ] || die "usage: vm.sh install <seed-dir>"
  [ -f "$SEED/user-data" ] && [ -f "$SEED/meta-data" ] || die "$SEED needs user-data and meta-data (agentbox seed --out)"
  [ -f "$ISO" ] || die "missing $ISO"
  [ -f "$DISK" ] && die "$DISK exists; run 'vm.sh reset' first"
  running && die "a VM is running"
  case $DISKBUS in nvme) WANT="QEMU_NVMe_Ctrl_${SERIAL}_1" ;; virtio) WANT=$SERIAL ;; *) die "DISKBUS must be nvme or virtio" ;; esac
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
  tpm_start
  qemu-img create -q -f qcow2 "$DISK" 40G
  : > "$VM/install.log"
  run_qemu -no-reboot -drive "if=virtio,format=raw,readonly=on,file=$(qopt "$ISO")" \
    -drive "if=virtio,format=raw,readonly=on,file=$(qopt "$VM/seed.iso")" \
    -kernel "$VM/vmlinuz" -initrd "$VM/initrd" -append "autoinstall ds=nocloud console=ttyAMA0" \
    -serial "file:$VM/install.log" &
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
  tpm_start
  run_qemu -serial "file:$VM/boot-$(date +%Y%m%dT%H%M%S).log"
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
  # Every reinstall makes a new host key, so this throwaway VM never records one. IdentitiesOnly: an agent that holds
  # other checkouts' VM keys would use up the server's MaxAuthTries before .vm/id_vm is offered. ServerAlive: QEMU's
  # user network keeps the host side of a session open when the guest reboots, and ssh would wait forever.
  exec ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o IdentitiesOnly=yes -o AddKeysToAgent=no \
    -i "$VM/id_vm" -p "$SSH_PORT" "${VM_USER:-boxadmin}@127.0.0.1" "$@"
  ;;
reset)
  running && die "a VM is running"
  pkill -F "$VM/tpm/pid" -x swtpm 2>/dev/null || :
  rm -rf "$DISK" "$VM/vars.fd" "$VM/tpm" "$VM/tpm.on" "$VM/diskbus" "$VM/seed.iso" "$VM/vmlinuz" "$VM/initrd"
  echo "reset: removed VM disk, UEFI vars and TPM state (ISO kept)"
  ;;
*) die "usage: vm.sh install <seed-dir> | boot | ssh [cmd] | tang up|down|thp | cut | reset" ;;
esac

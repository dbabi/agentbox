# agentbox

A headless home for AI agents on stock Ubuntu Server 26.04. Agents get full freedom inside disposable, network-less task containers. Everything that touches the host, secrets, the network, other agents or shared memory goes through typed, policy-checked, audited operations.

- **Design:** `~/workplace/ai-os-research/ARCHITECTURE.md`
- **Plan:** `~/workplace/ai-os-research/PLAN.md`
- **Threat model:** `docs/THREAT-MODEL.md`

## Status: week 1, days 1-3
| Piece | State |
|---|---|
| `agentbox recovery keygen` / `decrypt` | done: RSA-4096 key, OAEP-SHA256, proven interoperable with the installer's `openssl pkeyutl` call |
| `agentbox seed` | done: renders the autoinstall seed (`tpm2+tang`, `tpm2`, `none`; UEFI or BIOS), validates every input against subiquity 26.04.1's rules, builds a cidata ISO |
| `hack/verify-seed.py` | done: real YAML parse, structure asserts, `dash -n` on every embedded script (also run by `go test`) |
| QEMU arm64 install, `none` | **passed:** unattended install, boots `@gen-1` through `09_agentbox`, persistent subvolumes, zram, logs in `@var_log` |
| QEMU arm64 install, `tpm2` (swtpm) | **passed:** LUKS2 unlocks unattended through clevis in the dracut initramfs; `recovery.bin` decrypts to a key that opens LUKS |
| `tpm2+tang`, BIOS, old x86 PC, `os.apply` | next (needs podman for Tang; week 2 for x86) |

## Quick start (operator machine)
The install needs wired Ethernet with DHCP and HTTP access to the Ubuntu archive: archive.ubuntu.com and security.ubuntu.com
on amd64, ports.ubuntu.com on arm64. minisign, podman, crun, systemd-container, systemd-zram-generator, clevis*, clevis-dracut
and tpm2-tools are not on the ISO. The seed stops before touching any disk when the archive is unreachable, when the disk
serial matches anything but exactly one disk, or (encrypted modes) when there is no TPM2.

1. Create the recovery key pair. Keep `recovery.key` offline:
   ```sh
   go build -o bin/agentbox ./cmd/agentbox
   ./bin/agentbox recovery keygen --out ~/agentbox-keys
   ```
2. Get the target disk's udev `ID_SERIAL`. `lsblk SERIAL` is the short form and never matches SATA, NVMe or USB disks.
   Boot the target from the 26.04 ISO (stock or step 5's, with no seed attached: the installer then waits for you),
   open a shell in the installer (F2, or Help, then Enter shell), and run:
   ```sh
   udevadm info --query=property --property=ID_SERIAL --value /dev/nvme0n1   # or /dev/sda
   [ -d /sys/firmware/efi ] && echo uefi || echo bios                        # the seed's --boot
   ```
   If you skip this step, the install stops before touching any disk and logs every disk's ID_SERIAL; read them from the
   installer shell with `journalctl -b | grep 'agentbox: disk'`.
3. Generate the seed (`tpm2+tang` shown). `user-data` and `seed.iso` hold your password hash: keep them private.
   ```sh
   ./bin/agentbox seed \
     --disk-serial '<ID_SERIAL from step 2>' \
     --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" \
     --password-hash "$(openssl passwd -6)" \
     --minisign-pubkey RW... \
     --release-url https://.../agentbox.tgz \
     --encryption tpm2+tang --tang-url http://<tang LAN IPv4>:7500 --tang-thp <thumbprint> \
     --recovery-pub ~/agentbox-keys/recovery.pub \
     --out seed --iso seed.iso
   ```
4. Check it:
   ```sh
   uv run --with pyyaml python3 -I hack/verify-seed.py seed/user-data
   ```
5. Make the zero-touch USB stick: the pinned stock ISO with `autoinstall ds=nocloud` on its GRUB linux line, so subiquity
   does not wait for a typed `yes`. Write `seed.iso` to a second stick (or drive); the installer finds it by its
   `cidata` label.
   ```sh
   hack/remaster-iso.sh ubuntu-26.04.1-live-server-amd64.iso agentbox-amd64.iso   # checks the ISO against hack/SHA256SUMS
   ```
   Boot the stick once from the firmware's boot menu. Do not put USB first in the boot order: with both sticks still in,
   every boot reinstalls. (With the stock ISO instead: at its GRUB menu press `e`, add `autoinstall` before ` ---`, then
   press Ctrl-X.)
6. After the first boot, copy the encrypted recovery blob off the box and keep it next to `recovery.key`:
   ```sh
   scp boxadmin@<box>:/bootpart/agentbox/recovery.bin ~/agentbox-keys/
   ```
   To unlock by hand: `agentbox recovery decrypt --key recovery.key --in recovery.bin --out luks.key`, then type its
   48 digits at the disk passphrase prompt.

## QEMU test VM (Apple Silicon)
The seed's `--boot` picks the VM. `uefi`: arm64 under HVF with resolute's AAVMF and Secure Boot on (`SECUREBOOT=0` starts
with no keys enrolled); the disk is NVMe, so the seed needs `--disk-serial QEMU_NVMe_Ctrl_QM00001_1`. `bios`: amd64 q35
with SeaBIOS under TCG, several times slower; the disk is SATA, `--disk-serial QEMU_HARDDISK_QM00001`
(`DISKBUS=virtio` uses `QM00001` on both). `hack/vm.sh install` boots the zero-touch ISO through the firmware, as real
hardware does; `DIRECT_KERNEL=1` boots the stock ISO's kernel with `-kernel` instead (UEFI: with `SECUREBOOT=0`).
The firmware and the ISOs are pinned in `hack/SHA256SUMS`. `hack/vm.sh ssh` logs in as `boxadmin` with the throwaway key in `.vm/id_vm`. For `tpm2+tang`, run `hack/vm.sh tang up` first (needs podman); it prints the
`--tang-url` and `--tang-thp` seed flags. `hack/gate.sh tpm2 bios` runs a gate on the amd64 VM.

Several VMs can run at once, one per checkout: each needs its own `AGENTBOX_VM_ID` (0-9: SSH on 127.0.0.1:2222+ID, Tang
on 127.0.0.1:7500+ID) and its own git worktree, because everything else lives in the checkout's `.vm`.
`AGENTBOX_ISO_DIR` lets worktrees share one ISO:
```sh
git worktree add --detach ../agentbox-wt/b main
cd ../agentbox-wt/b && AGENTBOX_VM_ID=1 AGENTBOX_ISO_DIR=~/workplace/agentbox/.vm hack/gate.sh tpm2+tang
```

## Test
```sh
go vet ./... && go test ./...
```

License: Apache-2.0.

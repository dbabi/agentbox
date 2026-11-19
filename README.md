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
| Release pipeline and firstboot | done: `make release`, `install.sh`, `agentbox-reconcile.service`, `agentbox os mark-last-good`; firstboot refuses a tampered tarball, an older signed release and a wrong-key signature, and installs nothing |
| `hack/verify-seed.py` | done: real YAML parse, structure asserts, `dash -n` on every embedded script (also run by `go test`) |
| QEMU arm64 install, `none` | **passed:** unattended install, boots `@gen-1` through `09_agentbox`, persistent subvolumes, zram, logs in `@var_log` |
| QEMU arm64 install, `tpm2` (swtpm) | **passed:** LUKS2 unlocks unattended through clevis in the dracut initramfs; `recovery.bin` decrypts to a key that opens LUKS |
| `agentbox os plan` / `apply` / `health` / `mark-last-good` / `status` | week-1 `os.apply` on the box (ARCHITECTURE §3.3): closure plan with `.deb` hashes, approval by plan sha256, user-namespaced offline nspawn build, initrd gate, one-time boot, commit by the health timer, retention. Gates: `hack/apply-gate.sh none\|tpm2\|tpm2+tang` |
| `hack/remaster-iso.sh` (zero-touch USB) | done: the pinned ISO with `autoinstall ds=nocloud` on GRUB's linux line; `vm.sh install` boots it through the firmware (shim and GRUB on UEFI), with no `-kernel` |
| QEMU arm64 install, `tpm2`, Secure Boot on | **passed:** resolute's AAVMF (pinned), shim-verified boot, kernel lockdown, `mokutil --sb-state` enabled |
| QEMU amd64 BIOS install (q35, SeaBIOS, SATA, swtpm, TCG) | **passed:** `none` and `tpm2` (an install takes 60-80 min under TCG) |
| Old x86 PC | **not run:** needs its owner and the PC (see [Old-PC gate](#old-pc-gate-needs-the-owner)) |

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
   The hash must be yescrypt or sha512-crypt with `rounds=100000` or more; `openssl passwd -6` (5000 rounds) is refused.
   `mkpasswd` is in Debian/Ubuntu's `whois` package; on a Mac, run it in a container:
   `podman run --rm -it docker.io/library/ubuntu:26.04 sh -c 'apt-get update -qq && apt-get install -qq -y whois >/dev/null && mkpasswd -m yescrypt'`
   ```sh
   ./bin/agentbox seed \
     --disk-serial '<ID_SERIAL from step 2>' --boot '<uefi or bios from step 2>' \
     --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" \
     --password-hash "$(mkpasswd -m yescrypt)" \
     --minisign-pubkey RW... \
     --release-url https://.../agentbox-<ver>.tgz --release-sha256 <hash that make release printed> \
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

## Old-PC gate (needs the owner)
PLAN row 1-2 ends with "Old PC passes in week 2": the install and `os.apply` checks on the old x86 PC. The VMs run UEFI
only on arm64 and BIOS only on amd64 (`os.apply` on both: `hack/apply-gate.sh <mode> bios` on amd64), so the PC runs the
first `os.apply` on real hardware, and a UEFI PC the first amd64 UEFI install. About 1 h hands-on, plus the install.
1. Publish a release the PC can fetch: `make release VERSION=<ver> MINISIGN_KEY=<your key>`, then put
   `dist/agentbox-<ver>.tgz` and its `.minisig` side by side at one https URL with a CA-trusted certificate and no query
   string (firstboot fetches `<url>` and `<url>.minisig`; `--dev`'s plain http is for the VM only). A public host
   publishes the code: record the clearance first (PLAN "Required before writing code", LEDGER C-spec-conformance-17).
2. Install with the Quick start steps above, seeded with that URL, the `--release-sha256` that `make release` printed
   and your minisign public key. Use `--encryption tpm2` if `test -c /dev/tpmrm0` succeeds in the installer shell
   (Quick start step 2), else `none`. A placeholder release checks the install only: `os.apply` runs from the release.
3. After the first boot, from the Mac:
   ```sh
   ssh -t boxadmin@<box> 'cat /proc/cmdline; findmnt -n -o SOURCE,FSROOT /; findmnt -n -o FSROOT /boot;
     readlink /var/lib/agentbox/current; sudo grub-editenv /boot/grub/grubenv list; systemctl --failed --no-legend;
     [ -d /sys/firmware/efi ] && mokutil --sb-state || echo bios'
   ```
   Expect `BOOT_IMAGE=/agentbox/gens/gen-1/vmlinuz-...` with `rootflags=subvol=@gen-1`, root `/@gen-1` (on
   `/dev/mapper/croot` if encrypted), `/boot` at `/agentbox/gens/gen-1`, `releases/<ver>`,
   `saved_entry=agentbox-gen-1-...` and no failed units. Then do Quick start step 6: `recovery.bin` must decrypt.
4. One `os.apply` on the PC:
   ```sh
   sudo /var/lib/agentbox/current/bin/agentbox os plan --reinstall --install base-files   # prints plan sha256: <H>
   sudo /var/lib/agentbox/current/bin/agentbox os apply --approve <H>                     # reboots into the trial
   ```
   After the reboot `/proc/cmdline` must have `rootflags=subvol=@gen-2`. Within a few minutes the health timer commits
   it: `/bootpart/agentbox/committed` and `saved_entry` in `sudo grub-editenv /boot/grub/grubenv list` both read
   `agentbox-gen-2-<kernel>`. Left uncommitted, the box falls back to gen-1 after 15 min.
5. Keep the outputs of steps 3 and 4 with the evidence, and put the firmware (`uefi` or `bios`) and the
   `mokutil --sb-state` line in the status row above. On a UEFI PC, say there that this was the first amd64 UEFI run.

## Release
`make release VERSION=<ver> MINISIGN_KEY=<minisign secret key file>` builds agentbox for linux/arm64 and linux/amd64
and writes `dist/agentbox-<ver>.tgz` (the binaries, `install/install.sh`, `systemd/*`) plus its `.minisig`, then prints
the seed's `--release-sha256`. The tarball is reproducible: the same commit and Go version give the same hash.
Firstboot checks that hash before minisign, because minisign alone accepts any older signed release. Then
`install.sh --from-firstboot` installs `/var/lib/agentbox/releases/<ver>` and switches the `current` and `previous`
links by rename.

## QEMU test VM (Apple Silicon)
The seed's `--boot` picks the VM. `uefi`: arm64 under HVF with resolute's AAVMF and Secure Boot on (`SECUREBOOT=0` starts
with no keys enrolled); the disk is NVMe, so the seed needs `--disk-serial QEMU_NVMe_Ctrl_QM00001_1`. `bios`: amd64 q35
with SeaBIOS under TCG, several times slower; the disk is SATA, `--disk-serial QEMU_HARDDISK_QM00001`
(`DISKBUS=virtio` uses `QM00001` on both). `hack/vm.sh install` boots the zero-touch ISO through the firmware, as real
hardware does; `DIRECT_KERNEL=1` boots the stock ISO's kernel with `-kernel` instead (UEFI: with `SECUREBOOT=0`).
The firmware and the ISOs are pinned in `hack/SHA256SUMS`. `hack/vm.sh ssh` logs in as `boxadmin` with the throwaway key in `.vm/id_vm`. For `tpm2+tang`, run `hack/vm.sh tang up` first (needs podman); it prints the
`--tang-url` and `--tang-thp` seed flags. `hack/gate.sh tpm2 bios` runs a gate on the amd64 VM.

`hack/gate.sh` needs minisign (`brew install minisign`). It signs its test releases with a throwaway key
(`.vm/keys/minisign.key`), serves them with `hack/release-serve` on 127.0.0.1:7600+ID, and renders a `--dev` seed: only
`--dev` accepts the plain-http `http://10.0.2.2:<port>` release URL, and firstboot still checks the sha256 pin and
minisign.

Several VMs can run at once, one per checkout: each needs its own `AGENTBOX_VM_ID` (0-9: SSH on 127.0.0.1:2222+ID, Tang
on 127.0.0.1:7500+ID, releases on 127.0.0.1:7600+ID) and its own git worktree, because everything else lives in the
checkout's `.vm`.
`AGENTBOX_ISO_DIR` lets worktrees share one ISO:
```sh
git worktree add --detach ../agentbox-wt/b main
cd ../agentbox-wt/b && AGENTBOX_VM_ID=1 AGENTBOX_ISO_DIR=~/workplace/agentbox/.vm hack/gate.sh tpm2+tang
```

`hack/apply-gate.sh none|tpm2|tpm2+tang [uefi|bios] [install setup cycles breaks cuts]` runs the `os.apply` gates on the
same VM (all five scenarios take about 90 minutes on arm64); results land in `.vm/apply-gate-<mode>[-bios].txt`.

Power cuts: `hack/powercut.sh log boot` runs the VM with every disk write and flush logged (QEMU blklogwrites), and the
podman machine replays the log with xfstests `replay-log`. `hack/powercut.sh check` runs `btrfs check --readonly` at
every flush; `hack/powercut.sh boot <entry>...` boots the disk as it was after those log entries;
`hack/powercut.sh grub` reads `/bootpart` as GRUB does (no journal replay) after every entry that writes it, and fails
unless GRUB would find its entry, kernel and initrd. The script header says what this models and what it does not.

## Test
```sh
go vet ./... && go test ./...
```
`.github/workflows/ci.yml` runs the same on Linux, plus `hack/gate.sh none bios` and `hack/gate.sh tpm2 bios` under KVM,
once the repo is pushed.

License: Apache-2.0.

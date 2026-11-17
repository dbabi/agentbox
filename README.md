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
| `agentbox os plan` / `apply` / `health` / `mark-last-good` / `status` | week-1 `os.apply` on the box (ARCHITECTURE §3.3): closure plan with `.deb` hashes, approval by plan sha256, user-namespaced offline nspawn build, initrd gate, one-time boot, commit by the health timer, retention. Gates: `hack/apply-gate.sh none\|tpm2\|tpm2+tang` |
| BIOS, old x86 PC | next (week 2) |

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
   Boot the target from the 26.04 ISO, open a shell, and run:
   ```sh
   udevadm info --query=property --property=ID_SERIAL --value /dev/nvme0n1   # or /dev/sda
   ```
   If you skip this step, the install stops before touching any disk and logs every disk's ID_SERIAL; read them from the
   installer shell with `journalctl -b | grep 'agentbox: disk'`.
3. Generate the seed (`tpm2+tang` shown). `user-data` and `seed.iso` hold your password hash: keep them private.
   The hash must be yescrypt or sha512-crypt with `rounds=100000` or more; `openssl passwd -6` (5000 rounds) is refused.
   `mkpasswd` is in Debian/Ubuntu's `whois` package; on a Mac, run it in a container:
   `podman run --rm -it docker.io/library/ubuntu:26.04 sh -c 'apt-get update -qq && apt-get install -qq -y whois >/dev/null && mkpasswd -m yescrypt'`
   ```sh
   ./bin/agentbox seed \
     --disk-serial '<ID_SERIAL from step 2>' \
     --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" \
     --password-hash "$(mkpasswd -m yescrypt)" \
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
5. Boot the stock ISO with `seed.iso` attached. At the ISO's GRUB menu press `e`, add `autoinstall` before ` ---`, then
   press Ctrl-X. Without it, subiquity waits for you to type `yes`.
6. After the first boot, copy the encrypted recovery blob off the box and keep it next to `recovery.key`:
   ```sh
   scp boxadmin@<box>:/bootpart/agentbox/recovery.bin ~/agentbox-keys/
   ```
   To unlock by hand: `agentbox recovery decrypt --key recovery.key --in recovery.bin --out luks.key`, then type its
   48 digits at the disk passphrase prompt.

## QEMU test VM (Apple Silicon)
`hack/vm.sh` attaches the disk as NVMe by default, so the seed needs `--disk-serial QEMU_NVMe_Ctrl_QM00001_1`
(`DISKBUS=virtio` uses `QM00001`). `hack/vm.sh ssh` logs in as `boxadmin` with the throwaway key in `.vm/id_vm`. For `tpm2+tang`, run `hack/vm.sh tang up` first (needs podman); it prints the
`--tang-url` and `--tang-thp` seed flags.

Several VMs can run at once, one per checkout: each needs its own `AGENTBOX_VM_ID` (0-9: SSH on 127.0.0.1:2222+ID, Tang
on 127.0.0.1:7500+ID) and its own git worktree, because everything else lives in the checkout's `.vm`.
`AGENTBOX_ISO_DIR` lets worktrees share one ISO:
```sh
git worktree add --detach ../agentbox-wt/b main
cd ../agentbox-wt/b && AGENTBOX_VM_ID=1 AGENTBOX_ISO_DIR=~/workplace/agentbox/.vm hack/gate.sh tpm2+tang
```

`hack/apply-gate.sh none|tpm2|tpm2+tang [install setup cycles breaks cuts]` runs the `os.apply` gates on the same VM
(all five scenarios take about 90 minutes); results land in `.vm/apply-gate-<mode>.txt`.

## Test
```sh
go vet ./... && go test ./...
```

License: Apache-2.0.

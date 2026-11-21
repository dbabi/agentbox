This page installs agentbox on a physical machine from two USB sticks. One stick holds the zero-touch Ubuntu installer. The other holds your seed. The page covers what you need, the disk serial, a real seed, the sticks, the first boot and the checks after it. BIOS, UEFI and Secure Boot have their own sections near the end.

> **No real hardware has run agentbox yet.** Every install so far ran in a QEMU VM. agentbox is early alpha and not for production use. If you follow this page, yours may be the first real install. Expect rough edges, and please [report your result](#report-your-result).

> **Warning: the install erases one disk completely, and it does not ask first.** The seed names that disk by its udev `ID_SERIAL`. The installer deletes every partition and all data on the one disk with that serial. Check the serial twice. Back up anything you want to keep from that disk.

**The steps at a glance**

1. [Build agentbox](#step-1-build-agentbox) (operator machine)
2. [Make your keys](#step-2-make-your-keys)
3. [Build and host a release](#step-3-build-and-host-a-release)
4. [Make the installer stick](#step-4-make-the-installer-stick)
5. [Read the disk serial on the target](#step-5-read-the-disk-serial-on-the-target) (target machine)
6. [Make a password hash](#step-6-make-a-password-hash)
7. [Choose an encryption mode](#step-7-choose-an-encryption-mode)
8. [Render and check the seed](#step-8-render-and-check-the-seed)
9. [Write the seed stick](#step-9-write-the-seed-stick)
10. [Install](#step-10-install) (target machine)
11. [First boot](#step-11-first-boot)
12. [Check the box](#step-12-check-the-box)

## Before you start

What has run, at the time of writing:

| Machine | Status |
|---|---|
| arm64, UEFI, Secure Boot on | Passed in an arm64 QEMU VM: `none`, `tpm2`, `tpm2+tang` |
| arm64, UEFI, Secure Boot off | Passed in `none` mode. QEMU loaded the installer kernel directly, not from the zero-touch image. |
| amd64, legacy BIOS, SATA disk | Passed in an amd64 QEMU VM in `none` and `tpm2` modes. `tpm2+tang` has not run on amd64. |
| amd64, UEFI | No install has run. One VM probe booted the amd64 zero-touch image under UEFI (Secure Boot off) as far as the installer kernel. |
| Any physical machine | Not run |

These parts of the path have not run in any test:

- Booting from physical USB sticks. The VM tests attach the images as virtual disks. Two one-off probes booted the amd64 image as an emulated USB stick, under legacy BIOS and under UEFI, but did not install.
- A hardware TPM. The encrypted VM tests use a software TPM (swtpm).
- A real Tang server. The `tpm2+tang` tests use a throwaway Tang container.
- The first-boot download over HTTPS. The VM tests serve the release over plain `http` with `--dev`, a flag for the VM only.

Know these limits before the box joins your network:

- It runs no AI agents yet. Today agentbox is an installer, an OS layer and the first host services.
- The host firewall filters only outbound traffic from agentbox's own service users. It has no inbound rules. Put the box on a network you trust.
- The week-3 services (firewall, audit daemon, root daemon, quotas, ntfy) have passed their gates in `none` mode on arm64 UEFI only.
- Nothing updates packages by itself. An admin updates them with `os plan` and `os apply`. See [Generations and Updates](Generations-and-Updates.md).
- The agentbox release on the box cannot be updated. A new release means a reinstall.

Time: the project estimates about one hour of hands-on work, plus the install itself. No install has been timed on real hardware.

## What you need

### The target machine

| Need | Details |
|---|---|
| CPU | amd64 (x86-64) or arm64 |
| Firmware | UEFI, with Secure Boot on or off, or legacy BIOS. arm64 machines use UEFI. |
| Disk | One disk you are ready to erase. The install uses all of it. |
| TPM | A TPM 2.0 for the `tpm2` and `tpm2+tang` modes. The `none` mode needs no TPM. |
| Network | Wired Ethernet with DHCP. The seed has no Wi-Fi settings and no proxy settings. |
| Internet | HTTP access to the Ubuntu archive for the whole install. HTTPS access to your release host at first boot. |
| Screen and keyboard | For the firmware boot menu and the installer shell. The install itself needs no input. |

- The installer downloads packages from an Ubuntu mirror that it picks itself, often a country mirror such as `<country>.archive.ubuntu.com`, and from `security.ubuntu.com`. The VM tests saw this on both amd64 and arm64. Before that, the seed checks that `archive.ubuntu.com` (amd64) or `ports.ubuntu.com` (arm64) answers. A firewall must allow all of these hosts over HTTP.
- The archive must stay reachable during the whole install. Several required packages are not on the ISO: minisign, podman, crun, systemd-container, systemd-zram-generator, the clevis packages and tpm2-tools.
- The `tpm2+tang` mode also needs a Tang server on your LAN, at a private IPv4 address. It must answer during the install and at every boot.

### The operator machine (macOS or Linux)

| Tool | Used for |
|---|---|
| `git` | getting the code |
| Go 1.26 or later | building `agentbox` and `make release` |
| `make` | `make release` |
| `minisign` | signing the release |
| `xorriso` | `agentbox seed --iso` and `hack/remaster-iso.sh` |
| `openssl` and `sha256sum` | `hack/remaster-iso.sh` |
| `uv` (or `python3` with PyYAML) and `dash` | checking the seed with `hack/verify-seed.py` |
| `mkpasswd` (Debian and Ubuntu: package `whois`), or `podman` on a Mac | the admin password hash |
| `curl`, `ssh`, `scp` | the ISO download and the box login |

On a Mac with Homebrew: `brew install go xorriso minisign uv podman`. Recent macOS versions include `sha256sum`. Check with `command -v sha256sum`.

git and make come with the Xcode Command Line Tools: `xcode-select --install`.

### Other things

- Two USB sticks. The installer stick needs 4 GB or more. The seed stick can be any size. Both get erased.
- An HTTPS host for the release, with a CA-trusted certificate.
- An SSH key pair for the admin login.

### Files you will make

| File | What it is | Keep it |
|---|---|---|
| `~/agentbox-keys/recovery.key` | Decrypts `recovery.bin`, so you can unlock the disk by hand when the TPM (or Tang) cannot | Offline. If it is lost and the box can no longer unlock by itself (TPM cleared or replaced, or in `tpm2+tang` the Tang keys lost), the data is gone. |
| `~/agentbox-keys/recovery.pub` | Goes into the seed | Public, but keep it where only you can write it, at least until you render the seed. |
| `~/agentbox-keys/minisign.key` | Signs your releases | Private, with a password |
| `~/agentbox-keys/minisign.pub` | Its second line goes into the seed | Anywhere |
| `seed/user-data`, `seed.iso` | The seed. It holds your admin password hash. | Private |
| `recovery.bin` | The disk key (48 digits), encrypted to `recovery.pub`. Made by the installer. | Next to `recovery.key`. It is useless without that key. |

## Step 1: build agentbox

```sh
git clone https://github.com/dbabi/agentbox.git
cd agentbox
go build -o bin/agentbox ./cmd/agentbox
./bin/agentbox version
```

- `version` prints `dev` for a plain build.
- Run every later operator command from the top of the checkout.
- git ignores `bin/`, `dist/`, `seed/`, `*.iso` and `luks.key`, the files this page makes in the checkout.

## Step 2: make your keys

```sh
./bin/agentbox recovery keygen --out ~/agentbox-keys
minisign -G -p ~/agentbox-keys/minisign.pub -s ~/agentbox-keys/minisign.key
```

- `recovery keygen` writes `recovery.key` (an RSA-4096 private key, mode 0600) and `recovery.pub`. Only the encrypted modes use them.
- It refuses to overwrite either file. It also refuses a directory that anyone else can write.
- The seed needs only `recovery.pub`. Move `recovery.key` offline. You need it again only to unlock the disk by hand, and once after the install to test it.
- `minisign -G` asks for a password for the signing key.

## Step 3: build and host a release

At first boot, the box downloads a signed agentbox release and installs it. Build one:

```sh
make release VERSION=0.0.1 MINISIGN_KEY="$HOME/agentbox-keys/minisign.key"
```

It asks for the signing key's password. Then it prints:

```
wrote dist/agentbox-0.0.1.tgz and dist/agentbox-0.0.1.tgz.minisig
seed flags: --release-url https://<host>/<path>/agentbox-0.0.1.tgz --release-sha256 <64 hex digits>
```

- Write `"$HOME/..."` in `MINISIGN_KEY=`, not `~`. zsh and `sh` do not expand `~` after the `=` in a command argument.
- Save the 64 hex digits. The seed pins this SHA-256.
- Upload both files side by side to one HTTPS URL, with a CA-trusted certificate and no query string. Firstboot fetches `<url>` and `<url>.minisig`.
- Details: [Release Pipeline](Release-Pipeline.md).

No release host yet? Any well-formed `https://` URL and SHA-256 still let the OS install finish. Firstboot then fails and retries every 60 seconds. `os plan` and `os apply` are not available either, because the box gets its `agentbox` binary from the release.

## Step 4: make the installer stick

Download the pinned Ubuntu Server 26.04.1 ISO for the target's CPU. Then remaster it into the zero-touch image.

amd64:

```sh
curl -fLO https://releases.ubuntu.com/26.04.1/ubuntu-26.04.1-live-server-amd64.iso
hack/remaster-iso.sh ubuntu-26.04.1-live-server-amd64.iso agentbox-amd64.iso
```

arm64:

```sh
curl -fLO https://cdimage.ubuntu.com/releases/26.04.1/release/ubuntu-26.04.1-live-server-arm64.iso
hack/remaster-iso.sh ubuntu-26.04.1-live-server-arm64.iso agentbox-arm64.iso
```

- The ISO is about 2.9 GB (amd64) or 3.1 GB (arm64). The output needs about as much free space again.
- Keep the file name exactly as downloaded. `curl -O` does that. The pin in `hack/SHA256SUMS` matches by file name.
- `hack/remaster-iso.sh` checks the ISO against its pin first. It refuses an ISO that does not match.
- It adds `autoinstall ds=nocloud` to GRUB's `linux` lines, so the installer starts without asking for a typed confirmation.
- It changes only `/boot/grub/grub.cfg` and that file's line in `/md5sum.txt`. The boot setup stays as Ubuntu shipped it, Secure Boot included.
- At the end it prints the changed line. For amd64 it is `linux  /casper/vmlinuz  autoinstall ds=nocloud ---`.
- Ubuntu moves an older point release to `old-releases.ubuntu.com` once a newer one ships. If the download fails, get the same file name from `https://old-releases.ubuntu.com/releases/26.04.1/` (amd64 and arm64).

Write the image to the first stick. Use the whole device, not a partition. On arm64, use `agentbox-arm64.iso` in place of `agentbox-amd64.iso`.

> **`dd` erases the device you name, and it does not ask first.** Check the device name twice. A wrong name erases that disk.

macOS (replace `N` with the stick's number from `diskutil list external`):

```sh
diskutil list external
diskutil unmountDisk /dev/diskN
sudo dd if=agentbox-amd64.iso of=/dev/rdiskN bs=4m
diskutil eject /dev/diskN
```

`dd` prints nothing until it is done. Press Ctrl-T to see its progress.

Linux (replace `sdX` with the stick from `lsblk`; its `TRAN` column shows `usb`):

```sh
lsblk -o NAME,SIZE,TRAN,MODEL,MOUNTPOINT
sudo dd if=agentbox-amd64.iso of=/dev/sdX bs=4M conv=fsync status=progress
```

If a partition of the stick is mounted, unmount it first with `sudo umount`.

## Step 5: read the disk serial on the target

The seed names the disk to erase by its udev `ID_SERIAL`. Read it on the target machine:

1. Plug in only the installer stick. Leave the seed stick out.
2. Power on. Open the firmware's one-time boot menu, and boot the stick. Pick the entry for the mode you plan to install in, UEFI or legacy BIOS (see [BIOS or UEFI](#bios-or-uefi)).
3. With no seed, the installer starts in its normal interactive mode and waits. Do not start an install from its screens.
4. Open a shell: press F2, or open Help and choose Enter shell.
5. Run these four commands:

```sh
lsblk -d -o NAME,SIZE,MODEL,TRAN
udevadm info --query=property --property=ID_SERIAL --value /dev/nvme0n1
[ -d /sys/firmware/efi ] && echo uefi || echo bios
test -c /dev/tpmrm0 && echo tpm2 || echo no-tpm
```

6. Write down the serial, the boot mode and the TPM result. Then turn the machine off, for example with `poweroff`.

| Command | What it tells you |
|---|---|
| `lsblk` | The disks. The USB sticks show `usb` under `TRAN`. Ignore the `loop` devices. Pick the disk to erase. If it is not `nvme0n1`, put its name in the `udevadm` line, for example `/dev/sda`. |
| `udevadm` | The disk's `ID_SERIAL`, for `--disk-serial`. Copy it exactly. |
| `/sys/firmware/efi` test | `uefi` or `bios`, for `--boot` |
| `/dev/tpmrm0` test | `tpm2` if a TPM 2.0 is available. Then `tpm2` and `tpm2+tang` are possible. |

- Do not use the `SERIAL` column of `lsblk`. It is a short form and never matches.
- The `ID_SERIAL` usually includes the model name. For example, the test VM's SATA disk shows `QEMU_HARDDISK_QM00001`.
- `no-tpm`? Some PCs ship with the firmware TPM turned off. Look for TPM, PTT (Intel) or fTPM (AMD) in the firmware settings. Or install with `--encryption none`.

The installer checks the serial again before it writes anything. If no disk or more than one disk has that serial, it stops. This check runs only when a seed is attached. If a seeded install stops at the serial check in step 10, it has logged every disk's `ID_SERIAL`. Press Enter for a shell, then run:

```sh
journalctl -b | grep 'agentbox: disk'
```

## Step 6: make a password hash

The admin password works on the console and for `sudo`. SSH accepts keys only.

On Debian or Ubuntu (package `whois`):

```sh
HASH=$(mkpasswd -m yescrypt)
```

On a Mac, run `mkpasswd` in a container. If `podman machine list` already shows a machine, skip `podman machine init`. If that machine is `Currently running`, also skip `podman machine start`.

```sh
podman machine init
podman machine start
podman run --rm -it docker.io/library/ubuntu:26.04 sh -c 'apt-get update -qq && apt-get install -qq -y whois >/dev/null && mkpasswd -m yescrypt'
```

It asks for the password and prints a hash that starts with `$y$`. Store it in a shell variable. Use single quotes, because the hash contains `$` signs:

```sh
HASH='<paste the $y$ hash here>'
```

- `mkpasswd` asks once and does not confirm. Type the password carefully.
- Run step 8 in the same terminal, so `$HASH` is still set.
- The seed accepts yescrypt, or sha512-crypt with `rounds=100000` or more. It refuses `openssl passwd -6`, which uses 5000 rounds.
- Pick a strong password. Anyone who gets the seed can try to guess it offline.

## Step 7: choose an encryption mode

| Mode | Needs | Protects against | Does not protect against |
|---|---|---|---|
| `tpm2+tang` (default, recommended) | A TPM 2.0 and a Tang server on your LAN | A removed disk. Theft of the whole machine, once it is away from your LAN. | An attacker who stays on your LAN with physical access |
| `tpm2` | A TPM 2.0 | A disk removed or thrown away without its machine | Theft of the whole machine |
| `none` | Nothing | Nothing | Anyone with the disk can read all of it |

- The encrypted modes use LUKS2. At boot, clevis unlocks the disk with no input.
- The installer also writes the disk key, encrypted to your `recovery.pub`, to `/bootpart/agentbox/recovery.bin`.
- `tpm2+tang` needs both the TPM and the Tang server to unlock. If Tang is down at boot, the box waits 300 seconds at the passphrase prompt, retries, then reboots. That loop takes about 8 minutes. It repeats until Tang is back or you type the 48-digit disk key. Get the key by decrypting `recovery.bin` with `recovery.key` (step 12). If Tang comes back while the prompt waits, the box unlocks with no input.
- `--tang-url` must be `http://<private IPv4>[:port][/path]`. Hostnames, `https` and public addresses are refused: the initramfs has no DNS resolver and no CA bundle.
- `--tang-thp` is the thumbprint of Tang's signing key. On the Tang host, `tang-show-keys` prints it. If Tang does not listen on port 80, add the port, for example `tang-show-keys 7500` for the test container.
- agentbox has not tested a real Tang server. [Encryption and Recovery](Encryption-and-Recovery.md) has untested setup steps. The tests use a throwaway Tang container.
- For a first test on a spare PC, `tpm2` is the shortest encrypted path. On amd64 it is also the only encrypted mode that has run in a test. Use `none` if the PC has no TPM.

More: [Encryption and Recovery](Encryption-and-Recovery.md).

## Step 8: render and check the seed

Replace each `<...>` with your value. Keep the single quotes.

```sh
./bin/agentbox seed \
  --disk-serial '<ID_SERIAL from step 5>' \
  --boot '<uefi or bios from step 5>' \
  --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" \
  --password-hash "$HASH" \
  --minisign-pubkey "$(sed -n 2p ~/agentbox-keys/minisign.pub)" \
  --release-url 'https://<host>/<path>/agentbox-0.0.1.tgz' \
  --release-sha256 '<64 hex digits from make release>' \
  --encryption tpm2+tang \
  --tang-url 'http://<Tang server IPv4>:<port>' \
  --tang-thp '<Tang thumbprint>' \
  --recovery-pub ~/agentbox-keys/recovery.pub \
  --out seed --iso seed.iso
```

For the other modes, replace the four lines from `--encryption` to `--recovery-pub` with one line:

| Mode | Line to use |
|---|---|
| `tpm2` | `--encryption tpm2 --recovery-pub ~/agentbox-keys/recovery.pub \` |
| `none` | `--encryption none \` |

No `~/.ssh/id_ed25519.pub`? Make one with `ssh-keygen -t ed25519`.

The flags:

| Flag | Default | Rule |
|---|---|---|
| `--disk-serial` | required | The exact udev `ID_SERIAL`. Letters, digits and `._:#+=@-`, 1 to 128 characters. |
| `--boot` | `uefi` | `uefi` or `bios`. It must match how the firmware booted the installer. |
| `--ssh-key` | at least one | One OpenSSH public key line. Repeat the flag for more keys. Types: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, or `ssh-rsa` of 3072 bits or more. The key comment may use only letters, digits and `@._+-`. |
| `--password-hash` | required | yescrypt, or sha512-crypt with `rounds=100000` or more |
| `--minisign-pubkey` | required | Line 2 of `minisign.pub`: 56 characters that start with `RW` |
| `--release-url` | required | `https://host[:port]/path`, port 1 to 65535, no query string |
| `--release-sha256` | required | 64 lowercase hex digits, as `make release` printed them |
| `--encryption` | `tpm2+tang` | `tpm2+tang`, `tpm2` or `none` |
| `--tang-url`, `--tang-thp` | none | For `tpm2+tang` only, and required there |
| `--recovery-pub` | none | Required for `tpm2` and `tpm2+tang`. Refused with `none`. An RSA key of 4096 bits or more. |
| `--hostname` | `agentbox` | A lowercase RFC 1123 label |
| `--admin` | `boxadmin` | The admin user name. The seed refuses names that the Ubuntu installer reserves, such as `root` and `admin`, and names that already exist in the installed system. |
| `--out` | required | The output directory |
| `--iso` | none | Also writes the seed ISO, with the volume label `cidata`. Needs `xorriso`. Give a file path. The seed refuses a device, such as a USB stick. |

Do not use `--dev`. It is for the QEMU test VM only.

What you should see:

```
wrote seed/user-data and seed/meta-data (0600: user-data holds the admin password hash, keep it private)
wrote seed.iso (volume label cidata)
```

- `tpm2` and `none` also print a warning about what they do not protect. That is expected.
- If a flag value is invalid, the seed lists every problem at once, writes nothing and exits 1. A misspelled flag exits 2. The seed checks the `--iso` path last, after it writes `seed/`.
- A password hash in double quotes fails. The shell expands its `$` parts, and the seed refuses the result. Use `"$HASH"` from step 6, or put the hash in single quotes.

Check the seed:

```sh
uv run --with pyyaml python3 -I hack/verify-seed.py seed/user-data
```

Every line starts with `ok`. The last one is `ok   no private keys, no failure suppression`.

## Step 9: write the seed stick

Write `seed.iso` to the second stick. The `dd` warning from step 4 applies here too.

macOS (replace `M` with the seed stick's number):

```sh
diskutil list external
diskutil unmountDisk /dev/diskM
sudo dd if=seed.iso of=/dev/rdiskM bs=4m
diskutil eject /dev/diskM
```

Linux (replace `sdY` with the seed stick):

```sh
lsblk -o NAME,SIZE,TRAN,MODEL,MOUNTPOINT
sudo dd if=seed.iso of=/dev/sdY bs=4M conv=fsync status=progress
```

- The installer finds the seed by its volume label, `cidata`. Write the image to the whole stick. A stick with `seed.iso` copied onto it as a file does not work.
- This stick now holds your password hash. Keep it private, and erase it after the install.

## Step 10: install

> **Last check.** This boot erases the disk whose `ID_SERIAL` is in the seed.

1. In the firmware settings, check that USB is not first in the permanent boot order. With both sticks attached, a USB-first order reinstalls at every boot.
2. Plug both sticks into the target.
3. Power on and open the firmware's one-time boot menu. Pick the installer stick, in the same mode (UEFI or legacy) as in step 5.
4. GRUB shows the installer menu for 30 seconds. To abort, turn the machine off now.
5. The installer runs with no input. First it checks the disk serial, the archive and, in an encrypted mode, the TPM. Then it erases the disk and installs.
6. When the install is done, the installer reboots the machine. (That is what happens in the VM tests.) Remove both sticks.

The installer stops before it writes to any disk when:

- no disk, or more than one disk, has the seed's `ID_SERIAL`, or another device's `/dev/disk/by-id` name contains it;
- the Ubuntu archive does not answer (not yet tested in a VM);
- an encrypted mode finds no TPM 2.0 at `/dev/tpmrm0` (not yet tested in a VM).

After these checks, the installer erases the disk. A failure after that point leaves the disk half-installed, for example when a package download fails. Fix the cause and start again from step 10.

In `tpm2+tang` mode, Tang must answer during the install too. The installer binds the disk to Tang near the end. If it cannot reach Tang, or `--tang-thp` is wrong, the install fails after the disk is erased. (From the seed code; not tested.)

## Step 11: first boot

This happens with no input:

1. In an encrypted mode, the initramfs unlocks the disk with the TPM, or with the TPM and Tang. A disk passphrase prompt shows for a few seconds while clevis unlocks the disk. Do not type anything. A problem shows only as a prompt that stays.
2. GRUB boots generation 1 (`gen-1`) of the OS.
3. `agentbox-firstboot.service` downloads the release and its `.minisig`. It checks the SHA-256 pin first, then the minisign signature. Only then does it install the release.
4. If firstboot fails, it retries every 60 seconds, and again at every boot.

Find the box's address in your router's DHCP list. Or log in on the console as the admin user, with your password, and run:

```sh
ip -4 -br addr
```

On the console you can also print the SSH host key fingerprint. Compare it with the one `ssh` shows when you first connect:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

## Step 12: check the box

1. Log in from the operator machine. Replace `<box-ip>` with the box's address from step 11. If you changed `--admin`, use that name instead of `boxadmin`.

```sh
ssh boxadmin@<box-ip>
```

2. Check that firstboot finished:

```sh
test -e /var/lib/agentbox/.firstboot-done && echo firstboot done || echo firstboot not done
```

If it is not done, `sudo journalctl -u agentbox-firstboot` shows why. See [Troubleshooting](#troubleshooting).

3. From the operator machine, run the post-install checks in one go. `sudo` asks for your admin password.

```sh
ssh -t boxadmin@<box-ip> 'cat /proc/cmdline; findmnt -n -o SOURCE,FSROOT /; findmnt -n -o FSROOT /boot;
  readlink /var/lib/agentbox/current; sudo grub-editenv /boot/grub/grubenv list; systemctl --failed --no-legend;
  [ -d /sys/firmware/efi ] && mokutil --sb-state || echo bios'
```

| Check | What you should see |
|---|---|
| `/proc/cmdline` | `BOOT_IMAGE=/agentbox/gens/gen-1/vmlinuz-<kernel>` and `rootflags=subvol=@gen-1` |
| root file system | `<root partition>[/@gen-1] /@gen-1`. The partition is `/dev/mapper/croot` in an encrypted mode. |
| `/boot` | `/agentbox/gens/gen-1` |
| release link | `releases/<version>`, for example `releases/0.0.1` |
| GRUB environment | `saved_entry=agentbox-gen-1-<kernel>` |
| failed units | no output |
| last line | `SecureBoot enabled` or `SecureBoot disabled` on UEFI, `bios` on BIOS |

4. Check the generations. The `agentbox` binary is not on `PATH`, so use its full path:

```sh
sudo /var/lib/agentbox/current/bin/agentbox os status
```

You should see:

```
booted:      agentbox-gen-1-<kernel>
committed:   agentbox-gen-1-<kernel>
saved_entry: agentbox-gen-1-<kernel>
next_entry:  
gen-1   subvolume=true  kernels=<kernel>,<older kernel>
```

5. In an encrypted mode, copy the recovery blob off the box. Do it now, before you need it:

```sh
scp boxadmin@<box-ip>:/bootpart/agentbox/recovery.bin ~/agentbox-keys/
```

Then test it on the machine that holds `recovery.key`:

```sh
./bin/agentbox recovery decrypt --key ~/agentbox-keys/recovery.key --in ~/agentbox-keys/recovery.bin --out luks.key
wc -c < luks.key
rm luks.key
```

- `wc -c` prints `48`. The disk key is 48 digits.
- `luks.key` unlocks the disk. Delete it after the test.
- To unlock the disk by hand, see [Encryption and Recovery](Encryption-and-Recovery.md).

6. Optional: try one OS change with `os plan` and `os apply`. At the time of writing, `os apply` has passed its VM tests on arm64 UEFI. On amd64 it has passed once, in the BIOS VM, on a fix branch before that branch merged. First, make a plan:

```sh
sudo /var/lib/agentbox/current/bin/agentbox os plan --reinstall --install base-files
```

It prints each package action, each `.deb` SHA-256, and a line `plan sha256: <H>`. It installs nothing on the running system. Its `approve:` line shows a bare `agentbox`. Use the full path. Approve the plan by its hash:

```sh
sudo /var/lib/agentbox/current/bin/agentbox os apply --approve <H>
```

It builds `gen-2`, sets it up for one trial boot and reboots. Log in again and check:

```sh
cat /proc/cmdline
sudo /var/lib/agentbox/current/bin/agentbox os status
```

- `/proc/cmdline` shows `rootflags=subvol=@gen-2`.
- The health timer commits a healthy `gen-2`. In the VM tests, that took about a minute after boot. Then `os status` shows `committed:   agentbox-gen-2-<kernel>`.
- If `gen-2` stays unhealthy, the box falls back to `gen-1` by itself, about 15 minutes after the trial boot.

A trial is healthy only when all of these hold:

- `systemctl is-system-running` prints `running`.
- `/boot` is the trial's own boot directory.
- `/lib/modules/<kernel>` exists.
- At least 2 GiB are free on `/`.
- There is an IPv4 default route.

One failed unit blocks every commit. Fix anything that `systemctl --failed` lists before you try. More: [Generations and Updates](Generations-and-Updates.md).

7. Clean up. Keep `seed/`, `seed.iso` and the seed stick private, or delete them. Do not store the two sticks together: booting the box from both reinstalls it.

## Report your result

No physical machine has run agentbox yet, so every report helps. Open an issue at `https://github.com/dbabi/agentbox/issues` with:

- the CPU architecture, the firmware mode, and the `mokutil --sb-state` line;
- the encryption mode;
- the output of the step 12 checks, and of the `os apply` test if you ran it;
- if something failed: the step, and the messages from `journalctl -b | grep agentbox:` or `journalctl -u agentbox-firstboot`.

Do not post your seed, your keys or `recovery.bin`. Remove anything else you consider private.

## BIOS or UEFI

- `--boot` must match how the firmware booted the installer. Read it in the installer shell (step 5).
- agentbox does not check this for you, and no test covers a mismatch. Check it twice.
- Many boot menus list a USB stick twice, once with a `UEFI:` prefix. Pick the same kind of entry in step 5 and in step 10.
- arm64 machines use UEFI only.
- What has run: UEFI on arm64 (VM, NVMe disk) and legacy BIOS on amd64 (VM, SATA disk, `none` and `tpm2` modes). In two one-off VM probes, the amd64 zero-touch image also booted as an emulated USB stick: under legacy BIOS, and under UEFI with Secure Boot off. Neither probe ran an install.
- No amd64 UEFI install has run. On a UEFI PC, your install would be the first amd64 UEFI install.

The disk layout (GPT):

| Partition | UEFI | BIOS |
|---|---|---|
| 1 | 1 GiB EFI system partition, FAT32, at `/boot/efi` | 1 MiB `bios_grub` |
| 2 | 4 GiB ext4, at `/bootpart`, not encrypted | the same |
| 3 | The rest of the disk: btrfs, inside LUKS2 (`croot`) in the encrypted modes | the same |

Each OS generation is a btrfs subvolume (`@gen-1`, `@gen-2`, ...). `/home`, `/var/log`, `/srv` and `/var/lib/agentbox` live in their own subvolumes, so they survive a change of generation.

## Secure Boot

- Secure Boot can be on or off. In the arm64 VM, Secure Boot on passed in all three modes, with Microsoft's keys enrolled. Secure Boot off passed in `none` mode, with no keys enrolled. In that run, QEMU loaded the installer kernel directly, not from the zero-touch image.
- No amd64 UEFI install has run, with or without Secure Boot.
- The zero-touch image keeps Ubuntu's signed shim and GRUB. It changes only `grub.cfg`, which GRUB does not verify. So the stick boots with Secure Boot on.
- In the VM test with Secure Boot on, the installed box boots through shim, and `mokutil --sb-state` prints `SecureBoot enabled`.
- Ubuntu's shim is signed with Microsoft's third-party UEFI CA. Some PCs ship with that CA turned off. Then the stick does not boot while Secure Boot is on. Turn the CA on in the firmware settings, or turn Secure Boot off.
- The TPM binding uses no PCR policy, so unattended unlock does not depend on the Secure Boot state. In `tpm2` mode, Secure Boot also does not stop a thief who has the whole machine: the TPM unseals for any boot. See [Security Model](Security-Model.md).
- The seed masks `secureboot-db.service`. The box does not apply Secure Boot database updates (db and dbx) at boot, and agentbox has no command for them yet.

## Troubleshooting

The messages below come from agentbox's code and its VM tests. Real screens may look different. In the installer shell, `journalctl -b | grep agentbox:` shows agentbox's own messages.

During the install:

| What you see | What it means | What to do |
|---|---|---|
| `agentbox: --disk-serial <S> matched 0 disks, need exactly 1` | No disk has that serial. Nothing was written. | Run `journalctl -b \| grep 'agentbox: disk'` in the installer shell. Render the seed again with the right serial. |
| `agentbox: --disk-serial <S> matched 2 disks, need exactly 1` | Two disks report the same serial. Nothing was written. | Disconnect one of them. |
| `agentbox: <by-id path> also contains <S> (curtin matches by-id substrings)` | Another device's `/dev/disk/by-id` name contains your serial. Nothing was written. | Disconnect that device. |
| `agentbox: no TPM2 (/dev/tpmrm0): enable it in firmware or use --encryption=none` | No TPM 2.0 was found. Nothing was written. | Turn the TPM on in the firmware, or render a `none` seed. |
| `An error occurred. Press enter to start a shell` | A step failed. The lines above it say which one. | Press Enter. Read `journalctl -b` and the logs in `/var/log/installer/`. |
| The normal interactive installer appears | The installer found no seed. | Turn the machine off. Write `seed.iso` to the whole seed stick (step 9). Do not install from the screens. |
| `Continue with autoinstall` | You booted the stock Ubuntu ISO, not the zero-touch image. | Turn the machine off. Boot the zero-touch stick. |
| The machine installs again after the reboot | USB comes first in the boot order, and both sticks are attached. | Remove the sticks. Fix the boot order. |
| The stick does not boot with Secure Boot on | The firmware may not trust Ubuntu's shim. | See [Secure Boot](#secure-boot). |

After the install:

| What you see | What it means | What to do |
|---|---|---|
| `tpm2+tang`: a disk passphrase prompt that stays, and a reboot about every 8 minutes | Unlock needs both the TPM and Tang. Either the initramfs cannot reach Tang, or the TPM did not unseal. | If Tang is down, bring it back: the box then unlocks with no input. Otherwise type the disk key: decrypt `recovery.bin` with `recovery.key` as in step 12, and type its 48 digits. See [Encryption and Recovery](Encryption-and-Recovery.md). |
| `tpm2`: a disk passphrase prompt that stays, and a reboot about every 8 minutes | The TPM did not unlock the disk. | Type the disk key: decrypt `recovery.bin` with `recovery.key` as in step 12, and type its 48 digits. See [Encryption and Recovery](Encryption-and-Recovery.md). Not copied `recovery.bin` yet? It is on partition 2, which is not encrypted, at `agentbox/recovery.bin`. |
| `agentbox-firstboot: release sha256 <h> does not match the seed's <pin>; nothing installed` | The hosted tarball is not the one the seed pins. | Host the exact tarball that `make release` built for this seed. A different release needs a new seed and a reinstall. |
| `agentbox-firstboot: release signature does not verify with the seed's minisign key; nothing installed` | The `.minisig` does not match the seed's minisign key. | Host the `.minisig` from the same `make release` run. |
| `/var/lib/agentbox/current` does not exist | Firstboot has not succeeded yet. | Run `sudo journalctl -u agentbox-firstboot`. Firstboot retries every 60 seconds. |

## See also

- [Getting Started](Getting-Started.md): a test install in a QEMU VM, and a shorter version of this page.
- [Encryption and Recovery](Encryption-and-Recovery.md): the three modes, Tang, and unlocking the disk by hand.
- [Generations and Updates](Generations-and-Updates.md): `os plan`, `os apply` and automatic fallback.
- [Release Pipeline](Release-Pipeline.md): `make release`, hosting and firstboot.
- [Security Model](Security-Model.md): what each mode protects, and what it does not.
- [Testing and Gates](Testing-and-Gates.md): the VM tests behind every "passed" on this page.

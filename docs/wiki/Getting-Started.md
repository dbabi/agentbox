This page takes you from a fresh Apple Silicon Mac to a passing install gate in a QEMU VM. Part 2 then shows a first install on a real PC with the zero-touch USB stick.

> **Early alpha. Not for production use.** agentbox runs no AI agents yet. Today it is an installer and an OS layer: an unattended Ubuntu Server 26.04.1 install with optional disk encryption and btrfs A/B generations. It has been tested in QEMU VMs only. No real hardware has run it yet.

A *gate* is a test script. It installs agentbox in a VM, boots it, and checks the result. `hack/gate.sh none` is the shortest gate that installs a whole box. It installs with no disk encryption.

## Part 1: a passing VM gate on an Apple Silicon Mac

### What you need

- An Apple Silicon Mac with [Homebrew](https://brew.sh). The arm64 test VM uses the macOS Hypervisor framework (`-accel hvf`), so it runs only on macOS.
- About 12 GB of free disk space for the checkout's `.vm/` directory (at the time of writing).
- An internet connection. You download a 3.1 GB Ubuntu ISO. The VM installs packages from the Ubuntu archive. The first install also downloads pinned UEFI firmware from launchpad.net.
- 4 CPU cores and 4 GiB of RAM for the VM.
- Time for the gate: at the time of writing, `hack/gate.sh none` takes about 9-17 minutes.

### Step 1: install the tools

```sh
brew install go qemu xorriso minisign uv
```

| Tool | What it is for |
|---|---|
| `go`, 1.26 or later | building `agentbox`, `make release`, the unit tests |
| `qemu`, 11.0 or later | the test VM. The arm64 VM uses the `virt-11.0` machine type. `qemu-img` comes with it. |
| `xorriso` | the seed ISO and the zero-touch install ISO |
| `minisign` | signing the test releases |
| `uv` | running `hack/verify-seed.py` in step 5 |

The `none` gate needs nothing else from Homebrew. The encrypted gates also need `swtpm`, which emulates a TPM. The Tang test server and the power-cut replays need `podman`. Install both now if you plan to run those gates later:

```sh
brew install swtpm podman
```

The harness also calls `make`, `ar` and `sha256sum`:

- `make` and `ar` come with the Xcode Command Line Tools. Homebrew needs them too. `xcode-select -p` prints the tools' folder if they are installed, and an error if not. `xcode-select --install` installs them.
- Recent macOS versions include `sha256sum` in `/sbin`. Check with `command -v sha256sum`. If it prints nothing, put a `sha256sum` (for example from GNU coreutils) on your `PATH`.

### Step 2: get the code

```sh
git clone https://github.com/dbabi/agentbox.git
cd agentbox
```

Run every later command from the top of the checkout.

### Step 3: get the Ubuntu ISO and check it

The VM installs from the stock Ubuntu Server 26.04.1 arm64 ISO. The harness looks for it in `.vm/`, under its exact file name.

```sh
mkdir -p .vm
curl -fL -o .vm/ubuntu-26.04.1-live-server-arm64.iso \
  https://cdimage.ubuntu.com/releases/26.04.1/release/ubuntu-26.04.1-live-server-arm64.iso
(cd .vm && grep live-server-arm64.iso ../hack/SHA256SUMS | shasum -a 256 -c)
```

The last command prints `ubuntu-26.04.1-live-server-arm64.iso: OK`.

- `hack/SHA256SUMS` pins both Ubuntu ISOs and the VM's UEFI firmware. The ISO pins match Ubuntu's published SHA-256 sums.
- The harness checks the pin again before every install. It refuses an ISO that does not match.
- Keep the file name exactly as shown. The pins match by file name.
- Ubuntu moves an older point release to `old-releases.ubuntu.com` once a newer one ships. If the download returns 404, use `https://old-releases.ubuntu.com/releases/26.04.1/ubuntu-26.04.1-live-server-arm64.iso`. The amd64 ISO moves to the same folder.

Already have the ISO in another directory? Set `AGENTBOX_ISO_DIR` to that directory instead of copying the file. Use an absolute path. For example, with the ISO in `~/isos`:

```sh
grep live-server-arm64.iso hack/SHA256SUMS | (cd "$HOME/isos" && shasum -a 256 -c)
AGENTBOX_ISO_DIR=$HOME/isos caffeinate -i hack/gate.sh none
```

The first command is the ISO check from above, run in that directory. The second command replaces the gate command in step 6.

`.vm/` is ignored by git. The harness keeps its VM files, test keys and results there.

### Step 4: build and run the unit tests

```sh
go build -o bin/agentbox ./cmd/agentbox
./bin/agentbox version
go vet ./... && go test ./...
```

`version` prints `dev` for a plain build. `go test` prints `ok` for every package that has tests.

The gate builds `bin/agentbox` again by itself. You need it now for the dry run in step 5.

### Step 5: render a test seed (dry run, no VM)

A *seed* is the pair of autoinstall files, `user-data` and `meta-data`, that drives the unattended install. The gate renders its own seed. This dry run renders one by hand. In about a minute, it checks `minisign`, `make release`, `agentbox seed` and the seed checker before the long VM run.

```sh
mkdir -p /tmp/agentbox-try
minisign -G -W -p /tmp/agentbox-try/minisign.pub -s /tmp/agentbox-try/minisign.key
SHA=$(make -s release VERSION=0.0.1-try MINISIGN_KEY=/tmp/agentbox-try/minisign.key DIST=/tmp/agentbox-try | sed -n 's/.*--release-sha256 //p')
ssh-keygen -q -t ed25519 -N "" -C agentbox-try -f /tmp/agentbox-try/id
./bin/agentbox seed \
  --disk-serial QEMU_NVMe_Ctrl_QM00001_1 \
  --encryption none \
  --ssh-key "$(cat /tmp/agentbox-try/id.pub)" \
  --password-hash '$y$j9T$agentboxgatesalt0000$nVjZH1ZaNBH.vEdKjhLQLZVUy6bJDJKQOxEO8qRil23' \
  --minisign-pubkey "$(sed -n 2p /tmp/agentbox-try/minisign.pub)" \
  --dev --release-url http://10.0.2.2:7600/agentbox-0.0.1-try.tgz \
  --release-sha256 "$SHA" \
  --out /tmp/agentbox-try/seed
uv run --with pyyaml python3 -I hack/verify-seed.py /tmp/agentbox-try/seed/user-data
```

| Flag | Value here | What it means |
|---|---|---|
| `--disk-serial` | `QEMU_NVMe_Ctrl_QM00001_1` | The udev `ID_SERIAL` of the VM's NVMe disk. The install uses only the one disk with this exact serial. |
| `--encryption` | `none` | No disk encryption. |
| `--password-hash` | the gate's test hash | A yescrypt hash of the password `x`. For test VMs only. |
| `--minisign-pubkey` | line 2 of `minisign.pub` | Firstboot installs only a release signed by this key. |
| `--release-sha256` | what `make release` printed | Firstboot installs only the release with this SHA-256. |
| `--dev`, `--release-url` | `http://10.0.2.2:7600/...` | The VM sees the Mac as `10.0.2.2`. Only a `--dev` seed accepts a plain `http://` release URL, and only to that address. |

What you should see:

- `seed` prints `wrote /tmp/agentbox-try/seed/user-data and /tmp/agentbox-try/seed/meta-data (0600: ...)`.
- It also prints `warning: --encryption=none: anyone who takes the disk can read everything on it`. That is expected.
- `verify-seed.py` prints lines that start with `ok`. The last one is `ok   no private keys, no failure suppression`.

If an input is wrong, `seed` lists every problem at once, writes nothing, and exits 1.

To run the dry run again, delete `/tmp/agentbox-try` first. `minisign` refuses to overwrite its key, and `ssh-keygen` asks before it overwrites.

### Step 6: run the gate

```sh
caffeinate -i hack/gate.sh none
```

`caffeinate -i` keeps the Mac from idle sleep during the run. Keep the Mac on power: a battery hibernate freezes the VM. Keep the lid open. `caffeinate -i` does not stop the sleep that closing the lid starts.

The gate does this, in order:

1. Builds the binaries, throwaway keys and signed test releases. It serves the releases on `127.0.0.1:7600`.
2. Renders a `--dev` test seed into `.vm/gate-seed-none/`.
3. Resets the VM. Then it installs Ubuntu unattended from a zero-touch copy of the ISO. The VM boots it through its UEFI firmware with Secure Boot on.
4. Boots the installed box and runs the checks over SSH on `127.0.0.1:2222`.
5. Offers firstboot three bad releases, which it must refuse. Then it offers the good one.
6. Reboots, checks again, and powers the VM off.

The install step prints nothing for several minutes. To watch it, run this in a second terminal:

```sh
tail -f .vm/install.log
```

Run one gate at a time in one checkout. To run several VMs at once, see [Testing and Gates](Testing-and-Gates.md).

Two safety notes:

- The gate uses test secrets: the admin password `x` and the keys in `.vm/keys`. Never use them for a real box.
- The VM can reach every service on your Mac's `127.0.0.1` through `10.0.2.2`. Do not run untrusted code in the VM.

### Step 7: read the results

A passing run ends with this line, and `hack/gate.sh` exits 0:

```
gate none: all checks passed
```

The results are in `.vm/gate-none.txt`. Each check writes one line: `PASS <check>` or `FAIL <check>`. The two large blocks of in-VM checks each end with a `fails=N` line. The gate passes only if no line starts with `FAIL` and both blocks end with `fails=0`.

```sh
grep -c '^PASS' .vm/gate-none.txt
grep '^FAIL' .vm/gate-none.txt
```

The first command counts the passed checks. The second prints nothing on a pass.

A passing file starts like this:

```
PASS root is @gen-1
PASS booted via 09_agentbox
PASS rootflags pick @gen-1
PASS /boot is gen-1's boot dir
...
fails=0
```

The checks cover:

- the boot path through agentbox's own GRUB entries
- the btrfs subvolume layout
- masked services
- the initrd contents
- the watchdog
- logs with no password hash
- firstboot

Other files in `.vm/`:

| File | What is in it |
|---|---|
| `install.log` | The installer's serial console. |
| `boot-<time>.log` | The serial console of each boot. |
| `gate-none.log` | Output of the firstboot and `install.sh` checks. Its "does not match", "does not verify" and "already installed with different content" lines are expected. They come from the refusal tests. |
| `gate-none-journal.txt` | The box's journal for firstboot, reconcile and `multi-user.target`. |
| `gate-seed-none/` | The seed the gate rendered. |
| `release/serve.log` | The test release server's log. |

If the gate stops early:

| Message | What to do |
|---|---|
| `gate.sh: minisign not installed (brew install minisign)` | Install the tools from step 1. |
| `vm.sh: missing .../.vm/ubuntu-26.04.1-live-server-arm64.iso` | Put the ISO in `.vm/` under that exact name (step 3). |
| `vm.sh: .../ubuntu-26.04.1-live-server-arm64.iso does not match hack/SHA256SUMS` | The download is wrong or incomplete. Download it again. |
| `vm.sh: a VM is running` | An earlier VM is still up. Stop it: `pkill -F .vm/qemu.pid -f qemu-system`. |
| `vm.sh: install failed or timed out; see .../install.log` | Read the end of `.vm/install.log`. On arm64 the time limit is 5400 s. `INSTALL_TIMEOUT` changes it. |
| `gate.sh: no SSH after boot (LUKS or boot failure); see .../boot-*.log` | Read the newest `.vm/boot-*.log`. |
| `gate.sh: gate none failed; see .../gate-none.txt` | Run `grep '^FAIL' .vm/gate-none.txt` to see which check failed. |

### Step 8 (optional): look around the box

The VM disk stays in `.vm/disk.qcow2` after the gate. Boot it again and log in:

```sh
hack/vm.sh boot &
until hack/vm.sh ssh true; do sleep 5; done
hack/vm.sh ssh
```

`hack/vm.sh boot` runs QEMU, here in the background. The `until` loop waits until SSH answers. Press Ctrl-C to stop waiting. `hack/vm.sh ssh` logs in as `boxadmin` with the throwaway key `.vm/id_vm`.

Inside the VM, the sudo password is `x`:

```sh
sudo /var/lib/agentbox/current/bin/agentbox os status
sudo poweroff
```

`os status` prints the booted and committed boot entries and each generation with its kernels. The `agentbox` binary is not on `PATH` on the box, so use the full path. For `os plan` and `os apply`, see [Generations and Updates](Generations-and-Updates.md).

### Step 9: clean up

```sh
hack/vm.sh reset
rm -rf /tmp/agentbox-try
```

`hack/vm.sh reset` deletes the VM disk, the UEFI variables and the TPM state. It keeps the ISOs and the firmware. You do not download the ISO again, and the next install does not fetch the firmware again. It refuses while a VM runs. Stop the VM first: `sudo poweroff` inside it, or `pkill -F .vm/qemu.pid -f qemu-system`.

You do not have to reset between gates. Every `hack/gate.sh` run resets the VM before it installs. A reset only frees disk space.

To remove everything the harness made, including the ISO, the firmware, the throwaway keys and the results:

```sh
rm -rf .vm bin
```

## Part 2: first install on a real PC

> **No real hardware has run agentbox yet.** The zero-touch ISO has been booted only in VMs. Expect rough edges. The install erases the target disk completely.

Know this before you install on real hardware:

- There is no host firewall yet. The seed masks `nftables.service`, and the agentbox firewall is not built. Put the box on a network you trust.
- There are no automatic security updates. Nothing updates packages by itself. An admin can upgrade named packages with `os plan --install PKG`, then `os apply`. There is no upgrade-all command yet.
- The agentbox release on the box cannot be updated. A new release means a reinstall.
- amd64 UEFI has not run anywhere yet. On amd64, only legacy BIOS has run, in a VM.

### What you need

- The Mac from Part 1, with `bin/agentbox` built.
- A target PC: amd64 (UEFI or legacy BIOS) or arm64 (UEFI), with one disk you can erase.
- Wired Ethernet with DHCP. The install needs HTTP access to the Ubuntu package archive.
- A TPM 2.0 for disk encryption. Without one, use `--encryption none`.
- Two USB sticks: one of 4 GB or more for the install ISO, and one of any size for the seed.
- An HTTPS server you control, with a CA-trusted certificate. Firstboot downloads the agentbox release from it.
- `podman` on the Mac, to make a password hash (`brew install podman`).

### Step 1: make your keys (once)

```sh
./bin/agentbox recovery keygen --out ~/agentbox-keys
minisign -G -p ~/agentbox-keys/minisign.pub -s ~/agentbox-keys/minisign.key
```

- `recovery keygen` writes `recovery.key` and `recovery.pub`. The seed needs only `recovery.pub`. `recovery.key` can unlock the box's disk, so keep it offline.
- `minisign -G` asks for a password for the release signing key.

### Step 2: build and host a release

```sh
make release VERSION=0.0.1 MINISIGN_KEY="$HOME/agentbox-keys/minisign.key"
```

It asks for the signing key's password. It writes `dist/agentbox-0.0.1.tgz` and `dist/agentbox-0.0.1.tgz.minisig`. Then it prints the seed flags:

```
seed flags: --release-url https://<host>/<path>/agentbox-0.0.1.tgz --release-sha256 <64 hex digits>
```

Put both files side by side on your HTTPS server. Firstboot fetches `<url>` and `<url>.minisig`, so the signature must sit next to the tarball. The URL must not have a query string.

Write `"$HOME/..."` in `MINISIGN_KEY=`, not `~`: zsh does not expand `~` after `=` in a command argument.

No server yet? Any well-formed `https://` URL and SHA-256 still let the OS install finish. Firstboot then fails and retries every 60 seconds. `os plan` and `os apply` are not available, because the box gets its `agentbox` binary from the release.

### Step 3: make the zero-touch USB stick

```sh
mkdir -p .vm
curl -fL -o .vm/ubuntu-26.04.1-live-server-amd64.iso \
  https://releases.ubuntu.com/26.04.1/ubuntu-26.04.1-live-server-amd64.iso
hack/remaster-iso.sh .vm/ubuntu-26.04.1-live-server-amd64.iso agentbox-amd64.iso
```

`hack/remaster-iso.sh` refuses an ISO that does not match its pin. It adds `autoinstall ds=nocloud` to GRUB's `linux` lines, so the installer does not wait for a typed confirmation. It changes only `grub.cfg` and that file's line in `md5sum.txt`. The boot setup, Secure Boot included, stays as Ubuntu shipped it. It prints the changed `linux` lines.

For an arm64 machine, use the arm64 ISO from Part 1 instead: `hack/remaster-iso.sh .vm/ubuntu-26.04.1-live-server-arm64.iso agentbox-arm64.iso`.

Write the image to the first stick.

> **`dd` erases the target device without asking.** Check the disk number twice. A wrong number erases that disk.

```sh
diskutil list external
diskutil unmountDisk /dev/diskN
sudo dd if=agentbox-amd64.iso of=/dev/rdiskN bs=4m
diskutil eject /dev/diskN
```

Replace `N` with the stick's number from `diskutil list external`.

### Step 4: read the disk's ID_SERIAL

The seed names the install disk by its udev `ID_SERIAL`. Read it on the target PC:

1. Plug in only the install stick. Boot it from the firmware's one-time boot menu.
2. Without a seed, the installer starts in its normal interactive mode and waits. Do not start an install from its screens.
3. Open a shell: press F2, or open Help and choose Enter shell.
4. Run these four commands:

```sh
lsblk -d -o NAME,SIZE,MODEL,TRAN
udevadm info --query=property --property=ID_SERIAL --value /dev/nvme0n1
[ -d /sys/firmware/efi ] && echo uefi || echo bios
test -c /dev/tpmrm0 && echo tpm2 || echo no-tpm
```

- `lsblk` lists the disks. The USB sticks show `usb` under `TRAN`. Pick the disk you want to erase. If it is not `nvme0n1`, use its name in the `udevadm` line, for example `/dev/sda`.
- `udevadm` prints the `ID_SERIAL`. Copy it exactly. Do not use the `SERIAL` column of `lsblk`: it is a short form and never matches.
- The third command prints the value for `--boot`.
- The fourth command tells you if `--encryption tpm2` is possible.

Then turn the PC off.

If the serial in the seed is wrong, the install stops before it writes to any disk. It logs every disk's `ID_SERIAL`. Read them in the installer shell with `journalctl -b | grep 'agentbox: disk'`.

### Step 5: make the seed

The admin user needs a password hash for console login and sudo. SSH accepts keys only. On a Mac, run `mkpasswd` in a container. If `podman machine list` already shows a machine, skip `podman machine init`. If that machine is `Currently running`, also skip `podman machine start`.

```sh
podman machine init
podman machine start
podman run --rm -it docker.io/library/ubuntu:26.04 sh -c 'apt-get update -qq && apt-get install -qq -y whois >/dev/null && mkpasswd -m yescrypt'
```

It asks for the password and prints a hash that starts with `$y$`. On Debian or Ubuntu, run `mkpasswd -m yescrypt` directly (package `whois`). The seed refuses weak hashes, such as `openssl passwd -6` output.

Render the seed. Replace `<the $y$ hash>` with the hash from above. Replace each other `<...>` with your value from steps 2 and 4. Keep the single quotes.

```sh
./bin/agentbox seed \
  --disk-serial '<ID_SERIAL from step 4>' \
  --boot '<uefi or bios from step 4>' \
  --encryption tpm2 --recovery-pub ~/agentbox-keys/recovery.pub \
  --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" \
  --password-hash '<the $y$ hash>' \
  --minisign-pubkey "$(sed -n 2p ~/agentbox-keys/minisign.pub)" \
  --release-url '<https URL of agentbox-0.0.1.tgz>' \
  --release-sha256 '<64 hex digits from make release>' \
  --out seed --iso seed.iso
uv run --with pyyaml python3 -I hack/verify-seed.py seed/user-data
```

- No TPM: use `--encryption none` and leave out `--recovery-pub`.
- `tpm2` protects the data if someone takes the disk without the PC. It does not protect against theft of the whole machine. The seed prints a warning that says so.
- The default mode, `tpm2+tang`, also needs a Tang server on your LAN. See [Encryption and Recovery](Encryption-and-Recovery.md).
- No `~/.ssh/id_ed25519.pub`? Make one with `ssh-keygen -t ed25519`.
- `seed/user-data` and `seed.iso` hold your password hash. Keep them private. git ignores both paths.

Write `seed.iso` to the second stick, with the same `dd` warning as in step 3:

```sh
diskutil list external
diskutil unmountDisk /dev/diskM
sudo dd if=seed.iso of=/dev/rdiskM bs=4m
diskutil eject /dev/diskM
```

The installer finds the seed by its volume label, `cidata`.

### Step 6: install

1. In the firmware settings, check that USB is not first in the permanent boot order. With both sticks attached, a USB-first order reinstalls at every boot.
2. Plug both sticks into the PC.
3. Open the firmware's one-time boot menu and pick the install stick, in the same mode (UEFI or legacy) that you used in step 4.
4. GRUB shows its menu for 30 seconds. To abort, turn the PC off now.
5. The install runs with no input. It erases the disk with your `ID_SERIAL`.
6. When the installer reboots the PC, remove both sticks.

The install stops before any disk write if:

- the serial does not match exactly one disk
- the Ubuntu archive does not answer (not yet tested in a VM)
- an encrypted mode finds no TPM 2.0 (not yet tested in a VM)

### Step 7: first boot

At first boot, `agentbox-firstboot.service` downloads the release. It checks the SHA-256 pin first, then the minisign signature, and only then installs it. On failure, it retries every 60 seconds.

Find the box's IP address in your router's DHCP list, or log in on the console and run `ip -4 -br addr`. On the console, `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` prints the host key fingerprint. Compare it with the one `ssh` shows when you first connect.

In the commands below, replace `<box-ip>` with the box's address. From the Mac, log in. The other two commands run on the box:

```sh
ssh boxadmin@<box-ip>
test -e /var/lib/agentbox/.firstboot-done && echo firstboot done || echo firstboot not done
sudo /var/lib/agentbox/current/bin/agentbox os status
```

If it prints `firstboot not done`, firstboot has not succeeded yet. See why with `sudo journalctl -u agentbox-firstboot`.

In an encrypted mode, copy the encrypted recovery blob off the box. Keep it with `recovery.key`:

```sh
scp boxadmin@<box-ip>:/bootpart/agentbox/recovery.bin ~/agentbox-keys/
```

To unlock the disk by hand, see [Encryption and Recovery](Encryption-and-Recovery.md). For the full post-install checks and a first `os apply` on the PC, see [Installing on Real Hardware](Installing-on-Real-Hardware.md).

## Next steps

- [Testing and Gates](Testing-and-Gates.md): the encrypted gates, the `os apply` gates, power-cut tests, and several VMs at once.
- [Encryption and Recovery](Encryption-and-Recovery.md): the three modes, Tang, and the recovery key.
- [Generations and Updates](Generations-and-Updates.md): `os plan`, `os apply`, and automatic fallback.
- [Release Pipeline](Release-Pipeline.md): how `make release` and firstboot fit together.

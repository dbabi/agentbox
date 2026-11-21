agentbox is early alpha. Do not use it for production.
The box-side steps that have been tested ran only in QEMU virtual machines, with a software TPM.
The operator-side commands ran on macOS.
No real hardware has run agentbox yet.
Some steps on this page have never run. Each one says so.

agentbox can encrypt the box's root partition with LUKS2, the standard Linux disk encryption format.
You pick the mode when you render the seed.
In the two encrypted modes, clevis unlocks the disk at every boot, with no input.
clevis runs in the initramfs, the small system that starts before the root disk is open.
If clevis cannot unlock, an offline recovery key opens the disk by hand.

## Status

| Part | State |
|---|---|
| `tpm2`: install and unattended unlock | Built. Proven in VM gates on arm64 UEFI with Secure Boot on, and on amd64 legacy BIOS. |
| `tpm2+tang`: install, unattended unlock, Tang down, a typed recovery key, Tang back | Built. Proven in VM gates on arm64 UEFI only. |
| `recovery.bin` decrypts to 48 digits that open LUKS | Built. Proven in the `tpm2` and `tpm2+tang` gates. |
| Real hardware, a real TPM, a real Tang server, amd64 UEFI | Not tested. The gates use swtpm (a software TPM) and a throwaway Tang container. |
| A cleared TPM or a replaced mainboard | Not tested. |
| Changing the mode, the Tang server or the recovery key after the install | Not built. There is no command for it. |

## Choose a mode

| Mode | How the disk unlocks at boot | What you need |
|---|---|---|
| `tpm2+tang` (default, recommended) | clevis splits the key into two shares. The box's TPM seals one. The other needs a Tang server on your LAN. Unlock needs both. | A TPM 2.0, a Tang server, wired Ethernet with DHCP at every boot, a recovery key pair |
| `tpm2` | clevis unseals the key with the box's TPM alone. | A TPM 2.0, a recovery key pair |
| `none` | Nothing is encrypted. | Nothing |

Every mode also needs wired Ethernet with DHCP during the install, to reach the Ubuntu archive.

In the encrypted modes, the console shows a disk passphrase prompt at every boot.
clevis answers it on its own, and you type nothing.

The mode is a seed flag.
`--encryption` defaults to `tpm2+tang`.
Add one of these flag sets to your `agentbox seed` command.
[Installing on Real Hardware](Installing-on-Real-Hardware.md) shows the full command.

```text
--encryption tpm2+tang --tang-url http://<Tang IPv4>[:port] --tang-thp <thumbprint> --recovery-pub ~/agentbox-keys/recovery.pub
--encryption tpm2 --recovery-pub ~/agentbox-keys/recovery.pub
--encryption none
```

- `--tang-url` and `--tang-thp` work only with `tpm2+tang`.
- `--recovery-pub` is required for `tpm2` and `tpm2+tang`. The seed refuses it with `none`.
- With `tpm2`, the seed prints a warning: this mode protects against disk removal only.
- With `none`, it prints `warning: --encryption=none: anyone who takes the disk can read everything on it`.

### Check for a TPM first

The encrypted modes need a TPM 2.0.
Boot the box from the Ubuntu Server ISO with no seed attached.
Open a shell in the installer (F2, or Help, then Enter shell), and run:

```sh
test -c /dev/tpmrm0 && echo tpm2 || echo no-tpm
```

If it prints `no-tpm`, turn the TPM on in the firmware settings.
An encrypted install on a box with no TPM 2.0 stops before it writes to any disk.
It logs `agentbox: no TPM2 (/dev/tpmrm0): enable it in firmware or use --encryption=none`.
No gate has tested this yet.
The check is an early command, like the disk guard, and the `dup-serial` gate proves that a failing early command stops the install before any disk write.

## What each mode protects against

The repo's one-page threat model is [`docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md).
It names a thief who has the disk alone, or the whole powered-off machine.
It also lists the risks that agentbox accepts.
[Security Model](Security-Model.md) covers the rest of the threat model.

| Threat | `none` | `tpm2` | `tpm2+tang` |
|---|---|---|---|
| Someone gets the disk alone: theft, resale, recycling, a warranty return | Not protected | Protected | Protected |
| Someone takes the whole powered-off box away from your LAN | Not protected | Not protected | Protected |
| Someone with physical access boots the box on your LAN | Not protected | Not protected | Not protected |
| Someone gets root on the running box | Not protected | Not protected | Not protected |

Why:

- **The disk alone.** Both encrypted modes need the box's own TPM. Without it, the disk opens only with the recovery key.
- **The whole box, `tpm2`.** The TPM binding has no PCR policy, so the TPM unseals for any boot. A thief can boot their own system on the box and get the key. A changed initrd on the unencrypted `/bootpart` can also capture it. The threat model accepts whole-machine theft in `tpm2` mode. Its answer today is `tpm2+tang`.
- **The whole box, `tpm2+tang`.** Unlock also needs your Tang server. Away from your LAN, the box cannot reach it, so the disk stays locked. This holds only while Tang is unreachable from outside your LAN. The protection also fails if the thief takes the Tang server too.
- **Physical access on your LAN.** On your LAN, the box can reach both its TPM and Tang. Someone who boots a live USB on the box there can unlock the disk. The threat model accepts this risk for `tpm2+tang`: an attacker who stays on your LAN with physical access.
- **Root on the running box.** Encryption protects a powered-off disk. Once the disk is open, root can read the key. The threat model names two cases. A signed but malicious package in an approved `os apply` plan runs as root at the trial boot. It can read the LUKS key, and rewrite `/bootpart` and the EFI system partition. Fallback covers crashes, not hostile code. The admin account is also root-equivalent, because the installer adds it to `sudo`.

## Why there is no PCR policy

The clevis `tpm2` binding has an empty config, `{}`.
So the TPM unseals with no PCR policy.
This is on purpose. It was decided on 2026-11-16.
[FAQ](FAQ.md) has a short version.

A PCR policy makes the TPM unseal only when the boot measurements match.
agentbox does not bind PCR 7, the Secure Boot state, for three reasons:

- **It does not stop a thief.** Booting a live medium signed with the same keys, such as a stock Ubuntu USB stick, gives the same PCR 7 value.
- **It does not cover the initrd.** The initrd sits on the unencrypted `/bootpart`, and PCR 7 does not measure it.
- **It breaks unattended unlock.** PCR 7 changes when the Secure Boot databases, the revocation list (dbx) or SBAT change. That state lives in the firmware and on the one EFI system partition that all generations share. So one update would stop unattended unlock for every generation at once.

So the TPM binding alone covers a removed disk.
Only Tang covers theft of the whole box.
For `tpm2`, the threat model's upgrade path is a unified kernel image (UKI) with a signed PCR 11 policy.
It is a v2 idea: out of scope for v1, and neither designed nor built.

## Tang on your LAN

Tang is a small network service that clevis uses to unlock the disk.
In `tpm2+tang` mode, the box needs it twice:

- at install time, when clevis binds the disk;
- at every boot, when clevis unlocks the disk from the initramfs.

Tang never receives the disk key.

### What the seed accepts

| Flag | Rule |
|---|---|
| `--tang-url` | `http://<private IPv4>[:port][/path]`, port 1-65535. Private means `10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16`. The seed refuses host names, `https` and every other address. |
| `--tang-thp` | The thumbprint of the Tang server's signing key. base64url, 20 to 128 characters. |

The initramfs has no DNS resolver and no CA bundle.
That is why the URL must be plain `http://` to an IP address.
clevis pins the server by its key thumbprint instead.

### At install and at boot

During the install, clevis fetches Tang's advertisement and checks it against `--tang-thp`.
If Tang is unreachable, or the thumbprint does not match, the bind step fails.
Then the whole install fails.
This happens late in the install, so the disk is already wiped by then.
No gate tests a wrong thumbprint yet.

At boot, the kernel command line has `ip=dhcp rd.neednet=1` in this mode.
The initramfs gets an address over DHCP, then contacts Tang.
Use wired Ethernet.

### Where to run Tang

- Run it on an always-on machine on your LAN, not on the box.
- Give it a fixed address, for example with a DHCP reservation. The URL is fixed at install, and agentbox has no command to change it.
- Keep it unreachable from the internet.
- Keep it away from the box. A thief who takes both can unlock the disk.
- If the Tang server loses its keys, the box cannot unlock on its own again. Then only the recovery key opens the disk.

### Set up a Tang server

agentbox has not tested a real Tang server.
The setup steps below are untested.
agentbox ships only a throwaway Tang container for VM tests (`hack/tang`).
Do not use that container for a real box: its keys live in the container image.

One option is Ubuntu 26.04's own `tang` package.
Not tested on a real host.
These steps come from the files in that package, version 15-3ubuntu1.
On the Tang machine, run:

```sh
sudo apt install tang
sudo systemctl enable --now tangd.socket
tang-show-keys
```

- `tangd.socket` listens on TCP port 80.
- Tang creates its keys at the first request.
- `tang-show-keys` prints the thumbprint for `--tang-thp`.

With this setup, the seed flags are `--tang-url http://<Tang IPv4> --tang-thp <thumbprint>`.

## The recovery key

What the installer does:

- It makes the LUKS key: 48 random decimal digits, about 159 bits. You can type them at the disk prompt.
- The key exists only in the installer's memory, in a tmpfs file under `/run`.
- The installer encrypts it to your RSA-4096 public key, with RSA-OAEP and SHA-256. It writes the result to `/bootpart/agentbox/recovery.bin`.
- Then it shreds the tmpfs copy. The install gates check the shred step. They also check that the key is in no file under `/var/log`, `/etc`, `/bootpart` or `/boot`.
- LUKS now has two ways in: the clevis binding, and the 48 digits.

Keep your private key, `recovery.key`, off the box.
Non-negotiable 7 of the threat model says the LUKS key exists only in installer tmpfs and in `recovery.bin`, encrypted to your offline RSA key.

Good to know:

- `/bootpart` is not encrypted. Anyone with the disk can read `recovery.bin`. Only `recovery.key` decrypts it.
- Each install makes a new LUKS key. After a reinstall, copy the new `recovery.bin`.
- One key pair can serve several boxes. Each box still gets its own LUKS key.
- `none` mode has no recovery key.

### 1. Make the key pair, before the install

Run this on your operator machine, from the repo root.
[Getting Started](Getting-Started.md) shows how to build `./bin/agentbox`.

```sh
./bin/agentbox recovery keygen --out ~/agentbox-keys
```

| File | What it is | What to do with it |
|---|---|---|
| `recovery.key` | RSA-4096 private key, PKCS#8 PEM, mode 0600 | Move it offline. It unlocks the disk. |
| `recovery.pub` | The public key, PKIX PEM | Pass it to the seed. |

- keygen refuses to overwrite either file.
- It refuses a directory that other users can write.
- Store `recovery.key` offline, for example on a USB stick in a safe place. Keep a second copy somewhere else.

### 2. Put the public key in the seed

Add this flag to your `agentbox seed` command:

```text
--recovery-pub ~/agentbox-keys/recovery.pub
```

The seed accepts only an RSA key of at least 4096 bits.

### 3. Copy recovery.bin off the box, after the first boot

```sh
scp boxadmin@<box-ip>:/bootpart/agentbox/recovery.bin ~/agentbox-keys/
```

- Replace `<box-ip>` with the box's address. Use your admin name if you changed `--admin`.
- The admin user can read the file without `sudo`.
- If you skip this step, you can still read the file from the disk later. See [Unlock from rescue media](#unlock-from-rescue-media).

### 4. Decrypt recovery.bin, when you need the key

Do this on your operator machine, never on the box.
From the repo root, run:

```sh
./bin/agentbox recovery decrypt --key /path/to/recovery.key --in ~/agentbox-keys/recovery.bin --out ~/agentbox-keys/luks.key
```

- Replace `/path/to/recovery.key` with the path to your offline copy.
- `luks.key` gets the 48 digits, with no newline, mode 0600.
- The command refuses to overwrite an existing `luks.key`.

No agentbox binary at hand?
`recovery.bin` is plain RSA-OAEP with SHA-256, so OpenSSL can decrypt it too:

```sh
(umask 077 && openssl pkeyutl -decrypt -inkey /path/to/recovery.key -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in ~/agentbox-keys/recovery.bin -out ~/agentbox-keys/luks.key)
```

At the time of writing, this works with OpenSSL 4.1 and with the LibreSSL that ships with macOS.

The 48 digits open the disk.
Keep `luks.key` private, and delete it after step 5.

### 5. Type the key at the prompt

At boot, the box's console shows a prompt like this:

```text
Please enter passphrase for disk <disk name> (croot):
```

To read the digits in groups of 8, run this on your operator machine:

```sh
fold -w 8 ~/agentbox-keys/luks.key; echo
```

Then, at the box's console:

1. Type all 48 digits as one string, with no spaces.
2. Press Enter.

The boot goes on as usual.
Then delete the key file on your operator machine:

```sh
rm ~/agentbox-keys/luks.key
```

- The prompt waits 300 seconds. If it times out, the box reboots and asks again. See [When Tang is down](#when-tang-is-down).
- You need a keyboard and a screen on the box. A serial console shows the prompt only if the install stick added `console=ttyS0` (or your port) as the third argument of `hack/remaster-iso.sh`. Only the VM gates have done this.
- The prompt comes before SSH starts, so there is no remote unlock.
- The typed key unlocks this boot only. The next boot tries clevis again.
- The `tpm2+tang` gate types the key on the VM's serial console. No real machine has done this yet.

### Unlock from rescue media

Use this to reach your data from another Linux system, for example a live USB stick with `cryptsetup`.
Not tested: nobody has run these steps yet.
The gates check only that `luks.key` opens LUKS, with `cryptsetup open --test-passphrase` on the running box.

Copy `luks.key` to that system first.
Never copied `recovery.bin`? [Read it from the disk](#never-copied-recoverybin) first.

1. List the partitions:
   ```sh
   lsblk -o NAME,SIZE,FSTYPE
   ```
   On the agentbox disk, partition 2 is `ext4` (`/bootpart`). Partition 3 is `crypto_LUKS`.
2. Open partition 3. Replace `<root partition>` with its name, for example `nvme0n1p3` or `sda3`:
   ```sh
   sudo cryptsetup open --key-file luks.key /dev/<root partition> croot
   ```
3. Mount a subvolume read-only. This example mounts `@home`:
   ```sh
   sudo mount -o ro,subvol=@home /dev/mapper/croot /mnt
   ```
4. Unmount and close when you are done:
   ```sh
   sudo umount /mnt
   sudo cryptsetup close croot
   ```
5. Delete `luks.key` from that system.

Other subvolumes include `/srv` (`@srv`), `/var/lib/agentbox` (`@var_lib_agentbox`), `/var/lib/agentbox/data` (`@var_lib_agentbox_data`) and `/var/log` (`@var_log`).
Each OS generation is a subvolume named `@gen-N`.

#### Never copied recovery.bin?

Read it from partition 2, then decrypt it on your operator machine ([step 4](#4-decrypt-recoverybin-when-you-need-the-key)).
Replace `<boot partition>` with its name from step 1 above, for example `nvme0n1p2` or `sda2`:

```sh
sudo mount -o ro /dev/<boot partition> /mnt
cp /mnt/agentbox/recovery.bin .
sudo umount /mnt
```

## When Tang is down

In `tpm2+tang` mode, clevis needs both the TPM and Tang.
If Tang does not answer, every boot goes like this:

| Time after the prompt appears | What happens |
|---|---|
| 0 s | The disk prompt appears. clevis keeps trying Tang in the background. |
| 300 s | The prompt times out (`timeout=300s` in crypttab). |
| about 490 s | The initramfs (dracut) waits out `rd.retry`, 180 s by default. Then it gives up and reboots (`rd.emergency=reboot`). |
| after the reboot | A new boot starts, with a new prompt. |

One cycle takes about 8 minutes.
In the VM gates, the reboot came 487 to 493 seconds after the prompt appeared.
Nothing on the box answers the whole time: SSH does not start.

The loop ends in one of three ways:

- **Tang answers while the prompt waits.** clevis unlocks with no input and no extra reboot.
- **Tang is back by the next boot.** That boot unlocks on its own.
- **Someone types the recovery key** within the 300 seconds. See [step 5](#5-type-the-key-at-the-prompt). This unlocks the current boot only. If Tang is still down at the next boot, the loop starts again.

The `tpm2+tang` gate proves the main path.
With Tang down, the disk does not unlock, and the box reboots after the timeout.
A typed recovery key unlocks it.
Once Tang is back, clevis unlocks it with no input.
In the gate, Tang comes back right after a prompt appears.

## When the TPM is cleared or the mainboard is replaced

No gate covers this. Treat it as untested.

Both encrypted modes need the box's TPM.
If the TPM is cleared, or the box gets a new mainboard, clevis cannot unlock.
In `tpm2+tang`, the Tang share alone is not enough.
The box then loops as in [When Tang is down](#when-tang-is-down).

The design's plan is to unlock with the recovery key, then re-bind clevis with `clevis luks regen`.
agentbox has no command or test for this yet.

## If you lose recovery.key

- The box keeps working while clevis can unlock it.
- If clevis can no longer unlock and `recovery.key` is gone, the data is gone too.
- agentbox has no command to give an installed box a new recovery key. A new key pair takes effect only at the next install, and an install wipes the disk.

To get a recovery key again: copy your data off the box, make a new key pair, and reinstall.

## Test it in a VM

On an Apple Silicon Mac, one gate runs the whole flow.
It covers the install, unattended unlock, Tang down, a typed recovery key, and Tang back.

```sh
hack/gate.sh tpm2+tang
```

At the time of writing, it takes about 20 minutes (18-24 in the recorded runs).
[Testing and Gates](Testing-and-Gates.md) lists what it needs and what each check means.

## See also

- [`docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md): the one-page threat model.
- [Security Model](Security-Model.md): the threat model in more depth.
- [Installing on Real Hardware](Installing-on-Real-Hardware.md): the full seed command and the zero-touch install.
- [FAQ](FAQ.md): the short answer to "Why no PCR 7?".

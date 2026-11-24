# Generations and Updates

agentbox keeps the operating system in numbered generations.
A package change never changes the running generation.
It is built offline into a new generation, booted once as a trial, and kept only if the box comes up healthy.
If the trial does not boot, or does not pass the health check within 15 minutes, the box goes back to the committed generation on its own.
Nobody has to type anything at the console.

> **Status:** built, and tested in QEMU virtual machines only: arm64 UEFI with Secure Boot on, plus one passing amd64 BIOS run (cycles and breaks, no power cuts) on a development branch before it merged, at the time of writing.
> No real hardware has run it yet.
> agentbox is early alpha. Do not use it in production.

On this page:

- [In short](#in-short)
- [Words used on this page](#words-used-on-this-page)
- [Where generations live](#where-generations-live)
- [How GRUB boots a generation](#how-grub-boots-a-generation)
- [Change packages](#change-packages)
- [Unattended fallback](#unattended-fallback)
- [Retention](#retention)
- [Check the state](#check-the-state)
- [Power-cut safety](#power-cut-safety)
- [Not built yet](#not-built-yet)
- [Command reference](#command-reference)

## In short

1. `os plan` works out a package change and downloads it. Nothing changes yet.
2. You read the plan and approve it by its SHA-256 with `os apply`.
3. `os apply` builds a new generation offline and sets it to boot once. Then it reboots.
4. On that boot, the health check commits the new generation if the box is healthy. It has 15 minutes.
5. If the trial fails to boot or stays unhealthy, the box boots the last committed generation again.

A low-risk first test: re-install one package at its current version, or upgrade it if a newer version exists.

```sh
sudo /var/lib/agentbox/current/bin/agentbox os plan --reinstall --install base-files
# read the plan, then approve the hash on its "plan sha256:" line
sudo /var/lib/agentbox/current/bin/agentbox os apply --approve <plan-sha256>
# the box reboots into the trial; about a minute after it is up:
sudo /var/lib/agentbox/current/bin/agentbox os status
```

After the commit, `booted`, `committed` and `saved_entry` all name the new generation.

## Words used on this page

| Word | Meaning |
|---|---|
| generation | One OS root, the btrfs subvolume `@gen-N`, plus its own boot directory `/bootpart/agentbox/gens/gen-N/`. Generation 1 is the install. |
| entry | One GRUB menu entry: one generation with one kernel. Its id is `agentbox-gen-N-<kernel>`. |
| committed | The entry the box boots by default. Its id is in `/bootpart/agentbox/committed` and in GRUB's `saved_entry`. |
| plan | A resolved package change, tied to the generation it was made on. You approve it by its SHA-256. |
| trial | The first boot of a new generation. It happens once. |
| fallback | Booting the committed entry again after a trial fails. |

## Where generations live

The root file system is btrfs, inside LUKS2 in the encrypted modes.
Its top level holds only subvolumes whose names start with `@`:

```
@gen-1, @gen-2, ...      one OS root per generation: /, /etc, /usr, /var/lib/dpkg, ...
@home                    /home
@var_log                 /var/log
@var_lib_agentbox        /var/lib/agentbox
@var_lib_agentbox_data   /var/lib/agentbox/data
@var_lib_tailscale       /var/lib/tailscale
@var_lib_ntfy            /var/lib/ntfy
@srv                     /srv
@snapshots               /.snapshots
```

Everything outside `@gen-N` persists across generations.
ntfy is installed from its Ubuntu package (milestone 2) and keeps its state in `@var_lib_ntfy`. Tailscale is not installed yet; its subvolume is reserved for later.

Kernels and GRUB's files live on a separate 4 GiB ext4 partition, mounted at `/bootpart`.
It is not encrypted. GRUB reads it directly.

```
/bootpart/grub/                   GRUB's files, including grub.cfg and grubenv; shared by every generation (bound at /boot/grub)
/bootpart/agentbox/gens/gen-N/    kernels and initrds of generation N (bound at /boot)
/bootpart/agentbox/committed      the committed entry id
/bootpart/agentbox/recovery.bin   the LUKS key, encrypted to your recovery public key (encrypted modes only)
```

Each generation's `/etc/fstab` binds its own boot directory at `/boot`:

```
/bootpart/agentbox/gens/gen-N /boot none bind,x-systemd.requires-mounts-for=/bootpart 0 0
/bootpart/grub /boot/grub none bind,x-systemd.requires-mounts-for=/boot 0 0
```

So a kernel update in a new generation writes only to that generation's boot directory.
Older generations keep the kernels and initrds they booted with.
On UEFI, the EFI system partition is mounted at `/boot/efi`. It is shared too.

The kernel command line picks the generation with `rootflags=subvol=@gen-N`.
To see which generation runs:

```sh
cat /proc/cmdline            # has rootflags=subvol=@gen-N
findmnt -n -o FSROOT /       # prints /@gen-N
findmnt -n -o FSROOT /boot   # prints /agentbox/gens/gen-N
```

## How GRUB boots a generation

### The 09_agentbox script

`/etc/grub.d/09_agentbox` is a `grub-mkconfig` script.
The installer puts it in generation 1, and every later generation inherits it.
It runs before Ubuntu's `10_linux`, so its entries come first in the menu.

- It writes one entry per generation and kernel. The title is `agentbox gen-N <kernel>`. The id is `agentbox-gen-N-<kernel>`.
- Generations come oldest first. Inside a generation, kernels come newest first.
- An entry needs both `vmlinuz-<kernel>` and `initrd.img-<kernel>`. A kernel name with any character outside `[0-9A-Za-z.+~_-]` is skipped.
- Each entry boots `root=UUID=<btrfs uuid> ro`, then the GRUB command line, then `rd.luks.uuid=<uuid>` in the encrypted modes, then `rootflags=subvol=@gen-N`.

Two extra kinds of line make fallback work with no input:

- After each entry: on a one-time boot, if `saved_entry` names this entry, GRUB's `fallback` is set to its position. GRUB's `fallback` takes only numbers, so the script counts the entries.
- At the end: if this is not a one-time boot and `saved_entry` is empty, the default is the committed entry. The script reads its id from `/bootpart/agentbox/committed` each time `grub.cfg` is made.

The generated part of `grub.cfg` looks like this. Values in angle brackets vary, and the second entry is shortened:

```
menuentry 'agentbox gen-1 <kernel>' --id 'agentbox-gen-1-<kernel>' {
 insmod part_gpt
 insmod ext2
 insmod gzio
 search --no-floppy --fs-uuid --set=root <bootpart uuid>
 linux /agentbox/gens/gen-1/vmlinuz-<kernel> root=UUID=<btrfs uuid> ro <kernel args> rootflags=subvol=@gen-1
 initrd /agentbox/gens/gen-1/initrd.img-<kernel>
}
if [ -n "${boot_once}" ]; then if [ "${saved_entry}" = "agentbox-gen-1-<kernel>" ]; then set fallback=0; fi; fi
menuentry 'agentbox gen-2 <kernel>' --id 'agentbox-gen-2-<kernel>' {
 ...
}
if [ -n "${boot_once}" ]; then if [ "${saved_entry}" = "agentbox-gen-2-<kernel>" ]; then set fallback=1; fi; fi
if [ -z "${boot_once}" ]; then if [ -z "${saved_entry}" ]; then set default="agentbox-gen-2-<kernel>"; fi; fi
```

`<kernel args>` includes `panic=10 rd.emergency=reboot rd.shell=0 rd.timeout=600`, plus `ip=dhcp rd.neednet=1` in `tpm2+tang` mode and `rd.luks.uuid=<uuid>` in the encrypted modes.
The menu also shows Ubuntu's stock entries after agentbox's. agentbox does not use them.

### What GRUB boots

agentbox uses two values in `/bootpart/grub/grubenv`: `next_entry` and `saved_entry`.
The seed sets `GRUB_DEFAULT=saved`.

| State | GRUB boots |
|---|---|
| `next_entry` is set | That entry, once. GRUB clears `next_entry` before it boots. |
| `saved_entry` is set | That entry, normally the committed one. |
| `grubenv` is empty or lost | The committed entry, through the last line of 09_agentbox. |
| `saved_entry` names no entry in `grub.cfg` | Entry 0: the oldest generation's newest kernel, never the newest trial. |

To see the values:

```sh
sudo grub-editenv /boot/grub/grubenv list
cat /bootpart/agentbox/committed
```

## Change packages

All `os` commands run on the box, as root.
The `agentbox` binary is at `/var/lib/agentbox/current/bin/agentbox`. It is not on `PATH`.
Firstboot installs it from the agentbox release. Until firstboot succeeds, there is no `os` command and no health timer.

### Step 1: make a plan

```sh
sudo /var/lib/agentbox/current/bin/agentbox os plan --install <package>
sudo /var/lib/agentbox/current/bin/agentbox os plan --install <package>=<version> --remove <other-package>
sudo /var/lib/agentbox/current/bin/agentbox os plan --reinstall --install base-files
```

| Flag | Meaning |
|---|---|
| `--install PKG` or `--install PKG=VER` | Install or upgrade a package. Repeatable. |
| `--remove PKG` | Remove a package. Repeatable. Plans never purge. |
| `--reinstall` | Also re-install named packages that are already at that version. |

Give at least one `--install` or `--remove`.

What `os plan` does:

1. It copies the running generation's apt setup and dpkg state into a work directory. apt's hooks are turned off.
2. It runs `apt-get update` and a dry run, `apt-get -s install`, against that copy.
3. It downloads every `.deb` into the work directory. Each file must match the size and hash in apt's signed index. Once the plan is complete, the work directory becomes the plan's directory, `/var/lib/agentbox/cas/debs/<plan-sha256>/`, with the files in its `debs/` subdirectory.
4. It writes `plan.json`: the base generation, the SHA-256 of its dpkg status, the request, every action, every `.deb` with its SHA-256, and the end state (every installed `package:arch=version`).
5. It prints the plan.

`os plan` installs nothing and changes nothing in the running generation.
It needs the network to reach the Ubuntu archive. The build in step 2 does not.

Example output. Hashes are shortened here; the real output prints all 64 hex digits. Versions will differ.

```
base: gen-1, dpkg status sha256 aa9d42cb...
  Inst base-files 14ubuntu6.2 -> 14ubuntu6.3 [arm64] ("Ubuntu:26.04/resolute-updates")
  Inst motd-news-config 14ubuntu6.2 -> 14ubuntu6.3 [all] ("Ubuntu:26.04/resolute-updates")
debs: 2 files, 80148 bytes, in /var/lib/agentbox/cas/debs/41515a95...
  8d9fa0c4...  base-files_14ubuntu6.3_arm64.deb
  8c21e5cf...  motd-news-config_14ubuntu6.3_all.deb
end state: 775 installed packages
plan sha256: 41515a95...
approve: agentbox os apply --approve 41515a95...
```

A new package's line ends in `new`. A removal reads `Remv <package> <installed version>`.
The `approve:` line prints a bare `agentbox`. On the box, use the full path.

Errors you may see. Each one starts with `agentbox: `.

| Message | Meaning |
|---|---|
| `os plan: give at least one --install or --remove` | No package was named. |
| `plan: nothing to install or remove` | apt found nothing to change, for example because the package is already at its newest version. Add `--reinstall` to install it again. |
| `plan: "<arg>" is not a package, pkg=version or pkg-` | A package name is malformed. |

### Step 2: approve and apply

Read the whole plan first.
Its SHA-256 covers the base, every action, every `.deb` hash and the end state.
Approving means passing that hash to `os apply`:

```sh
sudo /var/lib/agentbox/current/bin/agentbox os apply --approve <plan-sha256>
```

`os apply` builds the new generation, sets it up for one trial boot, then reboots.
Add `--no-reboot` to skip the reboot. The trial then waits for the next boot, whatever causes it.

Before the clone, `os apply` checks `plan.json` and every `.deb` against their hashes again.
It prints one progress line per step:

| Progress line | What happens |
|---|---|
| `os: base check` | The booted entry must be the committed one. Its generation and dpkg status must match the plan, or the build stops with `stale_base`. |
| `os: prune gen-N` | Retention runs first. Failed trials and interrupted builds are deleted. |
| `os: clone gen-CUR -> gen-M` | The running generation's subvolume is snapshotted to `@gen-M`. Its boot directory is copied to `gens/gen-M/`. |
| `os: fstab: /boot -> ...` | The new generation's `/boot` line is pointed at its own boot directory. Exactly one line must match. |
| `os: nspawn: apt-get -s` | Inside a `systemd-nspawn` container, apt's dry run must match the approved actions. |
| `os: nspawn: apt-get install` | apt installs the approved `.deb` files, checked again by SHA-256. The container has no network and a fixed private user-ID range. It sees the new generation's root and boot directory; the `.deb` files and package lists are read-only. Service starts are blocked, and `update-grub` and `grub-install` are diverted to no-ops. |
| `os: scaffolding check` | Those blockers must be gone. The installed packages must equal the plan's end state. |
| `os: name check` | Every file name in the new boot directory must match `[0-9A-Za-z.+~_-]`. |
| `os: initrd gate` | Every kernel's initrd must hold `btrfs.ko` and the disk and watchdog drivers recorded at install. The encrypted modes also need the `croot` line in `etc/crypttab`, `clevis-luks-askpass` and `systemd-cryptsetup`. `tpm2+tang` also needs `clevis-decrypt-tang`. |
| `os: update-grub` | `grub.cfg` is regenerated and must list the new entry. |
| `os: boot once: <entry>` | Everything is flushed to disk, the pending trial is recorded, and `next_entry` is set. |

The trial boots the newest kernel in the new generation.
If any step after the clone fails, the build is discarded: its subvolume and boot directory are deleted, and the running generation is unchanged.
The command then prints `agentbox: ALERT: build gen-M discarded: <reason>`.
One exception: if setting `next_entry` fails after the write may have landed, the trial stays pending instead. See the last row of the error table below.

Example from a test run. apt's output is left out. The numbers jump from 12 to 18 because earlier test trials failed.

```
os: base check
os: prune gen-17
os: clone gen-12 -> gen-18
os: fstab: /boot -> /bootpart/agentbox/gens/gen-18
os: nspawn: apt-get -s
os: nspawn: apt-get install
(apt and dpkg output)
os: scaffolding check
os: name check
os: initrd gate
os: update-grub
os: boot once: agentbox-gen-18-<kernel>
built gen-18: the next boot tries agentbox-gen-18-<kernel> once; health commits it, anything else falls back
```

Errors you may see. Each one starts with `agentbox: `.

| Message | What to do |
|---|---|
| `os apply: --approve needs the plan's sha256 (64 hex digits)` | Pass the full hash from the `plan sha256:` line. |
| `no plan <sha256>: ...` | This box has no plan with that hash. Run `os plan`. |
| `busy: an os.apply trial is pending (<entry>)` | One trial at a time. Reboot into the pending trial. It commits or falls back. |
| `booted <entry> is not the committed generation (...)` | The box is not running its committed entry. Reboot into it first. |
| `stale_base: the plan is for gen-N with dpkg status ..., the box runs gen-CUR with ...` | Packages or the running generation changed since the plan. Make a new plan. |
| `ALERT: retention refused: kept gen-K's fstab still binds /bootpart/agentbox/gens/gen-D` | A kept generation's fstab still mounts a boot directory that retention would delete. Nothing was deleted. Remove the extra line that mounts that boot directory. If gen-K is the running generation, its fstab is `/etc/fstab`. For any other generation, its fstab is `etc/fstab` inside the `@gen-K` subvolume, which is not mounted on the box. Do not delete a `/boot` line: it must point at gen-K's own boot directory, `/bootpart/agentbox/gens/gen-K`. Then run `os apply` again. |
| `... <entry> stays pending: the next boot tries it once or falls back` | Setting `next_entry` failed after the new value may have reached the disk. The trial stays pending. |

`os apply` and `os mark-last-good` wait while another `os` command holds the lock.

### Step 3: the trial boot

GRUB finds `next_entry`, clears it, and boots the trial. This is the only boot that tries the trial.

- If the trial fails inside GRUB, for example because its kernel file is missing, GRUB's `fallback` boots the committed entry in the same boot.
- Once the kernel starts, `next_entry` is already gone. Any reboot from then on boots the committed entry.

### Step 4: health check and commit

`agentbox-health.timer` runs `agentbox os health` 1 minute after boot, then every 50 seconds.
On the trial, it checks five things:

| Check | Passes when |
|---|---|
| System state | `systemctl is-system-running` prints `running`: boot finished and no unit failed. |
| `/boot` | `/boot` is the booted generation's own boot directory. |
| Kernel modules | `/lib/modules/$(uname -r)` exists. |
| Free space | At least 2 GiB is free on `/`. |
| Network | There is an IPv4 default route. |

The first run that passes every check commits the trial. In the test gates, that came about a minute after boot.
The commit does this, in order:

1. It sets `saved_entry` to the trial, then reads `grubenv` back to confirm it.
2. It writes the trial's id to `/bootpart/agentbox/committed`.
3. It regenerates `grub.cfg`, so the empty-`grubenv` fallback names the new generation.
4. It clears the pending record.
5. It applies [retention](#retention).

The journal shows `os: committed agentbox-gen-M-<kernel>`, then one `os: prune gen-N` line per deleted generation.

If a check fails, health logs the problem and tries again a minute later:

```
agentbox: health: system is starting, not running (boot unfinished or a unit failed)
agentbox: health: trial agentbox-gen-17-<kernel> not committed yet; the boot deadline falls back unless it gets healthy
```

On the committed generation, health only alerts: `agentbox: ALERT: the committed generation is unhealthy (see above)`.
It also regenerates `grub.cfg` if it lists an entry whose kernel or initrd is gone.

These checks are a first version. Before them, `agentbox-health.service` runs `agentbox fwcheck --repair`, which restores an altered firewall table. Checks for agentbox services, DNS and Tailscale are designed, not built.

### What the new generation carries

- The new generation starts as a snapshot of the running one, taken when `os apply` runs.
- Edits to `/etc` made after `os apply` stay in the old generation only. The new generation does not have them.
- Running `apt` by hand changes the running generation in place, outside A/B. It also changes the dpkg status, so a plan made before it fails with `stale_base`. Use `os plan` and `os apply` instead.
- The seed masks apt's daily timers and snapd, because they would change the OS in place.

## Unattended fallback

No path back needs console input.

| What fails | What brings the box back | Time in the arm64 QEMU gates |
|---|---|---|
| The trial fails inside GRUB, for example a missing kernel | GRUB's `fallback` boots the committed entry in the same boot. | under 1 minute |
| The kernel panics | `panic=10` reboots after 10 s. `next_entry` is already used up, so the committed entry boots. | not measured |
| The disk cannot unlock, for example clevis missing from the initrd | The LUKS prompt gives up after 300 s, dracut retries, then `rd.emergency=reboot` reboots. | about 9 minutes |
| The initrd cannot find root, for example btrfs missing from the initrd | The initrd gives up after `rd.timeout=600` and reboots. | about 10.5 minutes |
| A mount fails and systemd enters emergency mode | The emergency shell reboots after 120 s. | about 4 minutes |
| The trial boots but never gets healthy, or a unit blocks boot forever | The commit deadline reboots after 900 s. | the deadline plus one reboot |
| PID 1 hangs | The watchdog resets the box after 60 s (`RuntimeWatchdogSec=60s`). | not measured |
| Power is cut during `os apply` | See [Power-cut safety](#power-cut-safety). | |
| `grubenv` is empty or lost | The last line of 09_agentbox boots the committed entry. | passed |

Times are from QEMU VMs, at the time of writing. The gates shorten the commit deadline to 300 s.
The amd64 BIOS VM runs under software emulation and took longer, for example 70 s for the GRUB case.
The initrd gate stops a build whose initrd lacks these files, before any reboot. The gates break an initrd on purpose, after the build, to test these paths.

The watchdog driver is detected at install. A box with no hardware watchdog uses `softdog`, which cannot recover from every kernel hang.

In `tpm2+tang` mode, a Tang outage stops every generation from unlocking, the committed one included. See [Encryption and Recovery](Encryption-and-Recovery.md).

### The commit deadline

`agentbox-boot-deadline.service` comes from the seed. It is plain shell, so it works before the agentbox release is installed.
It starts early in every boot (`DefaultDependencies=no`, `WantedBy=sysinit.target`), so a unit that blocks boot cannot stop it.

It sleeps 900 s (15 minutes). Then it builds the booted entry id from the root subvolume and `uname -r`.
If `saved_entry` or `/bootpart/agentbox/committed` names that entry, it exits.
If not, it logs this line and runs `systemctl reboot --force`:

```
agentbox: boot deadline: <entry> is not committed; rebooting into the committed generation
```

This applies to any uncommitted entry, however it was booted.
The script reads `AGENTBOX_BOOT_DEADLINE_SEC`. The test gates set it to 300 with a systemd drop-in.

### After a fallback

About a minute after the box is back on the committed entry, the next health run records the failure:

- If `grubenv` still names the trial in `next_entry` or `saved_entry`, it puts those values back first.
- It writes `/var/lib/agentbox/os/failed/gen-M.json`.
- It logs `agentbox: ALERT: trial <entry> failed: the box booted <entry> instead; it stays uncommitted`.

The failed generation stays on disk until the next `os apply` deletes it.
Nothing needs cleaning up by hand.
Everything outside `@gen-N`, such as `/home`, `/var/log` and `/var/lib/agentbox`, survives the fallback.
Anything the trial wrote there stays too. Restoring service state after a fallback is designed, not built.
The trial's boot logs stay in the journal.

## Retention

Retention runs after every commit and at the start of every `os apply`. It keeps:

- the three newest generations at or below the committed one: current, previous and one more;
- any generation that is booted, committed, named by `saved_entry`, or pending.

Everything else is deleted, including failed trials and builds that a power cut interrupted.
A generation's boot directory and subvolume are deleted together. Then `grub.cfg` is regenerated.
Linux frees a deleted subvolume in the background, and the last step can leave the disk quota counts inconsistent, so that no quota limits anything.
So retention then waits until Linux has freed the deleted subvolumes, and asks rootd to check the quota counts at once (`agentbox quota check`).
The journal shows `os: qgroups checked after deleting subvolumes <ids>: <rootd's reply>`.
If rootd can't be reached, the command prints `agentbox: ALERT: qgroups not checked after deleting subvolumes ...` and fails; rootd's own check, every 5 minutes, still runs.
For example, with generations 1 to 4 on disk, committing gen-4 deletes gen-1.
After a commit, three generations normally remain. During a trial there is one more.

Before it deletes anything, retention reads the fstab of every kept generation.
If one still mounts a boot directory that would be deleted, it deletes nothing and stops with `ALERT: retention refused: ...`.
If an error or a power cut leaves `grub.cfg` listing a deleted generation, the next health run on the committed generation regenerates it.

A new generation's number is above every generation on disk and every failed trial on record, so gaps in the numbers are normal.
One exception: a build that is discarded before its trial leaves no record, so the next build can reuse its number.

## Check the state

```sh
sudo /var/lib/agentbox/current/bin/agentbox os status
```

Example, right after `os apply --no-reboot`:

```
booted:      agentbox-gen-1-<kernel>
committed:   agentbox-gen-1-<kernel>
saved_entry: agentbox-gen-1-<kernel>
next_entry:  agentbox-gen-2-<kernel>
pending:     agentbox-gen-2-<kernel> (plan <plan-sha256>)
gen-1   subvolume=true  kernels=<kernel>,<older kernel>
gen-2   subvolume=true  kernels=<kernel>,<older kernel>
```

| Line | Meaning |
|---|---|
| `booted` | The entry running now. |
| `committed` | The contents of `/bootpart/agentbox/committed`. |
| `saved_entry`, `next_entry` | GRUB's values in `grubenv`. |
| `pending` | A trial waiting for its boot or its commit, with its plan hash. |
| `failed` | One line per failed trial on record, as JSON. |
| `gen-N` | Each generation: whether its subvolume exists, and its kernels, newest first. |

A failed trial adds a line like this:

```
failed:      {"at":"<time>","booted":"agentbox-gen-1-<kernel>","entry":"agentbox-gen-6-<kernel>","plan":"<plan-sha256>"}
```

`os status` changes nothing. A trial that fell back shows as `pending` until the next health run records it.

The journal keeps every commit, prune and alert from health, and every deadline reboot, across all generations.
`os apply` prints its own prune and ALERT lines to your terminal only.
When you run `os mark-last-good` by hand, its lines, including any commit, also go only to your terminal.
To read the journal:

```sh
sudo journalctl -u agentbox-health.service -u agentbox-boot-deadline.service
```

Lines from a test run, with the kernel names replaced:

```
agentbox: boot deadline: agentbox-gen-17-<kernel> is not committed; rebooting into the committed generation
agentbox: ALERT: trial agentbox-gen-17-<kernel> failed: the box booted agentbox-gen-12-<kernel> instead; it stays uncommitted
os: committed agentbox-gen-18-<kernel>
os: prune gen-10
```

If another `os` command holds the lock when the timer fires, health prints `busy: another agentbox os command is running` and skips that run.

To see when health runs next:

```sh
systemctl list-timers agentbox-health.timer
```

To write `saved_entry` again after `grubenv` was emptied or lost:

```sh
sudo /var/lib/agentbox/current/bin/agentbox os mark-last-good
```

`os mark-last-good` re-asserts the booted entry as committed. Firstboot runs it once, on generation 1.
It refuses when the booted entry is not the committed one and no trial is pending.
It also refuses while a trial is pending and not yet booted, for example right after `os apply --no-reboot`. The error reads `trial <entry> is pending but <entry> is booted`.
On a booted trial, it commits the trial at once, without the health checks.
The next `os apply` also writes `saved_entry` again.

## Power-cut safety

The aim: a power cut at any moment leaves a box that boots on its own, into the committed entry or into a complete trial.

### What a cut leaves behind

- The build writes the new subvolume `@gen-M`, its boot directory, `grub.cfg`, `grubenv` and agentbox's state files. It never writes to the running generation's root.
- A cut before `next_entry` is set boots the committed entry. The next `os apply` deletes the unfinished build. If the pending record was already written, health first marks that trial failed.
- A cut after `next_entry` is set boots the trial once. `os apply` flushed everything to disk before it recorded the trial, so the trial is complete. Health commits it if it is healthy.
- A plan's directory appears under its hash only after every file in it is on disk.
- agentbox writes `committed`, `pending.json`, the failure records and the new fstab with a temp file, fsync, rename, then a directory fsync.

### How GRUB reads the disk

GRUB reads `/bootpart`, an ext4 file system, directly. Its ext4 driver does not replay the journal.
After a cut, GRUB sees each metadata block as it was last written to its home location.
Linux replays the journal when it mounts the partition, so Linux can see newer data than GRUB.

That breaks the usual "write a temp file, fsync, rename" pattern for files that GRUB reads.
Linux sees the rename as atomic. GRUB can see the new name before the new file's inode is home, or the old name after the old inode was freed.

So agentbox replaces `grub.cfg` and `grubenv` in this order:

1. Write the new file under a temporary name and fsync it.
2. Checkpoint the ext4 journal (`EXT4_IOC_CHECKPOINT`, Linux 5.13 or later). This writes every journaled block home and flushes the disk. The new file is now complete where GRUB reads, before the real name points at it.
3. Hard-link the current file to `<name>.agentbox-old`, so its inode and blocks stay allocated.
4. Rename the new file over the old name, then fsync the directory.
5. Checkpoint again. The rename is now home too.
6. Remove `<name>.agentbox-old`.

At every point, GRUB finds either the old file or the new one.

Other rules:

- `grub.cfg` is generated into a temp file with `grub-mkconfig -o`, checked with `grub-script-check`, then replaced as above. Plain `update-grub` rewrites `grub.cfg` in place.
- `grubenv` is changed on a copy with `grub-editenv`, replaced as above, then read back with `grub-editenv list`.
- agentbox never calls `grub-reboot` or `grub-set-default`. They rewrite `grubenv` in place, and a cut can leave it empty.
- The seed masks `grub2-common.service` and `grub-initrd-fallback.service`. Both would rewrite `grubenv` in place at every boot.
- GRUB itself still writes `grubenv` in place when it clears `next_entry`. That is upstream GRUB behavior.
- If `grubenv` ends up empty anyway, the last line of 09_agentbox boots the committed entry.

A cut in the middle of a `grubenv` replace can still leave GRUB reading the old values while Linux reads the new ones.
When that happens and the trial did not boot, the next health run puts `next_entry` and `saved_entry` back before it records the failure.
So no later boot runs the failed trial.

### How it was tested

At the time of writing, in QEMU VMs:

- QMP resets cut the power at five points during `os apply`, plus one right after it returns. The five points are clone, package install, initrd gate, `update-grub`, and boot once. Each time, the box booted the committed entry or the complete trial, with `grub.cfg` and `grubenv` intact. After the cut right after `os apply` returned, the trial booted and committed. That last cut has run only on development branches so far.
- One `os apply`, trial and commit was logged and replayed one write at a time. After each of more than 1,000 writes to `/bootpart`, a reader that skips the journal, as GRUB does, found a bootable entry with its kernel and initrd.
- The newest harness also boots the disk at each point where GRUB and Linux read different `grubenv` values. Each one settled on the committed entry. Those runs passed on development branches before they merged.
- The `breaks` scenario breaks trials on purpose: in GRUB, in the initrd, in fstab, and with a unit that blocks boot forever. Each one fell back with no console input.
- The `cycles` scenario removes a kernel, then upgrades it back together with systemd, and a third cycle prunes the oldest generation. The initrd built inside the container unlocked LUKS.
- A separate suite logs a VM's disk writes and runs `btrfs check --readonly` on the disk as it was at each flush (`none` mode only). None failed.

Limits:

- QMP power cuts ran in `tpm2` mode on the arm64 UEFI VM only.
- A replay keeps every write up to the cut, in order. A real disk can also lose or reorder writes made since its last flush. That is not tested.
- Torn sectors, disks that ignore flushes, discards, and firmware or TPM state are not modeled.
- No power cut has been tested on real hardware.

[Testing and Gates](Testing-and-Gates.md) explains the harness: `hack/apply-gate.sh` and `hack/powercut.sh`.

## Not built yet

Control:

- There is no command to boot, pin or roll back to an older generation. Fallback is automatic only.
- There is no command to cancel a pending trial. It runs at the next boot.
- Approval is the plan's SHA-256, passed by root to `os apply`. Signed approvals are designed, not built.

Protection:

- There is no protected-package list. `os plan` accepts any change apt can resolve, including the kernel, systemd, GRUB and shim. Read every plan before you approve it.
- The boot loader is not part of a generation. `os apply` never runs `grub-install` and never writes the EFI system partition. A plan that upgrades GRUB or shim packages does not update the installed boot loader. A post-commit boot-loader step is designed.
- A/B fallback covers crashes and bad builds, not hostile code. A signed but malicious package in an approved plan runs as root at the trial boot. See [Security Model](Security-Model.md).

Upkeep:

- There are no automatic updates. The nightly update job is designed. Today, updates happen only when an admin runs `os plan` and `os apply`.
- `os apply` updates Ubuntu packages, not agentbox itself. A new agentbox release means a reinstall. See [Release Pipeline](Release-Pipeline.md).
- Nothing deletes old plans or their `.deb` files in `/var/lib/agentbox/cas/debs/` yet.

[Roadmap](Roadmap.md) lists when these are planned.

## Command reference

All `os` commands run on the box, as root. Each one re-runs itself in a private mount namespace with `unshare --mount`.
On a machine without `unshare`, such as a Mac, they stop with an error that ends in `(agentbox os runs on the box)`.
On the box, call the binary by its full path, `/var/lib/agentbox/current/bin/agentbox`.

| Command | What it does |
|---|---|
| `agentbox os plan [--install PKG[=VER] ...] [--remove PKG ...] [--reinstall]` (at least one `--install` or `--remove`) | Resolves and downloads a change against the running generation. Prints the plan and its SHA-256. Installs nothing. |
| `agentbox os apply --approve <plan-sha256> [--no-reboot]` | Builds a new generation from that plan and sets up its one-time trial boot. Reboots unless `--no-reboot` is given. |
| `agentbox os status` | Prints the booted and committed entries, `saved_entry`, `next_entry`, any pending or failed trial, and every generation with its kernels. |
| `agentbox os health` | Runs the health check, and commits a healthy booted trial. `agentbox-health.timer` runs it every 50 seconds. |
| `agentbox os mark-last-good` | Re-asserts the booted entry as committed, or commits the booted trial without the health checks. |

Related pages: [Getting Started](Getting-Started.md), [Encryption and Recovery](Encryption-and-Recovery.md), [Testing and Gates](Testing-and-Gates.md), [Security Model](Security-Model.md), [Architecture](Architecture.md).

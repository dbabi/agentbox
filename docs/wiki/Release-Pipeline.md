The release pipeline packs the `agentbox` binary, its installer and its systemd units into one signed tarball. At first boot, the box downloads that release, checks it, and installs it.

> **Early alpha. Not for production use.** agentbox runs no AI agents yet. It has run only in QEMU virtual machines, never on real hardware.

No official agentbox release exists yet. There is no release host and no project signing key. You build, sign and host your own release.

## How the pieces fit

1. You make a minisign key pair once.
2. `make release` builds one tarball for amd64 and arm64 and signs it with your key.
3. You host the tarball and its `.minisig` file side by side on one HTTPS server.
4. The seed pins three values: the URL, the tarball's SHA-256 and your public key.
5. At first boot, the box downloads the tarball. It checks the SHA-256 first, then the signature. Only then does it install the release.

One seed installs exactly one release. There is no way yet to update the release on an installed box.

| Part | State at the time of writing |
|---|---|
| `make release` | Built. Run on macOS only. |
| Firstboot checks and install | Built. Proven in QEMU VM gates. |
| `install.sh` link switch and re-run | Built. Proven in QEMU VM gates. |
| Release download over HTTPS | Built, not tested. The gates serve releases over plain HTTP with `--dev`. |
| Release update on an installed box | Not built. A new release means a reinstall. |
| Real hardware | Not run. |

## What you need

- Go 1.26 or later.
- `make`.
- `minisign`. On a Mac, run `brew install minisign`. On Debian or Ubuntu, run `sudo apt install minisign`.
- A checkout of the repo. Run the build commands from the repo root.

## 1. Make a signing key (once)

```sh
minisign -G -p ~/agentbox-keys/minisign.pub -s ~/agentbox-keys/minisign.key
```

- minisign asks for a password twice. Set one. `make release` asks for it each time it signs.
- minisign creates `~/agentbox-keys` if it is missing. It refuses to overwrite key files that already exist.
- `minisign.key` is the secret key. Keep it private and outside the repo. Never commit it.
- `minisign.pub` is the public key. Its second line is the key itself: 56 characters that start with `RW`.

Print that line:

```sh
sed -n 2p ~/agentbox-keys/minisign.pub
```

The seed needs this line, not the path of the file.

If the secret key leaks, make a new key pair for your next seed. A leaked key cannot change a release that a seed already pins, because firstboot also checks the SHA-256.

`hack/gate.sh` makes its own throwaway keys in `.vm/keys`. Never use those keys for a real box.

## 2. Build a release

```sh
make release VERSION=0.0.1 MINISIGN_KEY="$HOME/agentbox-keys/minisign.key"
```

Write `$HOME` in `MINISIGN_KEY=`, not `~`. zsh, the default shell on macOS, does not expand `~` after `=` in a command argument. The build then fails with `release: stat ~/agentbox-keys/minisign.key: no such file or directory`.

First, `make` prints the `go run` line it runs, and minisign asks for the key's password. The output then ends with two lines like these:

```
wrote dist/agentbox-0.0.1.tgz and dist/agentbox-0.0.1.tgz.minisig
seed flags: --release-url https://<host>/<path>/agentbox-0.0.1.tgz --release-sha256 <64 hex digits>
```

| Variable | Required | Rule |
|---|---|---|
| `VERSION` | yes | 1 to 64 characters. The first one is a letter or a digit. The rest are letters, digits, `.`, `_`, `~` or `-`. No `+`. The version names the release directory on the box. |
| `MINISIGN_KEY` | yes | The path of your minisign secret key file. |
| `DIST` | no | The output directory. The default is `dist`, which git ignores. Use the default, or a directory outside the repo. An output directory that git does not ignore makes the next build's tree dirty, and its hash changes. |

What `make release` does:

1. It builds `agentbox` for linux/amd64 and linux/arm64, with the version built in. The binaries are static (`CGO_ENABLED=0`) and target baseline CPUs (`GOAMD64=v1`, `GOARM64=v8.0`).
2. It keeps your own Go settings out of the build, such as `GOFLAGS` and values set with `go env -w`. It still uses the Go version you run.
3. It packs one tarball. Every entry is a regular file owned by root. The entries are sorted and share one fixed timestamp.
4. It refuses a tarball over 64 MiB, because firstboot downloads no more than that. At the time of writing, the tarball is about 5 MB.
5. It signs the tarball with minisign. The signature also covers the trusted comment `agentbox <ver>`.
6. It prints the seed flags.

A rebuild with the same `VERSION` replaces both files in `DIST`. Any new commit gives a new hash, even one that changes only docs. So does any uncommitted change, or any new file in the tree that git does not ignore. A box that was seeded with the old hash refuses the new file.

The tarball holds these files:

```
bin/linux-amd64/agentbox
bin/linux-arm64/agentbox
install.sh
systemd/agentbox-health.service
systemd/agentbox-health.timer
systemd/agentbox-reconcile.service
```

One tarball holds both architectures because the seed has only one release URL. `install.sh` picks the binary that matches the box.

### Reproducible builds

Two builds from clean git checkouts of the same commit, with the same Go version and `VERSION`, give the same tarball, byte for byte. With the same key, the `.minisig` file is identical too. Ed25519 signatures are deterministic, and the trusted comment is fixed.

Anyone can rebuild a commit and compare the hash with the one a seed pins. Four rules apply:

- Build from a git checkout. Go records the commit id in the binary, so a source copy without `.git` gives a different hash.
- Keep the tree clean. Go also records whether the tree had changes. An uncommitted edit, or even a new file that git does not ignore, gives a different hash.
- Use the same Go version.
- Use the same `VERSION`. It is built into the binaries.

A CI build on Linux (ubuntu-26.04) and a rebuild on an Apple Silicon Mac, both with go1.26.11, gave byte-identical tarballs (v0.0.1-rc.2, 2026-11-20).

## 3. Check and host the release

Check the files before you upload them. These are the same two checks that firstboot makes.

```sh
shasum -a 256 dist/agentbox-0.0.1.tgz
minisign -Vm dist/agentbox-0.0.1.tgz -p ~/agentbox-keys/minisign.pub
```

On Linux, `sha256sum dist/agentbox-0.0.1.tgz` prints the same hash. The hash must equal the one that `make release` printed. minisign prints:

```
Signature and comment signature verified
Trusted comment: agentbox 0.0.1
```

To list the tarball's contents, run `tar -tzf dist/agentbox-0.0.1.tgz`.

Upload both files side by side. The signature's URL must be the tarball's URL plus `.minisig`:

```
https://<host>/<path>/agentbox-0.0.1.tgz
https://<host>/<path>/agentbox-0.0.1.tgz.minisig
```

The host must meet these rules:

| Rule | Why |
|---|---|
| The URL is `https://host[:port]/path`, with a port from 1 to 65535 and no query string. The path uses only letters, digits, `.`, `_`, `~`, `/` and `-`. | `agentbox seed` refuses any other URL. |
| The box trusts the certificate. A certificate from a public CA meets this rule. | curl on the box checks the certificate. |
| Any redirect goes to an `https` URL. | curl on the box follows redirects only to `https`. |
| Each file is at most 64 MiB. | curl on the box stops a bigger download. |
| The box can reach the host at first boot. | Firstboot downloads both files then. |

GitHub release asset URLs, such as `https://github.com/dbabi/agentbox/releases/download/<tag>/agentbox-0.0.1.tgz`, meet the URL rules if the tag uses only letters, digits, `.`, `_`, `~` and `-`. At the time of writing, they redirect to an `https` download URL with a query string. That is fine: only the URL in the seed must have none. No one has tested them with firstboot yet.

No gate has downloaded a release over HTTPS yet. Treat your first real install as that test.

## 4. Pin the release in the seed

Add these three flags to your `agentbox seed` command. Replace each `<...>` with your value, and keep the single quotes:

```
--minisign-pubkey "$(sed -n 2p ~/agentbox-keys/minisign.pub)"
--release-url 'https://<host>/<path>/agentbox-0.0.1.tgz'
--release-sha256 '<64 hex digits from make release>'
```

| Flag | What the seed accepts |
|---|---|
| `--minisign-pubkey` | The 56-character Ed25519 minisign public key that starts with `RW`. |
| `--release-url` | A URL that meets the rules above. With `--dev` only, also `http://10.0.2.2:PORT/path` (see [Testing in a VM](#testing-in-a-vm)). |
| `--release-sha256` | Exactly 64 lowercase hex digits. It is required and has no default. |

The full seed command is in [Getting Started](Getting-Started.md) and [Installing on Real Hardware](Installing-on-Real-Hardware.md).

The seed pins the SHA-256 as well as the key for one reason. A minisign check alone accepts any release that the same key signed, including an older one. An attacker who controls the host could then serve an old release with known bugs. The pin allows exactly one tarball.

The seed writes the three values to `/etc/agentbox-firstboot.env` on the box. They are not secret.

`agentbox seed` lists every problem at once and writes nothing. These are the release errors:

- `release url "...": https://host[:port]/path without query string required, port 1-65535 (with --dev, also http://10.0.2.2:PORT/path)`
- `release sha256 "...": the tarball's SHA-256 is required, 64 lowercase hex digits (make release prints it); minisign alone would accept any older signed release`
- `minisign public key: expected the 56-char Ed25519 minisign key starting with RW`. You see this one when you pass the path of `minisign.pub` instead of its second line.

## 5. What firstboot does

The seed installs `agentbox-firstboot.service` into generation 1. The unit runs `/usr/local/sbin/agentbox-firstboot`. It works in this order:

1. It cleans the btrfs top level. The installer leaves files there, outside every subvolume. Firstboot deletes every top-level entry whose name does not start with `@`.
2. It downloads the tarball and the `.minisig` file with curl.
3. It checks the tarball's SHA-256 against the seed's pin.
4. It checks the minisign signature with the seed's public key.
5. It unpacks the tarball and runs `install.sh --from-firstboot`.
6. It starts `agentbox-reconcile.service`.
7. It runs `agentbox os mark-last-good`. This confirms generation 1 as the committed generation.
8. It writes `/var/lib/agentbox/.firstboot-done`.

If the check in step 3 or step 4 fails, firstboot installs nothing. It logs one of these lines:

```
agentbox-firstboot: release sha256 <hash> does not match the seed's <pin>; nothing installed
agentbox-firstboot: release signature does not verify with the seed's minisign key; nothing installed
```

Every step is safe to repeat. A retry after a failure at any step does no harm.

curl runs with these options:

```
-fsSL --proto-redir =https --connect-timeout 20 --max-time 900 --retry 5 --retry-all-errors --max-filesize 64M
```

The downloads go into a work directory in `/run`, which is in memory. The 64 MiB cap limits what a bad release host can make the box store.

These unit settings control when firstboot runs:

| Setting | Effect |
|---|---|
| `After=network-online.target`, `Wants=network-online.target` | It waits for the network. |
| `ConditionPathExists=!/var/lib/agentbox/.firstboot-done` | It never runs again after step 8. |
| `Restart=on-failure`, `RestartSec=60`, `StartLimitIntervalSec=0` | After a failure, it tries again every 60 seconds, with no limit. |
| `WantedBy=multi-user.target` | Until step 8, it also runs at every boot. |
| `TimeoutStartSec=45min` | One attempt can take up to 45 minutes. |
| `RuntimeDirectory=agentbox-firstboot`, `RuntimeDirectoryMode=0700` | Each attempt starts in a fresh, empty, root-only directory, `/run/agentbox-firstboot`. systemd removes it when the attempt ends. |
| `PrivateMounts=yes` | Its mount of the btrfs top level stays private to the unit. |

### When firstboot fails

The health timer ships in the release. Until firstboot installs it, nothing else reports a failing firstboot. The failure shows on the console and in these commands on the box:

```sh
sudo systemctl status agentbox-firstboot
sudo journalctl -u agentbox-firstboot
```

To see the values the box expects, run:

```sh
sudo cat /etc/agentbox-firstboot.env
```

If the release URL does not work, the OS install still completes. Firstboot then retries forever. The `agentbox` binary comes from the release, so it is not on the box, and `agentbox os` commands are not available.

## 6. What install.sh does

`install.sh` must run as root. It takes exactly one argument, `--from-firstboot`. Anything else stops it with:

```
install.sh: usage: install.sh --from-firstboot (agentbox-firstboot runs it; there is no release-update op)
```

It works in this order:

1. It picks `bin/linux-<arch>/agentbox` for the box's architecture, as `dpkg --print-architecture` reports it.
2. It runs that binary as `agentbox version`. The output names the release. This also proves that the binary runs on the box.
3. It stages the release in `/var/lib/agentbox/releases/.<ver>.new` and syncs it to disk. Then it renames the directory to `/var/lib/agentbox/releases/<ver>`. So a release directory only ever appears complete.
4. It points the `current` link at the new release. If `current` pointed at another release, the `previous` link now points there. Both links switch by rename.
5. It copies the units to `/etc/systemd/system/`. systemd reads units before `/var/lib/agentbox` is mounted, so the copies must be on the root file system.
6. It runs `systemctl daemon-reload`. Then it enables every shipped unit that has an `[Install]` section. Today these are `agentbox-health.timer` and `agentbox-reconcile.service`.
7. It syncs again. A power cut then cannot leave firstboot marked done with empty unit files.

`install.sh` is safe to re-run. The same version with the same content changes nothing. `install.sh` refuses the same version with different content:

```
install.sh: release <ver> is already installed with different content
```

The release directory takes its name from the binary's own version, not from the tarball's file name.

After firstboot, the box has these release files:

```
/var/lib/agentbox/current -> releases/0.0.1
/var/lib/agentbox/releases/0.0.1/bin/agentbox
/var/lib/agentbox/releases/0.0.1/systemd/agentbox-health.service
/var/lib/agentbox/releases/0.0.1/systemd/agentbox-health.timer
/var/lib/agentbox/releases/0.0.1/systemd/agentbox-reconcile.service
/var/lib/agentbox/.firstboot-done
```

The link targets are relative. They still resolve when rescue media mounts the subvolume at another path.

`/var/lib/agentbox` is its own btrfs subvolume, outside the OS generations. Every generation runs the same release, so an OS fallback does not change it. See [Generations and Updates](Generations-and-Updates.md).

### current and previous

A normal install has no `previous` link. Firstboot installs one release, and nothing on the box installs a second one. The install gate creates `previous` when it runs `install.sh` by hand with two test releases. That run tests the link switch. It is not an update path.

### Check the installed release

Run these commands on the box:

```sh
readlink /var/lib/agentbox/current
/var/lib/agentbox/current/bin/agentbox version
```

For release `0.0.1`, they print `releases/0.0.1` and `0.0.1`. The binary is not on `PATH`, so use the full path.

## 7. The reconcile unit

`agentbox-reconcile.service` ships in the release. It runs `/var/lib/agentbox/current/bin/agentbox reconcile`.

- Today it does nothing. It prints `reconcile: no control state to re-apply yet` and exits 0.
- It has `Type=oneshot` and `RemainAfterExit=yes`, so it runs once per boot. A second start in the same boot does nothing.
- Firstboot starts it on the first boot. After that, `multi-user.target` starts it at every boot (`WantedBy=multi-user.target`).
- Never order it `After=multi-user.target` or `After=agentbox-firstboot.service`. Firstboot starts it from inside the boot. With either ordering, firstboot waits for that start, and the start waits for firstboot. The boot hangs until systemd stops the firstboot attempt at its 45-minute `TimeoutStartSec`.
- `systemd-analyze verify` does not catch that mistake. The install gate checks the unit's `After=` list and then boots the box for real.

Designed, not built: reconcile will rebuild what agentbox manages in the OS, such as agent accounts, from agentbox's own state. It runs at every boot, so whichever generation boots gets the same setup. Every agentbox service will require it and start after it.

## Units on the box

| Unit | Comes from | Job |
|---|---|---|
| `agentbox-firstboot.service` | the seed | Installs the release once. |
| `agentbox-boot-deadline.service` | the seed | Reboots the box if the booted generation is still not committed after 900 seconds. See [Generations and Updates](Generations-and-Updates.md). |
| `agentbox-reconcile.service` | the release | Runs reconcile once per boot. Today it does nothing. |
| `agentbox-health.timer` | the release | Starts `agentbox-health.service` 1 minute after boot, then 1 minute after each run ends. |
| `agentbox-health.service` | the release | Runs `agentbox os health`. See [Generations and Updates](Generations-and-Updates.md). |

## Testing in a VM

`agentbox seed --dev` is for QEMU test VMs only.

- With `--dev`, the seed also accepts a plain-HTTP release URL of the form `http://10.0.2.2:PORT/path`. The port is required.
- A QEMU guest on user networking reaches the host's loopback interface at `10.0.2.2`.
- Even with `--dev`, the seed refuses every other plain-HTTP address.
- `--dev` changes nothing else in the seed. Firstboot runs the same code and still checks the SHA-256 pin and the signature.

`hack/gate.sh` uses `--dev` like this:

1. It makes throwaway keys in `.vm/keys`.
2. It runs `make release` for two test versions: `0.0.1-gate`, and an older `0.0.0-gate`.
3. It serves the releases with `hack/release-serve` on `127.0.0.1`, port `7600` plus `AGENTBOX_VM_ID` (default 0).
4. It renders a seed with `--dev --release-url http://10.0.2.2:<port>/agentbox-0.0.1-gate.tgz`.

Then the gate checks firstboot against four releases:

| The gate serves | Firstboot must |
|---|---|
| A tampered tarball (its `install.sh` changed) with the real signature | Refuse it. The SHA-256 does not match the pin. |
| The older release, validly signed with the same key | Refuse it. Only the pin catches this one. |
| The right tarball, signed with another key | Refuse it. The signature does not verify. |
| The right tarball and its signature | Install it, start reconcile, finish, and let the boot complete. |

After each refusal, the gate checks that nothing was installed: no `releases/` directory, no `current` link and no reconcile unit. It also checks that `install.sh` switches `current` and `previous`, re-runs cleanly and refuses changed content.

Run the gate on an Apple Silicon Mac that is set up as in [Testing and Gates](Testing-and-Gates.md):

```sh
hack/gate.sh none
```

At the time of writing, this takes about 9-17 minutes. The results go to `.vm/gate-none.txt`.

`hack/release-serve` listens on `127.0.0.1` only. The VM can still reach every service on the Mac's loopback interface through `10.0.2.2`. Do not run untrusted code in the VM.

## Not built yet

- There is no way to update the agentbox release on an installed box. `install.sh` supports only `--from-firstboot`. A new release means a reinstall with a new seed.
- The design notes leave a release-update operation out of scope for v1. If one is built later, it must work like `os apply`: a health window, and on failure it switches `current` back to `previous` and restores the pre-migration database copy.
- `agentbox reconcile` does nothing yet.
- There is no official release, no release host and no project signing key. A signed project release is planned for the end of the 16-week plan. See [Roadmap](Roadmap.md).

OS package updates use a different path, `agentbox os plan` and `agentbox os apply`. See [Generations and Updates](Generations-and-Updates.md).

## Troubleshooting

| You see | Cause | Fix |
|---|---|---|
| `release: stat ~/agentbox-keys/minisign.key: no such file or directory` | Your shell passed `~` to `make` without expanding it. | Write `MINISIGN_KEY="$HOME/agentbox-keys/minisign.key"`. |
| `release: minisign not installed (brew install minisign / apt install minisign)` | minisign is not on your `PATH`. | Install minisign. |
| `release: VERSION="...": need [0-9A-Za-z][0-9A-Za-z._~-]*, at most 64 chars (it names the release dir on the box)` | `VERSION` is missing, or it has a character such as `+`. | Pick a version that follows the rule. |
| `minisign public key: expected the 56-char Ed25519 minisign key starting with RW` | You passed the path of `minisign.pub`, or the whole file. | Pass `"$(sed -n 2p ~/agentbox-keys/minisign.pub)"`. |
| On the box: `release sha256 ... does not match the seed's ...` | The host serves another tarball than the one you pinned. A rebuild from another commit has a new hash, even if only docs changed. | Upload the exact tarball you pinned, or make a new seed with the new hash. |
| On the box: `release signature does not verify with the seed's minisign key` | The `.minisig` file is old, or another key made it. | Upload the `.minisig` file that `make release` wrote next to the tarball. |
| On the box: a `curl:` error in `journalctl -u agentbox-firstboot` | The box cannot download one of the two files. | Check the URL, the certificate, and that both files are uploaded. |

## Where the code lives

| Path | What it holds |
|---|---|
| `Makefile` | The `release` target. |
| `hack/release/main.go` | The tool that builds, packs and signs a release. |
| `install/install.sh` | The installer that firstboot runs. |
| `systemd/` | The units that ship in the release. |
| `internal/seed/` | The seed generator. `seed.go` checks the release flags. `user-data.tmpl` holds the firstboot script and its unit. |
| `hack/release-serve/main.go` | The plain-HTTP server for VM tests. |

## Releases on GitHub

A release is made in two halves. CI builds it, and the owner signs it. The minisign secret key never goes to GitHub.

1. Push a tag: `git tag v<ver> && git push origin v<ver>`.
2. `.github/workflows/release.yml` runs the tests and builds `agentbox-<ver>.tgz` with `go run ./hack/release -unsigned`. It records the commit and the Go version in `BUILDINFO`, writes `SHA256SUMS`, adds a GitHub build-provenance attestation, and drafts the release.
3. The owner runs `hack/sign-release.sh v<ver>`. It downloads the draft's tarball, checks `SHA256SUMS` and the provenance with `gh attestation verify`, and rebuilds the same commit with the same Go version. It signs only if the two tarballs are byte-identical. Then it uploads `agentbox-<ver>.tgz.minisig` and publishes the release.
4. The script prints the seed flags: `--release-url https://github.com/dbabi/agentbox/releases/download/v<ver>/agentbox-<ver>.tgz --release-sha256 <sum>`.

`MINISIGN_KEY` defaults to `~/agentbox-keys/minisign.key`, with its public key next to it as `minisign.pub`. A draft stays unsigned, and a seed refuses it, until step 3 runs.

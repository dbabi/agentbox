agentbox is early alpha. It is not for production use.
Milestones 1, 2 and 4 of 9 are built and tested in QEMU VMs: the installer, the OS layer, the first host services (firewall, audit daemon, root daemon skeleton, quotas, ntfy), agent accounts and task containers. Milestone 3, the request checks, is built and waits for its 24-hour fuzz run.
No real hardware has run it yet.
The brokers, policy and approvals are designed but not built.

This page covers how to set up, change, test and submit code.

## The short version

1. Open an issue before you start a large change or a new feature.
2. Keep each change small, with a test that fails without it.
3. Run `go vet ./... && go test ./...`.
4. If the change touches the install, the boot or `os apply`, run the gate that covers it.
5. Write the commit message as [Commit messages](#commit-messages) shows.

## How we work

Every change starts with an issue.

1. Find or open the issue. Use a template: Bug, Task or Gate failure. Security problems go to [SECURITY.md](../../SECURITY.md), not to an issue.
2. Branch from `main` as `issue-<n>-<slug>`, for example `issue-12-fwcheck-timer`.
3. Open a pull request with `Closes #<n>` in the body. Fill in the template: what changed, the tests and gates you ran with their results, the evidence and the risks.
4. Wait for CI to pass. The `test` and `lint` jobs must be green.
5. Squash merge. The squash commit follows the [commit message](#commit-messages) rules.

The board is the GitHub project "agentbox" (Project 1 of `dbabi`).
Every open issue is on it.
An item moves Backlog, then Ready, then In progress, then In review, then Done.

- Backlog: planned, not ready to start.
- Ready: can start now. Issues labeled `needs-human` sit here until the owner does them.
- In progress: someone works on it. Move it here when you push the branch.
- In review: the pull request is open.
- Done: the pull request is merged and the issue is closed.

Each issue has one `area/*` label and one `type/*` label, and the GitHub milestone it belongs to.
`blocked` means it waits on another issue; say which one in a comment.

A ruleset protects `main`. Every change goes through a pull request.
The `test` and `lint` checks must pass, and pull requests merge by squash only. Force pushes and branch deletion are blocked.

## Set up

### Apple Silicon Mac

The Mac is the main test platform.
The arm64 UEFI gates use macOS's hypervisor (HVF), so they run only on a Mac.

1. Install the tools:

   ```sh
   brew install go qemu swtpm xorriso podman minisign uv pkg-config openssl
   ```

2. Start the podman machine. The `tpm2+tang` gates and the power-cut replays need it.

   ```sh
   podman machine init && podman machine start
   ```

3. Check three more tools. Each name should print a path:

   ```sh
   command -v dash sha256sum make
   ```

4. Check that `openssl` is Homebrew's. This must not print `LibreSSL`:

   ```sh
   openssl version
   ```

   macOS's own `openssl` is LibreSSL. With it, `TestInstallerOpenSSLLine` skips.

5. Clone and build.

   ```sh
   git clone https://github.com/dbabi/agentbox.git
   cd agentbox
   go build -o bin/agentbox ./cmd/agentbox
   bin/agentbox version
   ```

   A local build prints `dev`.

[Getting Started](Getting-Started.md) walks through a first install in the test VM.

### Linux

CI runs on GitHub Actions on Ubuntu 26.04: `lint` and `test` on every push and pull request, and the amd64 BIOS gates under KVM on every push to `main`, weekly and on manual dispatch.

For the unit tests:

1. Install Go 1.26 or later from [go.dev/dl](https://go.dev/dl/).
2. Install the test tools:

   ```sh
   sudo apt-get update && sudo apt-get install -y dash openssl minisign xorriso python3-yaml qemu-utils
   ```

For the amd64 BIOS gates:

```sh
sudo apt-get update && sudo apt-get install -y qemu-system-x86 qemu-utils swtpm xorriso minisign make curl
test -w /dev/kvm && echo "kvm ok"
```

If the last line does not print `kvm ok`, run `sudo usermod -aG kvm "$USER"`, then log out and back in.
Without KVM the gate still runs, but in software emulation, which is much slower.

- Use Ubuntu 26.04. The swtpm in Ubuntu 24.04 lacks an option that `hack/vm.sh` uses.
- Keep the checkout under your home directory. Ubuntu's AppArmor profile for swtpm blocks writes to most places outside your home directory, such as `/srv` and `/opt`.
- The arm64 UEFI gates do not run on Linux. `hack/powercut.sh` expects a podman machine, as on a Mac.

## Repo layout

| Path | What it holds |
|---|---|
| `cmd/agentbox/` | The `agentbox` CLI. `main.go` has `seed`, `recovery`, `version` and `reconcile`. `os.go` has the `os` commands, `fw.go` the firewall commands, `audit.go` `auditd` and `audit`, and `rootd.go` `rootd` and `egress`. All but `seed` and `recovery` run on the box. |
| `internal/seed/` | The seed generator. `user-data.tmpl` is the autoinstall template. It holds the installer's shell steps and the firstboot script. `reserved.go` lists admin names the seed refuses. |
| `internal/recovery/` | The offline recovery key pair: `recovery keygen` and `recovery decrypt`. |
| `internal/rootd/gens/` | A/B generations: `os plan`, the offline build, the fstab rewrite, the initrd gate, commit, failed trials and retention. |
| `internal/rootd/` | The rootd skeleton: its sockets, `resolve/` (the resolver), `quota/` (qgroups) and `nl/` (netlink for nftables sets and conntrack). |
| `internal/fw/` | The nftables ruleset (`agentbox.nft`), `fw load` and `fwcheck`. |
| `internal/audit/` | `agentbox-auditd`: segments, the hash chain, the taint database, sealing and `audit verify`. |
| `internal/ntfy/` | ntfy's config, ACLs, unit drop-in and fwcheck's ntfy check. |
| `internal/rootd/accounts/`, `internal/task/`, `internal/seccomp/`, `internal/rootd/attach/` | Agent accounts, the task container and its seccomp profile, and interactive sessions. |
| `internal/taskenv/`, `internal/taskrun/`, `internal/rootd/witness/`, `image/task/` | The task environment, the in-task forwarders and `agentbox why`, the witness pipe, and the test task image. |
| `sysusers.d/`, `tmpfiles.d/` | The service users and runtime directories the release installs under `/usr/lib`. |
| `install/install.sh` | The release installer. Firstboot runs it with `--from-firstboot`. |
| `systemd/` | The units in the release: health and reconcile, the firewall, auditd and its sockets, rootd and its sockets, and the agent stand-in the gates use. |
| `hack/` | Build and test tools. See the next table. |
| `docs/THREAT-MODEL.md` | The one-page threat model. |
| `.github/workflows/ci.yml` | CI. |
| `Makefile` | `make release`. |
| `bin/`, `dist/`, `.vm/` | Build output, release output and the test VM. Git ignores them. |

| Path in `hack/` | What it does |
|---|---|
| `gate.sh` | The install gates. |
| `apply-gate.sh` | The `os apply` gates. |
| `vm.sh` | Runs the QEMU test VM. |
| `powercut.sh`, `powercut/` | Logs every VM disk write, then replays the disk at any point. |
| `remaster-iso.sh` | Builds the zero-touch install ISO. |
| `release/` | The release builder behind `make release`. |
| `release-serve/` | Serves test releases to the VM during a gate. |
| `tang/` | A throwaway Tang server container for the `tpm2+tang` gates. |
| `verify-seed.py` | Checks a rendered seed. |
| `SHA256SUMS` | Pins the Ubuntu ISOs and the UEFI firmware. |
| `*_test.go` | Go tests for the shell scripts. |

## Code style

### Go

- Prefer the standard library. `go.mod` requires only `golang.org/x/sys` and `modernc.org/sqlite`. Open an issue before you add a module.
- `gofmt -l .` must print nothing, and `go vet ./...` must pass.
- agentbox is one binary. Add a command to `cmd/agentbox`, not a new binary. Tools under `hack/` are the exception.
- Keep decisions in pure functions that a unit test can call. Keep the code that runs commands thin. In `internal/rootd/gens`, `gens.go` parses and decides, and `box.go` runs the commands.
- Check input where it enters. An error says what is wrong and how to fix it. `agentbox seed` reports every problem at once and writes nothing.
- Comments explain why. Cite the design section that the code implements, as the existing comments do.
- Mark a known limit with a `// shortcut:` comment. Say what the limit is and when to lift it. The code uses these instead of to-do comments.

### Shell

- Scripts are POSIX `sh`. Each one starts with `#!/bin/sh` and runs `set -eu` before any work. Do not use bash features.
- `dash` is the reference shell. Ubuntu's `/bin/sh` is dash, so scripts on the box run under dash.
- Quote every expansion unless the code needs word splitting, as `$PODMAN` does in `hack/powercut.sh`. A checkout path can hold spaces and commas. `hack/vm_test.go` tests that.
- Treat what the VM reports as data. Never put it into the text that `eval` parses. Keep it in a variable, and let the check code name that variable, as `apply-gate.sh` does. `hack/apply_gate_test.go` tests every check line of `apply-gate.sh` for this.

### Python

`hack/verify-seed.py` is the only Python file. It is a test tool. Nothing in a release uses Python.

### Tests

- Make one fix or one feature per commit.
- A fix comes with a test that fails without it.
- Shell code gets Go tests too. A test runs the script, or a block cut from it, under `dash` with fake commands first on `PATH`. See `hack/*_test.go` and `install/install_test.go`.
- Tests write only inside their temp dirs. `install/install_test.go` moves the box's paths into a temp dir before it runs `install.sh`.
- Feed parsers real output captured on a test VM. Say in a comment where it came from. See `internal/rootd/gens/testdata/` and `internal/rootd/gens/plan_test.go`.
- Skip a test only when a tool it needs is missing.

## Run the tests

From the repo root:

```sh
go vet ./... && go test ./...
```

Each package prints `ok`. `hack/release-serve` has no tests.

Other useful forms:

Run every test again, without the cache:

```sh
go test -count=1 ./...
```

Run every test under the race detector, as CI does. This takes a few minutes:

```sh
go test -race ./...
```

Test one package:

```sh
go test ./internal/seed/
```

Run one test:

```sh
go test -run TestRenderedSeedsVerify ./internal/seed/
```

List the skipped tests. This prints nothing if no test skips:

```sh
go test -v ./... 2>&1 | grep -- '--- SKIP'
```

List the Go files that need `gofmt`:

```sh
gofmt -l .
```

Check the syntax of every shell script without running it:

```sh
for f in hack/*.sh hack/powercut/replay.sh install/install.sh; do dash -n "$f"; done
```

Some tests need outside tools: `dash`, `xorriso`, `minisign`, `qemu-img` and `qemu-io` (both come with QEMU), OpenSSL (not LibreSSL), and `uv` or `python3` with PyYAML.
`TestPowercutCheck` also needs the `agentbox-powercut` image in the podman machine.
The first `hack/powercut.sh` replay builds it, for example in the `cuts` scenario of `apply-gate.sh`.
To build it now, run this from the repo root:

```sh
podman --connection podman-machine-default-root build -t agentbox-powercut hack/powercut
```

A test skips when something it needs is missing.
On a Mac with all of these, no test skips.
On Linux, `TestPowercutCheck` skips, because it needs a podman machine.
GitHub sets `CI`. With `CI` set, a missing `minisign` or a missing seed checker fails the run instead of skipping.

`go test ./internal/seed/` renders all six seeds: three encryption modes, each for UEFI and BIOS.
It checks each one with `hack/verify-seed.py`.

## Run the gates

A gate installs agentbox into a fresh QEMU VM, boots it and checks the result.
Each check prints one PASS or FAIL line.
The plan counts a feature as built only when a gate proves it.
[Testing and Gates](Testing-and-Gates.md) lists what each gate checks.

### Before the first gate

1. Download the pinned Ubuntu ISO into `.vm/`. At the time of writing, each one is about 3 GB. Keep the file name. The arm64 ISO is for the UEFI gates:

   ```sh
   mkdir -p .vm
   curl -fL -o .vm/ubuntu-26.04.1-live-server-arm64.iso https://cdimage.ubuntu.com/releases/26.04.1/release/ubuntu-26.04.1-live-server-arm64.iso
   ```

   The amd64 ISO is for the BIOS gates:

   ```sh
   curl -fL -o .vm/ubuntu-26.04.1-live-server-amd64.iso https://releases.ubuntu.com/26.04.1/ubuntu-26.04.1-live-server-amd64.iso
   ```

2. Start the podman machine if you run a `tpm2+tang` gate or the `cuts` scenario.
3. Keep the Mac on AC power, with the lid open. A sleeping Mac freezes the VM, and the gate's timed waits then fail. `apply-gate.sh` blocks idle sleep itself. Run `gate.sh` under `caffeinate -i`:

   ```sh
   caffeinate -i hack/gate.sh tpm2
   ```

Also know:

- `hack/vm.sh` checks each ISO against `hack/SHA256SUMS` on every install.
- Both download URLs worked at the time of writing. When the next point release ships, both ISOs move to `https://old-releases.ubuntu.com/releases/26.04.1/`, with the same file names.
- The VM installs packages from the Ubuntu archive, so it needs a network. The first arm64 install also downloads the pinned UEFI firmware.
- At the time of writing, `.vm/` grows to about 12 GB.
- Each `gate.sh` run deletes the old VM disk and installs from scratch. So does the `install` scenario of `apply-gate.sh`.

### Pick the gate

Every code change runs `go vet ./... && go test ./...`.
Then run the gate that covers what you changed:

| You changed | Run |
|---|---|
| Only docs | No gate. Check that each command you added works. |
| `internal/seed/`, `internal/recovery/`, `cmd/agentbox/main.go` | `hack/gate.sh <mode>` for each encryption mode the change affects. Also run `hack/gate.sh <mode> bios` if it touches disks, partitions or GRUB. Add `hack/gate.sh dup-serial` if it touches the disk guard. |
| `internal/rootd/gens/`, `cmd/agentbox/os.go` | `hack/apply-gate.sh <mode> install setup cycles breaks`. Add `cuts` if it changes what is written to disk, or in what order. |
| `internal/fw/`, `cmd/agentbox/fw.go` | `hack/fw-gate.sh` |
| `internal/audit/`, `cmd/agentbox/audit.go` | `hack/audit-gate.sh` |
| `internal/rootd/` (outside `gens/`), `cmd/agentbox/rootd.go` | `hack/rootd-gate.sh`, and `hack/fw-gate.sh` if it touches the firewall sets |
| `internal/rootd/quota/`, `internal/ntfy/` | `hack/quota-ntfy-gate.sh` |
| `internal/ops/`, `gen/` | `hack/registry-gate.sh` |
| `internal/gate/`, `internal/ids/` | `hack/agentboxd-gate.sh` |
| `internal/sockets/`, `tmpfiles.d/` | `hack/sockets-gate.sh` |
| `internal/rootd/accounts/` | `hack/accounts-gate.sh` |
| `internal/task/`, `internal/seccomp/`, task start and stop in `internal/rootd/` | `hack/tasks-gate.sh` |
| `internal/rootd/attach/`, `internal/controlpaths/` | `hack/attach-gate.sh` |
| `internal/taskenv/`, `internal/taskrun/`, `internal/rootd/witness/`, `image/task/` | `hack/taskenv-gate.sh` |
| `hack/release/`, `install/install.sh` | `hack/gate.sh none`. Every install gate builds test releases, and firstboot installs one. |
| `systemd/` | `hack/apply-gate.sh tpm2 install setup cycles`. The health timer commits each trial. |
| `hack/vm.sh`, `hack/remaster-iso.sh`, `hack/SHA256SUMS` | `hack/gate.sh none`. Add `hack/gate.sh none bios` if the change touches the amd64 VM. |
| `hack/powercut.sh`, `hack/powercut/` | `hack/apply-gate.sh tpm2 install setup cuts` |
| `hack/gate.sh`, `hack/apply-gate.sh` | `go test ./hack/`, then the gate you changed. |

The `apply-gate.sh` scenarios after `install` and `setup` use the box those two leave.
Start with `install setup` on a fresh VM.

### Gate commands and times

Times are from one Apple Silicon Mac, at the time of writing.

| Command | Needs | Time |
|---|---|---|
| `hack/gate.sh dup-serial` | Mac | about 1.5 min |
| `hack/gate.sh none`, `hack/gate.sh tpm2` | Mac | about 9-17 min |
| `hack/gate.sh tpm2+tang` | Mac, podman machine | about 20 min (18-24 in the recorded runs) |
| `hack/gate.sh none bios`, `hack/gate.sh tpm2 bios` | amd64 ISO. A Mac runs the amd64 VM in software emulation. | about 60-80 min |
| `hack/apply-gate.sh tpm2 install setup cycles` | Mac | about 25-35 min |
| `hack/apply-gate.sh tpm2` (all five scenarios) | Mac, podman machine | about 90 min |

`hack/apply-gate.sh` takes `bios` after the mode, for the amd64 VM.
On a Mac, `hack/apply-gate.sh tpm2 bios install setup cycles breaks` took about 2 h 40 min.

### Read the result

- `gate.sh` prints `gate tpm2: all checks passed` when every check passes. A BIOS run prints `gate tpm2-bios: ...`.
- Its checks are in `.vm/gate-<mode>.txt`. BIOS runs add `-bios`, as in `.vm/gate-tpm2-bios.txt`. Some checks write their command output to `.vm/gate-<mode>.log`.
- `apply-gate.sh` ends with a `fails=0` line and exits 0. Its checks are in `.vm/apply-gate-<mode>.txt`, with the same `-bios` rule. Command output goes to the matching `.log` file.
- The serial console logs are `.vm/install.log` and `.vm/boot-*.log`.

Check the exit status and the last line printed first.
`gate.sh` writes its `.txt` only once the checks start.
If the install or the boot before the checks fails, the file still holds the previous run.
`apply-gate.sh` starts a new `.txt` only when the first scenario is `install`, and appends otherwise.
An `apply-gate.sh` run that stops early ends with an `ABORT` line instead of `fails=`.

List the failures and any `ABORT` line, then count the passes:

```sh
grep -e FAIL -e ABORT .vm/gate-tpm2.txt
grep -c PASS .vm/gate-tpm2.txt
```

The same commands work on `.vm/apply-gate-tpm2.txt`.

To look inside the VM after a gate, boot it in the background, wait until SSH answers, then log in:

```sh
hack/vm.sh boot &
until hack/vm.sh ssh true; do sleep 5; done
hack/vm.sh ssh
```

For a `tpm2+tang` VM, run `hack/vm.sh tang up` first.

When you are done, run `sudo poweroff` in the VM (password `x`).
While the VM runs, `gate.sh` stops early with `vm.sh: a VM is running`.

### Several VMs at once

Each VM lives in its checkout's `.vm/`.
To run two gates at once, use a second git worktree and a second VM ID (0-9).
From the main checkout, which holds the ISOs in `.vm/`:

```sh
MAIN=$PWD
git worktree add --detach ../agentbox-b main
cd ../agentbox-b
AGENTBOX_VM_ID=1 AGENTBOX_ISO_DIR="$MAIN/.vm" hack/gate.sh tpm2+tang
```

`AGENTBOX_ISO_DIR` lets the worktree use the main checkout's ISOs.
A worktree holds only committed work.
When you are done, copy the results out first. Then `git worktree remove ../agentbox-b` deletes the worktree, its `.vm/` included.
[Testing and Gates](Testing-and-Gates.md) lists the ports each VM ID uses.

### Keep the VM safe

- The VM reaches the internet, and the Mac's `127.0.0.1` only on the Tang and release-serve ports. It can still reach your LAN and any Mac service that listens on a LAN address.
- Gate seeds use the admin password `x`. Their recovery and release-signing keys live in `.vm/keys`. Never use them for a real box.

### Test containers

The Tang and power-cut containers are built once.
After you edit `hack/tang/Containerfile`, remove the old image:

```sh
podman rmi agentbox-tang
```

After you edit `hack/powercut/Containerfile`, remove that image:

```sh
podman --connection podman-machine-default-root rmi agentbox-powercut
```

The next run rebuilds the image.

## Docs and the design

How the docs relate to the design:

- The full design lives in [`docs/design/`](../design/): the architecture in [`ARCHITECTURE.md`](../design/ARCHITECTURE.md) and the build plan in [`PLAN.md`](../design/PLAN.md).
- The design says what is planned. The code and the gates say what is built. When they disagree, the docs follow the code.
- Code comments cite the design by file and section, for example `ARCHITECTURE.md §3.3` or `PLAN.md week 2`. Keep these citations when you move code.
- The plan builds in order. Each milestone ends with a gate, and that gate must pass before the next milestone starts. Open an issue before you start on a planned component. [Roadmap](Roadmap.md) lists the milestones.
- `docs/THREAT-MODEL.md` summarizes the design's security model in one page. `docs/design/` holds copies of the full design notes.

When you change docs:

- The README and the wiki describe what is built. Mark anything planned as designed, and name its milestone.
- Mark numbers that will change, such as versions, timings and test counts, with "at the time of writing".
- If your change affects what agentbox protects, who it defends against, or a risk it accepts, update `docs/THREAT-MODEL.md` in the same pull request.
- If your change alters a flag, a message or a command's output, update the README in the same pull request. The wiki is a separate repository, so list the wiki pages that need an update in the pull request.
- Write in plain language: short sentences, active voice, one idea per sentence.

## Commit messages

Write the subject as `<area>: <what changed>`.
The area is the command, package or file you changed.
Start the part after the colon in lowercase, unless it starts with a name such as `DIRECT_KERNEL`.
Leave off the final period.

Examples from the history:

```
seed: refuse Tang and release URL ports outside 1-65535
os plan: quote repository origins in the approval listing
firstboot: cap each release download at 64 MiB
vm.sh install: check the stock ISO against hack/SHA256SUMS on every install
README: the seed command takes --boot from step 2
```

The body:

1. Says what was wrong, and what it broke.
2. Says what the change does, and why that fixes it.
3. Names the test or gate that proves it. Many commits end with a `Test:` or `Gate:` line for this.

Wrap body lines at about 72 characters.

```
<area>: <what changed>

<What was wrong, and what it broke.>

<What the change does, and why that fixes it.>

Test: <the test, and what it checks>
```

## Pull requests

- Open pull requests against `main`.
- CI runs on every pull request and every push to `main`, on Ubuntu 26.04: the `lint` job (gofmt, `go vet`, staticcheck, shellcheck, govulncheck) and the `test` job (`go test`). On every push to `main`, weekly, and on manual dispatch, the `bios` job also runs `hack/gate.sh none bios` and `hack/gate.sh tpm2 bios` under KVM.
- CI does not run the arm64 UEFI gates or the `os apply` gates. If your change needs one, run it on a Mac. Put the command, the commit and the PASS and FAIL counts in the pull request.
- Never commit or attach `.vm/keys`, `.vm/id_vm`, a seed (`user-data`, `seed.iso` or a `.vm/gate-seed-*` directory), a `recovery.key` or a `luks.key`. The gate logs (`.vm/gate-*.txt`, `.vm/gate-*.log`, `.vm/install.log`, `.vm/boot-*.log`) are safe to attach. CI uploads the same files. A seed holds the admin password hash. `.gitignore` covers `recovery.key`, `luks.key`, `.vm/` and a `seed/` folder at the repo root, but check `git status` before you commit.
- Do not put the details of a security problem in a public issue. [Security Model](Security-Model.md) says how to report it privately.

## License

- agentbox is under the Apache License 2.0. See [`LICENSE`](../../LICENSE).
- Your contribution is under the same license. Section 5 of the license says so.
- There is no contributor license agreement (CLA).
- No sign-off line is needed. Section 5 of the license covers every contribution you submit.
- Do not add license headers to files. `LICENSE` covers the whole repo.

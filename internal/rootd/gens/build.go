package gens

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// aptOpts point apt at a plan directory: a copy of the running generation's /etc/apt and dpkg state, its own
// lists, cache and archive dir. Planning never writes to the running generation.
func aptOpts(w string) []string {
	return []string{"-o", "Dir::Etc=" + w + "/etc", "-o", "Dir::State=" + w + "/state",
		"-o", "Dir::State::status=" + w + "/state/status", "-o", "Dir::Cache=" + w + "/cache",
		"-o", "Dir::Cache::Archives=" + w + "/debs/"}
}

// MakePlan resolves req (apt-get install arguments: pkg, pkg=version, pkg-) on the running generation, downloads
// the closure into cas/debs/<sha256 of the plan>/ and returns the plan and that hash (§3.3 step 1). reinstall
// also re-installs named packages that are already at their version.
func MakePlan(req []string, reinstall bool) (*Plan, string, error) {
	for _, r := range req {
		if strings.HasPrefix(r, "-") || !rePkg.MatchString(strings.TrimSuffix(strings.SplitN(r, "=", 2)[0], "-")) {
			return nil, "", fmt.Errorf("plan: %q is not a package, pkg=version or pkg-", r)
		}
	}
	if reinstall {
		req = append([]string{"--reinstall"}, req...)
	}
	gen, _, err := Booted()
	if err != nil {
		return nil, "", err
	}
	status, err := os.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(DebsDir, 0o755); err != nil {
		return nil, "", err
	}
	w, err := os.MkdirTemp(DebsDir, ".plan-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(w)                      // renamed away on success
	if err := os.Chmod(w, 0o755); err != nil { // the build reads debs/ and lists/ as an unprivileged container root
		return nil, "", err
	}
	for _, d := range []string{"state/lists/partial", "cache", "debs/partial"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
			return nil, "", err
		}
	}
	if _, err := run("cp", "-a", "/etc/apt", w+"/etc"); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(w+"/state/status", status, 0o644); err != nil {
		return nil, "", err
	}
	if b, err := os.ReadFile("/var/lib/apt/extended_states"); err == nil {
		if err := os.WriteFile(w+"/state/extended_states", b, 0o644); err != nil {
			return nil, "", err
		}
	}
	o := aptOpts(w)
	logf("plan: apt-get update")
	if err := stream("apt-get", append(o, "-q", "update")...); err != nil {
		return nil, "", err
	}
	sim, err := run("apt-get", append(append(o, "-s", "install"), req...)...)
	if err != nil {
		return nil, "", err
	}
	acts, err := ParseSim(sim)
	if err != nil {
		return nil, "", err
	}
	if len(acts) == 0 {
		return nil, "", errors.New("plan: nothing to install or remove")
	}
	out, err := run("apt-get", append(append(o, "-qq", "--print-uris", "install"), req...)...)
	if err != nil {
		return nil, "", err
	}
	uris, err := ParseURIs(out)
	if err != nil {
		return nil, "", err
	}
	var want, got []string
	for _, a := range acts {
		if a.Op == "Inst" {
			want = append(want, DebFile(a))
		}
	}
	for _, u := range uris {
		got = append(got, u.File)
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		return nil, "", fmt.Errorf("plan: apt would download %v for the installs %v", got, want)
	}
	logf("plan: download %d .debs", len(uris))
	if err := stream("apt-get", append(append(o, "-q", "-y", "--download-only", "install"), req...)...); err != nil {
		return nil, "", err
	}
	// apt in the build opens archives/lock read-write; on the read-only bind only a missing lock is tolerated (EROFS)
	if err := os.Remove(filepath.Join(w, "debs", "lock")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, "", err
	}
	var debs []Deb
	for _, u := range uris {
		s256, sAlg, size, err := hashFile(filepath.Join(w, "debs", u.File), u.HashType)
		if err != nil {
			return nil, "", err
		}
		if size != u.Size || sAlg != u.Hash {
			return nil, "", fmt.Errorf("plan: %s does not match the signed index (%d bytes, want %d)", u.File, size, u.Size)
		}
		debs = append(debs, Deb{File: u.File, Size: size, SHA256: s256})
	}
	slices.SortFunc(debs, func(a, b Deb) int { return strings.Compare(a.File, b.File) })
	inst, err := Installed(status)
	if err != nil {
		return nil, "", err
	}
	end, err := EndState(inst, acts)
	if err != nil {
		return nil, "", err
	}
	p := &Plan{BaseGen: gen, BaseDpkg: Hash(status), Request: req, Actions: acts, Debs: debs, EndState: end}
	b := p.Marshal()
	h := Hash(b)
	if err := os.WriteFile(filepath.Join(w, "plan.json"), b, 0o644); err != nil {
		return nil, "", err
	}
	dst := filepath.Join(DebsDir, h)
	if old, err := os.ReadFile(filepath.Join(dst, "plan.json")); err == nil && bytes.Equal(old, b) {
		return p, h, nil // the same closure planned again: content-addressed, keep the first copy
	}
	if err := os.RemoveAll(dst); err != nil {
		return nil, "", err
	}
	syscall.Sync() // the dir shows under its hash only once every file in it is on disk
	if err := os.Rename(w, dst); err != nil {
		return nil, "", err
	}
	return p, h, syncDir(DebsDir)
}

// Print shows the plan for approval: every action, every .deb with its SHA-256, the base and the plan hash.
func (p *Plan) Print(h string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "base: %s, dpkg status sha256 %s\n", p.BaseGen, p.BaseDpkg)
	for _, a := range p.Actions {
		switch {
		case a.Op == "Remv":
			fmt.Fprintf(&b, "  Remv %s %s\n", a.Package, a.Old)
		case a.Old != "":
			fmt.Fprintf(&b, "  Inst %s %s -> %s [%s] (%s)\n", a.Package, a.Old, a.Version, a.Arch, a.Origin)
		default:
			fmt.Fprintf(&b, "  Inst %s %s [%s] (%s) new\n", a.Package, a.Version, a.Arch, a.Origin)
		}
	}
	var total int64
	for _, d := range p.Debs {
		total += d.Size
	}
	fmt.Fprintf(&b, "debs: %d files, %d bytes, in %s\n", len(p.Debs), total, filepath.Join(DebsDir, h))
	for _, d := range p.Debs {
		fmt.Fprintf(&b, "  %s  %s\n", d.SHA256, d.File)
	}
	fmt.Fprintf(&b, "end state: %d installed packages\nplan sha256: %s\napprove: agentbox os apply --approve %s\n", len(p.EndState), h, h)
	return b.String()
}

// The build's scripts run inside the nspawn as the generation's own root. Scaffolding (§3.3 Build): policy-rc.d
// stops service starts, and update-grub and grub-install are diverted to no-ops because GRUB files and the ESP
// change only on the host. The trap removes it all on every exit path; the host checks that it did.
const simScript = `exec apt-get -s install "$@"`

const installScript = `set -eu
undo() {
	rm -f /usr/sbin/policy-rc.d
	for f in /usr/sbin/update-grub /usr/sbin/grub-install; do
		if [ -n "$(dpkg-divert --list "$f")" ]; then rm -f "$f"; dpkg-divert --local --rename --remove "$f"; fi
	done
}
trap undo EXIT
trap 'exit 1' HUP INT TERM
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
for f in /usr/sbin/update-grub /usr/sbin/grub-install; do
	dpkg-divert --local --rename --divert "$f.agentbox" --add "$f"
	printf '#!/bin/sh\nexit 0\n' > "$f"
	chmod 0755 "$f"
done
cd /var/cache/apt/archives
if [ -n "$AGENTBOX_SUMS" ]; then printf '%s\n' "$AGENTBOX_SUMS" | sha256sum --strict --quiet -c -; fi
apt-get install -y --no-download -o APT::Get::AutomaticRemove=false \
	-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
`

// nspawnArgs runs script in gen's subvolume: fixed user-namespace range with id-mapped ownership, no network, only
// the generation's own /boot, the approved .debs and the plan's package lists, all but /boot read-only.
func nspawnArgs(root, boot, planDir string, env []string, script string, args []string) []string {
	a := []string{"--quiet", "--register=no", "--as-pid2", "--console=pipe", "--resolv-conf=off", "--timezone=off",
		"--link-journal=no", nspawnUsers, "--private-users-ownership=map", "--private-network",
		"-D", root, "--bind=" + boot + ":/boot:rootidmap", "--tmpfs=/var/log",
		"--bind-ro=" + planDir + "/debs:/var/cache/apt/archives", "--bind-ro=" + planDir + "/state/lists:/var/lib/apt/lists",
		"--setenv=LC_ALL=C", "--setenv=DEBIAN_FRONTEND=noninteractive"}
	for _, e := range env {
		a = append(a, "--setenv="+e)
	}
	return append(append(a, "/bin/sh", "-c", script, "sh"), args...)
}

// Build turns the approved plan into gen-M and sets it up for one trial boot (§3.3 steps 3-5). Any failure after
// the clone discards gen-M. top is the mounted btrfs top level.
func Build(hash, top string) (*Pending, error) {
	if p, err := Settle(); err != nil {
		return nil, err
	} else if p != nil {
		return nil, fmt.Errorf("%w (%s)", ErrBusy, p.Entry)
	}
	planDir := filepath.Join(DebsDir, hash)
	b, err := os.ReadFile(filepath.Join(planDir, "plan.json"))
	if err != nil {
		return nil, fmt.Errorf("no plan %s: %v", hash, err)
	}
	p, err := LoadPlan(b, hash)
	if err != nil {
		return nil, err
	}
	logf("base check")
	cur, k, err := Booted()
	if err != nil {
		return nil, err
	}
	c, err := CommittedEntry()
	if err != nil || c != Entry(cur, k) {
		return nil, fmt.Errorf("booted %s is not the committed generation (%q, %v)", Entry(cur, k), c, err)
	}
	// 09_agentbox's one-shot fallback is the saved_entry; an emptied grubenv booted through the committed file has none
	if env, err := ReadGrubEnv(); err != nil {
		return nil, err
	} else if env["saved_entry"] != c {
		if err := SetGrubEnv("saved_entry", c); err != nil {
			return nil, err
		}
	}
	status, err := os.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		return nil, err
	}
	if cur != p.BaseGen || Hash(status) != p.BaseDpkg {
		return nil, fmt.Errorf("stale_base: the plan is for %s with dpkg status %.12s, the box runs %s with %.12s", p.BaseGen, p.BaseDpkg, cur, Hash(status))
	}
	var sums []string
	for _, d := range p.Debs {
		s, _, _, err := hashFile(filepath.Join(planDir, "debs", d.File), "")
		if err != nil || s != d.SHA256 {
			return nil, fmt.Errorf("%s does not match the approved sha256 (%v)", d.File, err)
		}
		sums = append(sums, d.SHA256+"  "+d.File)
	}
	all, err := Generations(top) // before pruning, so a failed trial's number is never reused
	if err != nil {
		return nil, err
	}
	m := Gen(slices.Max(all) + 1)
	if err := PruneGens(top); err != nil { // failed trials and interrupted builds go before a new one starts
		return nil, err
	}
	root, boot := filepath.Join(top, "@"+m), filepath.Join(GensDir, m)

	logf("clone %s -> %s", cur, m)
	if _, err := run("btrfs", "subvolume", "snapshot", filepath.Join(top, "@"+cur), root); err != nil {
		return nil, err
	}
	pend, err := build(p, hash, root, boot, m, sums)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: ALERT: build %s discarded: %v\n", m, err)
		if derr := discard(top, m); derr != nil {
			return nil, fmt.Errorf("%v; discarding %s failed too: %v", err, m, derr)
		}
		if cfg, _ := os.ReadFile(filepath.Join(GrubDir, "grub.cfg")); bytes.Contains(cfg, []byte("'agentbox-"+m+"-")) {
			if uerr := UpdateGrub(); uerr != nil {
				return nil, fmt.Errorf("%v; update-grub after the discard failed: %v", err, uerr)
			}
		}
		return nil, err
	}
	return pend, nil
}

func build(p *Plan, hash, root, boot, m string, sums []string) (*Pending, error) {
	planDir := filepath.Join(DebsDir, hash)
	st, err := os.ReadFile(filepath.Join(root, "var/lib/dpkg/status"))
	if err != nil || Hash(st) != p.BaseDpkg {
		return nil, fmt.Errorf("stale_base: the clone's dpkg status changed (%v)", err)
	}
	if err := os.Mkdir(boot, 0o755); err != nil {
		return nil, err
	}
	cur := p.BaseGen
	// from the per-generation dir, never /boot: /boot has the /boot/grub and /boot/efi binds inside it
	if _, err := run("cp", "-a", "--one-file-system", filepath.Join(GensDir, cur)+"/.", boot+"/"); err != nil {
		return nil, err
	}
	logf("fstab: /boot -> %s", boot)
	fstab, err := os.ReadFile(filepath.Join(root, "etc/fstab"))
	if err != nil {
		return nil, err
	}
	if fstab, err = RewriteBoot(fstab, boot); err != nil {
		return nil, err
	}
	if err := WriteAtomic(filepath.Join(root, "etc/fstab"), fstab, 0o644); err != nil {
		return nil, err
	}

	logf("nspawn: apt-get -s")
	sim, err := run("systemd-nspawn", nspawnArgs(root, boot, planDir, nil, simScript, p.AptArgs())...)
	if err != nil {
		return nil, err
	}
	acts, err := ParseSim(sim)
	if err != nil {
		return nil, err
	}
	if !SameActions(acts, p.Actions) {
		return nil, fmt.Errorf("apt-get -s in the build differs from the approved closure:\n%s", sim)
	}
	logf("nspawn: apt-get install")
	if err := stream("systemd-nspawn", nspawnArgs(root, boot, planDir, []string{"AGENTBOX_SUMS=" + strings.Join(sums, "\n")}, installScript, p.AptArgs())...); err != nil {
		return nil, err
	}

	logf("scaffolding check")
	for _, f := range []string{"/usr/sbin/update-grub", "/usr/sbin/grub-install"} {
		out, err := run("dpkg-divert", "--root="+root, "--list", f)
		if err != nil || len(bytes.TrimSpace(out)) > 0 {
			return nil, fmt.Errorf("scaffolding left a diversion of %s: %q %v", f, out, err)
		}
	}
	if out, err := run("dpkg", "--root="+root, "--verify", "grub2-common"); err != nil || len(bytes.TrimSpace(out)) > 0 {
		return nil, fmt.Errorf("dpkg --verify grub2-common: %q %v", out, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/sbin/policy-rc.d")); !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("scaffolding left /usr/sbin/policy-rc.d (%v)", err)
	}
	st, err = os.ReadFile(filepath.Join(root, "var/lib/dpkg/status"))
	if err != nil {
		return nil, err
	}
	inst, err := Installed(st)
	if err != nil {
		return nil, err
	}
	end, _ := EndState(inst, nil)
	if !slices.Equal(end, p.EndState) {
		return nil, fmt.Errorf("installed set differs from the approved end state")
	}

	logf("name check")
	rel, err := relPaths(boot)
	if err != nil {
		return nil, err
	}
	if bad := BadNames(rel); len(bad) > 0 {
		return nil, fmt.Errorf("%s has file names outside [0-9A-Za-z.+~_-]: %q", boot, bad)
	}

	logf("initrd gate")
	names, err := dirNames(boot)
	if err != nil {
		return nil, err
	}
	ks := Kernels(names)
	if len(ks) == 0 {
		return nil, fmt.Errorf("%s has no kernel", boot)
	}
	mode, err := bootMode()
	if err != nil {
		return nil, err
	}
	conf, err := os.ReadFile(filepath.Join(root, "etc/dracut.conf.d/90-agentbox.conf")) // every generation inherits gen-1's
	if err != nil {
		return nil, fmt.Errorf("initrd gate: %v", err)
	}
	for _, k := range ks {
		initrd := filepath.Join(boot, "initrd.img-"+k)
		if _, err := os.Stat(initrd); err != nil {
			return nil, fmt.Errorf("initrd gate: %v", err)
		}
		list, err := run("lsinitrd", initrd)
		if err != nil {
			return nil, err
		}
		var crypttab []byte
		if mode.Encrypted {
			if crypttab, err = run("lsinitrd", "-f", "etc/crypttab", initrd); err != nil {
				return nil, err
			}
		}
		dep, err := os.ReadFile(filepath.Join(root, "usr/lib/modules", k, "modules.dep"))
		if err != nil {
			return nil, fmt.Errorf("initrd gate: %v", err)
		}
		builtin, err := os.ReadFile(filepath.Join(root, "usr/lib/modules", k, "modules.builtin")) // shipped in linux-modules-K
		if err != nil {
			return nil, fmt.Errorf("initrd gate: %v", err)
		}
		km := mode
		km.Drivers = RecordedDrivers(string(conf), string(dep), string(builtin))
		if miss := InitrdProblems(string(list), string(crypttab), km); len(miss) > 0 {
			return nil, fmt.Errorf("initrd gate: initrd.img-%s: %s", k, strings.Join(miss, "; "))
		}
	}

	entry := Entry(m, ks[0])
	logf("update-grub")
	if err := UpdateGrub(); err != nil {
		return nil, err
	}
	if err := GrubHasEntry(entry); err != nil {
		return nil, err
	}
	logf("boot once: %s", entry)
	syscall.Sync() // gen-M is complete on disk before anything can boot it
	bid, err := bootID()
	if err != nil {
		return nil, err
	}
	pend := &Pending{Gen: m, Kernel: ks[0], Entry: entry, Plan: hash, BootID: bid}
	pb, _ := json.Marshal(pend)
	if err := WriteAtomic(filepath.Join(StateDir, "pending.json"), append(pb, '\n'), 0o600); err != nil {
		return nil, err
	}
	if err := SetGrubEnv("next_entry", entry); err != nil {
		os.Remove(filepath.Join(StateDir, "pending.json"))
		return nil, err
	}
	return pend, nil
}

// bootMode reads what the initrds must carry from the running box: LUKS root from /etc/crypttab, a tang pin from
// the clevis binding.
func bootMode() (Mode, error) {
	ct, err := os.ReadFile("/etc/crypttab")
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !hasLinePrefix(string(ct), "croot ")) {
		return Mode{}, nil
	}
	if err != nil {
		return Mode{}, err
	}
	st, err := run("cryptsetup", "status", "croot")
	if err != nil {
		return Mode{}, err
	}
	dev := ""
	for _, l := range strings.Split(string(st), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "device:"); ok {
			dev = strings.TrimSpace(v)
		}
	}
	bind, err := run("clevis", "luks", "list", "-d", dev)
	if err != nil {
		return Mode{}, err
	}
	return Mode{Encrypted: true, Tang: bytes.Contains(bind, []byte(`"tang"`))}, nil
}

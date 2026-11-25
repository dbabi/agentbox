package gens

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Paths on the box (ARCHITECTURE.md §3.1, §12).
const (
	GensDir   = "/bootpart/agentbox/gens"
	Committed = "/bootpart/agentbox/committed"
	GrubDir   = "/bootpart/grub"
	// StateDir stands in for rootd.db until week 3: pending.json is the os_lock row held across the trial boot,
	// failed/ records trials that another generation booted instead.
	StateDir = "/var/lib/agentbox/os"
	CASDir   = "/var/lib/agentbox/cas"
	DebsDir  = CASDir + "/debs"
	// The build's fixed user-namespace range: outside nspawn's automatic pool and every agent or app sub-id block (§2, §4.1).
	nspawnUsers = "--private-users=2130706432:65536" // 0x7F000000
)

// logf prints a progress line; hack/apply-gate.sh power-cuts the VM on them.
func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "os: "+format+"\n", a...) }

// noImageLock turns off systemd-nspawn's image lock, a .#@gen-M.lck next to the image on the btrfs top level, which
// holds only @* (§15): a power cut during or just after a build leaves it there. Lock serializes os commands instead.
const noImageLock = "SYSTEMD_NSPAWN_LOCK=0"

func run(name string, args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	c := exec.Command(name, args...)
	c.Env = append(os.Environ(), "LC_ALL=C", noImageLock)
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// stream runs a command with its output on stderr (apt and dpkg progress).
func stream(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", noImageLock)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	return nil
}

func readTrim(p string) (string, error) {
	b, err := os.ReadFile(p)
	return strings.TrimSpace(string(b)), err
}

// WriteAtomic replaces p so that a power cut leaves the old or the new content: temp file, fsync, rename, fsync dir.
func WriteAtomic(p string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".new-*")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), p)
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(d string) error {
	f, err := os.Open(d)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Booted returns the running generation and kernel.
func Booted() (gen, k string, err error) {
	cmdline, err := readTrim("/proc/cmdline")
	if err != nil {
		return "", "", err
	}
	if gen, err = CmdlineGen(cmdline); err != nil {
		return "", "", err
	}
	k, err = readTrim("/proc/sys/kernel/osrelease")
	return gen, k, err
}

// CommittedEntry reads /bootpart/agentbox/committed.
func CommittedEntry() (string, error) {
	id, err := readTrim(Committed)
	if err != nil {
		return "", err
	}
	if _, _, ok := ParseEntry(id); !ok {
		return "", fmt.Errorf("%s holds %q, not an agentbox entry id", Committed, id)
	}
	return id, nil
}

// ReadGrubEnv reads /bootpart/grub/grubenv; a missing or empty one reads as empty (GRUB then boots the committed entry).
func ReadGrubEnv() (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(GrubDir, "grubenv"))
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return GrubEnv(b), err
}

// SetGrubEnv sets one grubenv variable by atomic replacement (§3.3 step 8). grub-reboot and grub-set-default
// truncate grubenv in place, so a power cut could leave it empty.
func SetGrubEnv(key, val string) error {
	env := filepath.Join(GrubDir, "grubenv")
	tmp := env + ".new"
	os.Remove(tmp) // a leftover from a cut
	b, err := os.ReadFile(env)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(b) > 0 {
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			return err
		}
	}
	if _, err := run("grub-editenv", tmp, "set", key+"="+val); err != nil {
		return err
	}
	if err := replaceForGrub(tmp, env); err != nil {
		return err
	}
	out, err := run("grub-editenv", env, "list")
	if err != nil {
		return err
	}
	if !slices.Contains(strings.Split(string(out), "\n"), key+"="+val) {
		return fmt.Errorf("grubenv does not show %s=%s after the write", key, val)
	}
	return nil
}

// UpdateGrub regenerates grub.cfg so a power cut leaves the old or the new file, then checks it.
func UpdateGrub() error {
	cfg := filepath.Join(GrubDir, "grub.cfg")
	tmp := cfg + ".agentbox-new"
	os.Remove(tmp)
	if _, err := run("grub-mkconfig", "-o", tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if _, err := run("grub-script-check", tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return replaceForGrub(tmp, cfg)
}

// replaceForGrub renames tmp over dst so that GRUB, too, finds the old or the new file after a power cut at any point.
// GRUB reads ext4 without replaying the journal: it sees each metadata block as it last reached its home location, so
// fsync and rename alone can show it the new directory entry with the new inode not home yet, or the old entry with
// its inode already freed. The first checkpoint puts the new inode home before any entry names it; the hard link keeps
// the old inode and its blocks allocated until the second checkpoint has put the rename home.
func replaceForGrub(tmp, dst string) error {
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return err
	}
	dir, old := filepath.Dir(dst), dst+".agentbox-old"
	if err := checkpoint(dir); err != nil {
		return err
	}
	// a link left by a cut: the checkpoint made the rename it guarded final at home
	if err := os.Remove(old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Link(dst, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	if err := checkpoint(dir); err != nil {
		return err
	}
	if err := os.Remove(old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// checkpoint commits the journal of dir's ext4 file system, writes every transaction to its home location and flushes
// the disk (EXT4_IOC_CHECKPOINT, Linux 5.13). A variable so the tests, which run off ext4, can stand in for it.
var checkpoint = func(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	var flags uint32
	const ext4IocCheckpoint = 0x4004662b // _IOW('f', 43, __u32)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), ext4IocCheckpoint, uintptr(unsafe.Pointer(&flags))); e != 0 {
		return fmt.Errorf("EXT4_IOC_CHECKPOINT %s: %v", dir, e)
	}
	return nil
}

// GrubHasEntry is the §3.3 step 5 check: an unknown id silently boots entry 0.
func GrubHasEntry(id string) error {
	b, err := os.ReadFile(filepath.Join(GrubDir, "grub.cfg"))
	if err != nil {
		return err
	}
	if !bytes.Contains(b, []byte("--id '"+id+"'")) {
		return fmt.Errorf("grub.cfg has no menu entry --id '%s'", id)
	}
	return nil
}

// Pending is the trial in flight: written before next_entry is set, removed at commit or when the box booted
// something else. BootID tells the boot that ran the build from the trial boot.
type Pending struct {
	Gen    string `json:"gen"`
	Kernel string `json:"kernel"`
	Entry  string `json:"entry"`
	Plan   string `json:"plan"`
	BootID string `json:"bootId"`
}

func ReadPending() (*Pending, error) {
	b, err := os.ReadFile(filepath.Join(StateDir, "pending.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("pending.json: %v", err)
	}
	return &p, nil
}

func bootID() (string, error) { return readTrim("/proc/sys/kernel/random/boot_id") }

// Lock serializes os commands on the box. With wait=false a held lock fails at once.
func Lock(wait bool) (func(), error) {
	if err := os.MkdirAll(StateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(StateDir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_EX
	if !wait {
		how |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("busy: another agentbox os command is running")
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}

// Settle ends a trial that is over: once the box has rebooted since the build and booted any other generation,
// the trial failed (§3.3 step 6: mark it failed, alert, and grubenv names it nowhere). It returns the trial still
// pending.
func Settle() (*Pending, error) {
	p, err := ReadPending()
	if err != nil || p == nil {
		return p, err
	}
	gen, k, err := Booted()
	if err != nil {
		return nil, err
	}
	id, err := bootID()
	if err != nil {
		return nil, err
	}
	if id == p.BootID || (gen == p.Gen && k == p.Kernel) {
		return p, nil
	}
	// GRUB reads /bootpart without replaying its journal: a cut inside SetGrubEnv can boot the old grubenv while the
	// one Linux reads still arms the trial (next_entry) or makes it the default (saved_entry). This runs before
	// failed/ and pending.json change, so a cut in here either boots the trial, still pending, or runs this again.
	env, err := ReadGrubEnv()
	if err != nil {
		return nil, err
	}
	if env["next_entry"] == p.Entry {
		if err := SetGrubEnv("next_entry", ""); err != nil {
			return nil, err
		}
	}
	if env["saved_entry"] == p.Entry {
		c, err := CommittedEntry()
		if err != nil {
			return nil, err
		}
		if err := SetGrubEnv("saved_entry", c); err != nil {
			return nil, err
		}
	}
	rec, _ := json.Marshal(map[string]string{"entry": p.Entry, "plan": p.Plan, "booted": Entry(gen, k), "at": time.Now().UTC().Format(time.RFC3339)})
	if err := os.MkdirAll(filepath.Join(StateDir, "failed"), 0o700); err != nil {
		return nil, err
	}
	if err := WriteAtomic(filepath.Join(StateDir, "failed", p.Gen+".json"), append(rec, '\n'), 0o600); err != nil {
		return nil, err
	}
	if err := os.Remove(filepath.Join(StateDir, "pending.json")); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "agentbox: ALERT: trial %s failed: the box booted %s instead; it stays uncommitted\n", p.Entry, Entry(gen, k))
	alert("agentbox: os apply", "an os apply trial failed: the box booted another entry, and the trial stays uncommitted")
	return nil, nil
}

// Mounts sets up the view os commands work in. Callers run in a private mount namespace (cmd/agentbox), so none of
// it shows on the host and it vanishes with the process. top gets the btrfs top level (subvolid=5). /bootpart is
// shared, so the booted /boot/grub and /boot/efi mounts also show inside gens/<booted>/: a non-recursive bind of
// /bootpart over itself hides them, so copies and deletes under gens/ never reach /bootpart/grub or the ESP.
func Mounts(top string) error {
	src, err := run("findmnt", "-n", "-v", "-o", "SOURCE", "/")
	if err != nil {
		return err
	}
	if _, err = run("mount", "-o", "subvolid=5", strings.TrimSpace(string(src)), top); err != nil {
		return err
	}
	_, err = run("mount", "--bind", "/bootpart", "/bootpart")
	return err
}

// Generations lists every generation number that has a subvolume or a boot dir.
func Generations(top string) ([]int, error) {
	var all []int
	for _, glob := range []string{filepath.Join(top, "@gen-*"), filepath.Join(GensDir, "gen-*")} {
		ms, err := filepath.Glob(glob)
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			if n, ok := GenNum(strings.TrimPrefix(filepath.Base(m), "@")); ok && !slices.Contains(all, n) {
				all = append(all, n)
			}
		}
	}
	slices.Sort(all)
	return all, nil
}

// protectedGens are never deleted (§3.3 step 7): the booted generation, saved_entry's and committed's.
func protectedGens() (booted int, committed int, prot []int, err error) {
	g, _, err := Booted()
	if err != nil {
		return 0, 0, nil, err
	}
	booted, _ = GenNum(g)
	c, err := CommittedEntry()
	if err != nil {
		return 0, 0, nil, err
	}
	cg, _, _ := ParseEntry(c)
	committed, _ = GenNum(cg)
	prot = []int{booted, committed}
	env, err := ReadGrubEnv()
	if err != nil {
		return 0, 0, nil, err
	}
	if sg, _, ok := ParseEntry(env["saved_entry"]); ok {
		n, _ := GenNum(sg)
		prot = append(prot, n)
	}
	if p, err := ReadPending(); err != nil {
		return 0, 0, nil, err
	} else if p != nil {
		n, _ := GenNum(p.Gen)
		prot = append(prot, n)
	}
	return booted, committed, prot, nil
}

// AfterDelete runs once a prune or a failed build has deleted generation subvolumes, with their subvolume ids. Linux
// drops them in the background and may mark qgroups inconsistent at the end, so agentbox os waits for that and has
// rootd check qgroups (#209). Nil, as in tests, runs nothing.
var AfterDelete func(ids []string) error

// Alert, if set, sends an ALERT on to the human with fixed text (agentbox os: ntfy). The ALERT line on stderr keeps the
// details. Nil, as in tests, sends nothing.
var Alert func(title, msg string)

func alert(title, msg string) {
	if Alert != nil {
		Alert(title, msg)
	}
}

// afterDelete hands the ids of the deleted subvolumes, skipping "" (none was there), to AfterDelete.
func afterDelete(ids ...string) error {
	ids = slices.DeleteFunc(ids, func(id string) bool { return id == "" })
	if len(ids) == 0 || AfterDelete == nil {
		return nil
	}
	return AfterDelete(ids)
}

// PruneGens applies retention (§3.3 step 7). It refuses, deleting nothing, if a kept generation's fstab still binds
// a doomed generation's boot dir. Deleted generations leave grub.cfg in the same step; if that update-grub fails or
// is cut, FixGrub repairs grub.cfg from the next health run. The qgroup check after the deletes runs either way.
func PruneGens(top string) error {
	all, err := Generations(top)
	if err != nil {
		return err
	}
	_, committed, prot, err := protectedGens()
	if err != nil {
		return err
	}
	drop := Prune(all, committed, prot)
	if len(drop) == 0 {
		return nil
	}
	if err := stillBound(top, all, drop); err != nil {
		return err
	}
	var ids []string
	for _, d := range drop {
		logf("prune %s", Gen(d))
		id, err := discard(top, Gen(d))
		if err != nil {
			return errors.Join(err, afterDelete(ids...))
		}
		ids = append(ids, id)
	}
	return errors.Join(UpdateGrub(), afterDelete(ids...))
}

// stillBound is the retention guard: an error if the fstab of a generation in all but not in drop binds the boot dir
// of one in drop. top is the mounted btrfs top level.
func stillBound(top string, all, drop []int) error {
	for _, k := range all {
		if slices.Contains(drop, k) {
			continue
		}
		fstab, err := os.ReadFile(filepath.Join(top, "@"+Gen(k), "etc/fstab"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, d := range drop {
			if References(fstab, filepath.Join(GensDir, Gen(d))) {
				alert("agentbox: os apply", "retention deleted nothing: a kept generation's fstab still binds the boot dir of one it would delete")
				return fmt.Errorf("ALERT: retention refused: kept %s's fstab still binds %s", Gen(k), filepath.Join(GensDir, Gen(d)))
			}
		}
	}
	return nil
}

// FixGrub runs update-grub when grub.cfg lists a generation whose kernel or initrd is gone: a prune or discard whose
// update-grub failed or was cut, which no later prune retries (it finds nothing left to drop).
func FixGrub() error {
	cfg, err := os.ReadFile(filepath.Join(GrubDir, "grub.cfg"))
	if err != nil {
		return err
	}
	for _, id := range MenuIDs(cfg) {
		g, k, ok := ParseEntry(id)
		if !ok {
			continue
		}
		for _, f := range []string{"vmlinuz-" + k, "initrd.img-" + k} { // what 09_agentbox lists an entry for
			if _, err := os.Stat(filepath.Join(GensDir, g, f)); errors.Is(err, fs.ErrNotExist) {
				logf("grub.cfg lists %s, whose %s is gone: update-grub", id, f)
				return UpdateGrub()
			}
		}
	}
	return nil
}

// discard deletes a generation's boot dir, then its subvolume, and returns the subvolume's id ("" if it was gone).
func discard(top, gen string) (string, error) {
	if err := os.RemoveAll(filepath.Join(GensDir, gen)); err != nil {
		return "", err
	}
	sv := filepath.Join(top, "@"+gen)
	if _, err := os.Lstat(sv); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	id, err := run("btrfs", "inspect-internal", "rootid", sv)
	if err != nil {
		return "", err
	}
	if _, err := run("btrfs", "subvolume", "delete", sv); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(id)), nil
}

// Health is the week-1 skeleton of the §3.3 health check; it returns what is wrong.
// Still to come: agentbox units, the firewall check, DNS, Tailscale and its serve config.
func Health() []string {
	var bad []string
	if out, _ := exec.Command("systemctl", "is-system-running").Output(); strings.TrimSpace(string(out)) != "running" {
		bad = append(bad, "system is "+strings.TrimSpace(string(out))+", not running (boot unfinished or a unit failed)")
	}
	gen, k, err := Booted()
	if err != nil {
		return append(bad, err.Error())
	}
	if root, err := mountRoot("/boot"); err != nil || root != "/agentbox/gens/"+gen {
		bad = append(bad, fmt.Sprintf("/boot is %q, not %s's boot dir (%v)", root, gen, err))
	}
	if _, err := os.Stat("/lib/modules/" + k); err != nil {
		bad = append(bad, "no /lib/modules/"+k)
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil || uint64(st.Bavail)*uint64(st.Bsize) < 2<<30 {
		bad = append(bad, "less than 2 GiB free on / (budgets.toml disk.reserve_bytes default)")
	}
	if !defaultRoute() {
		bad = append(bad, "no IPv4 default route")
	}
	return bad
}

func defaultRoute() bool {
	b, _ := os.ReadFile("/proc/net/route")
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) > 1 && f[1] == "00000000" {
			return true
		}
	}
	return false
}

// mountRoot returns the FSROOT of the topmost mount at mp (findmnt -n -o FSROOT mp).
func mountRoot(mp string) (string, error) {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	root := ""
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) > 4 && f[4] == mp {
			root = f[3]
		}
	}
	if root == "" {
		return "", fmt.Errorf("%s is not a mount point", mp)
	}
	return root, nil
}

// Commit makes the booted trial the default (§3.3 step 6), after checking that it really booted.
func Commit(p *Pending, top string) error {
	gen, k, err := Booted()
	if err != nil {
		return err
	}
	if gen != p.Gen || k != p.Kernel {
		return fmt.Errorf("booted %s, not the trial %s: not committing", Entry(gen, k), p.Entry)
	}
	if err := SetGrubEnv("saved_entry", p.Entry); err != nil {
		return err
	}
	if err := WriteAtomic(Committed, []byte(p.Entry+"\n"), 0o644); err != nil {
		return err
	}
	if err := UpdateGrub(); err != nil { // the empty-grubenv fallback must name the new committed entry
		return err
	}
	if err := os.Remove(filepath.Join(StateDir, "pending.json")); err != nil {
		return err
	}
	if err := syncDir(StateDir); err != nil {
		return err
	}
	logf("committed %s", p.Entry)
	return PruneGens(top)
}

// MarkLastGood re-asserts the booted generation as committed (firstboot runs it on gen-1), or commits the booted trial.
func MarkLastGood(top string) error {
	p, err := Settle()
	if err != nil {
		return err
	}
	gen, k, err := Booted()
	if err != nil {
		return err
	}
	id := Entry(gen, k)
	if p != nil {
		if p.Entry != id {
			return fmt.Errorf("trial %s is pending but %s is booted", p.Entry, id)
		}
		return Commit(p, top)
	}
	c, err := CommittedEntry()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	env, err := ReadGrubEnv()
	if err != nil {
		return err
	}
	if c == "" { // installs from before the committed file existed: saved_entry was the only record
		c = env["saved_entry"]
	}
	if c != id {
		return fmt.Errorf("booted %s is not the committed %q; nothing pending to commit", id, c)
	}
	if err := GrubHasEntry(id); err != nil {
		return err
	}
	if env["saved_entry"] != id {
		if err := SetGrubEnv("saved_entry", id); err != nil {
			return err
		}
	}
	if b, _ := os.ReadFile(Committed); string(b) != id+"\n" {
		if err := WriteAtomic(Committed, []byte(id+"\n"), 0o644); err != nil {
			return err
		}
		if err := UpdateGrub(); err != nil {
			return err
		}
	}
	logf("last good: %s", id)
	return nil
}

// hashFile returns a file's SHA-256, its hash under alg (an apt hash name, or "" for none) and its size.
func hashFile(p, alg string) (sum256, sumAlg string, size int64, err error) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", 0, err
	}
	defer f.Close()
	h256 := sha256.New()
	ha := map[string]hash.Hash{"MD5Sum": md5.New(), "SHA1": sha1.New(), "SHA256": sha256.New(), "SHA512": sha512.New(), "": sha256.New()}[alg]
	if ha == nil {
		return "", "", 0, fmt.Errorf("unknown hash %q", alg)
	}
	if size, err = io.Copy(io.MultiWriter(h256, ha), f); err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(ha.Sum(nil)), size, nil
}

// dirNames lists a directory's entry names.
func dirNames(d string) ([]string, error) {
	es, err := os.ReadDir(d)
	var ns []string
	for _, e := range es {
		ns = append(ns, e.Name())
	}
	return ns, err
}

// relPaths walks d and returns every path below it, relative to d.
func relPaths(d string) ([]string, error) {
	var rel []string
	err := filepath.WalkDir(d, func(p string, _ fs.DirEntry, err error) error {
		if err != nil || p == d {
			return err
		}
		r, _ := filepath.Rel(d, p)
		rel = append(rel, r)
		return nil
	})
	return rel, err
}

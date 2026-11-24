// Package quota sets up the disk reserve (ARCHITECTURE.md §3.2, §4.1, §12): btrfs quotas in full mode, one parent
// qgroup 2/0 over every store agents or apps can fill, limited so that max(10%, 4 GiB) of the file system stays free
// when 2/0 is full, and the CAS cap. Control state (releases, control/, rootd.db, audit/ with taint.db) and the OS
// generations stay outside 2/0, so they always keep the reserve.
package quota

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"agentbox/internal/rootd/gens"
)

const (
	Agentbox   = "/var/lib/agentbox"
	Data       = Agentbox + "/data" // @var_lib_agentbox_data
	Parent     = "2/0"
	minReserve = 4 << 30
	// slack is how far 2/0's limit may drift before Refresh moves it. The limit is set slack below its bound, so a
	// drift never eats into the reserve.
	slack = 64 << 20
)

// Fillable are the nested subvolumes this package creates (cas/ may already exist: `os plan` creates it too).
var Fillable = []string{Agentbox + "/state", Agentbox + "/memory", gens.CASDir, Agentbox + "/git", Data + "/images"}

// Members are the subvolumes assigned to 2/0 here. Agent subvolumes join through their 1/N, which rootd assigns at
// agent.add. @var_lib_agentbox_data itself is a member too, so nothing an agent fills in data/ escapes the cap.
var Members = append(append([]string{}, Fillable...), Data, "/srv")

// Reserve is what 2/0 leaves free for control state and the OS: max(10%, 4 GiB) of the file system.
func Reserve(size uint64) uint64 { return max(size/10, minReserve) }

// Bound is the most 2/0 may reference and still leave the reserve free: what it references now plus the free space
// above the reserve. Usage outside 2/0 (the OS generations, logs, control state) thus comes out of 2/0's share, not
// out of the reserve (#209). Once that usage has eaten into the reserve, Bound is below what 2/0 references, down to 0.
func Bound(size, free, rfer uint64) uint64 { return free + rfer - min(free+rfer, Reserve(size)) }

// ParentLimit is 2/0's referenced limit: slack below Bound, at most size minus the reserve, and at least 1 byte (0
// would mean no limit), which refuses every write once the reserve is gone.
func ParentLimit(size, free, rfer uint64) uint64 {
	b := Bound(size, free, rfer)
	if b <= slack {
		return 1
	}
	return min(b-slack, size-min(size, Reserve(size)))
}

// CASMax is budgets.toml cas.max_bytes' default: 10% of the pool. shortcut: budgets.toml isn't read yet; it lands
// with the budget ops, and the default applies until then.
func CASMax(size uint64) uint64 { return size / 10 }

func run(name string, args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	c := exec.Command(name, args...)
	c.Env = append(os.Environ(), "LC_ALL=C")
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// ensureSubvol creates p as a subvolume, or checks that it is one: a plain directory can't become one in place.
func ensureSubvol(p string) error {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); errors.Is(err, fs.ErrNotExist) {
		_, err := run("btrfs", "subvolume", "create", p)
		return err
	} else if err != nil {
		return err
	}
	if st.Ino != 256 { // the root directory of every btrfs subvolume
		return fmt.Errorf("quota: %s is a plain directory, not a btrfs subvolume (§3.2), so qgroup 2/0 can't cap it", p)
	}
	return nil
}

func rootID(p string) (string, error) {
	out, err := run("btrfs", "inspect-internal", "rootid", p)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(out))
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return "", fmt.Errorf("quota: rootid %s: %q", p, id)
	}
	return "0/" + id, nil
}

// fsSpace is the file system's size and the bytes free to an unprivileged writer.
func fsSpace(p string) (size, free uint64, err error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(p, &s); err != nil {
		return 0, 0, err
	}
	return uint64(s.Blocks) * uint64(s.Bsize), uint64(s.Bavail) * uint64(s.Bsize), nil
}

func fsSize(p string) (uint64, error) {
	size, _, err := fsSpace(p)
	return size, err
}

// Ensure brings quotas to the §4.1 state, idempotently: agentbox-reconcile runs it on every boot, so a hand edit or
// a lost limit comes back at the next one.
func Ensure() error {
	for _, p := range Fillable {
		if err := ensureSubvol(p); err != nil {
			return err
		}
	}
	mode, err := quotaMode()
	if err != nil {
		return err
	}
	switch mode {
	case "":
		// full mode (no -s): simple quotas let an unprivileged BTRFS_SUBVOL_QGROUP_INHERIT with an empty list skip
		// auto-inherit, and they don't count shared extents
		if _, err := run("btrfs", "quota", "enable", Agentbox); err != nil {
			return err
		}
	case "qgroup":
	default:
		return fmt.Errorf("quota: btrfs quotas are in %q mode; agentbox needs full (qgroup) mode", mode)
	}
	if _, err := run("btrfs", "quota", "rescan", "-W", Agentbox); err != nil {
		return err
	}
	qs, err := Show()
	if err != nil {
		return err
	}
	if _, ok := qs[Parent]; !ok {
		if _, err := run("btrfs", "qgroup", "create", Parent, Agentbox); err != nil {
			return err
		}
	}
	size, err := fsSize(Agentbox)
	if err != nil {
		return err
	}
	if size <= Reserve(size) {
		return fmt.Errorf("quota: a %d-byte file system leaves nothing above the %d-byte reserve", size, Reserve(size))
	}
	for _, p := range Members {
		id, err := rootID(p)
		if err != nil {
			return err
		}
		if !qs[id].hasParent(Parent) {
			if _, err := run("btrfs", "qgroup", "assign", id, Parent, Agentbox); err != nil {
				return err
			}
		}
	}
	cas, err := rootID(gens.CASDir)
	if err != nil {
		return err
	}
	if qs[cas].MaxExcl != CASMax(size) {
		if _, err := run("btrfs", "qgroup", "limit", "-e", strconv.FormatUint(CASMax(size), 10), cas, Agentbox); err != nil {
			return err
		}
	}
	// an assign can leave the numbers inconsistent until the rescan it scheduled finishes; Refresh needs them right
	if _, err := run("btrfs", "quota", "rescan", "-W", Agentbox); err != nil {
		return err
	}
	if err := Refresh(); err != nil {
		return err
	}
	return Verify()
}

// Refresh moves 2/0's limit to ParentLimit when it is above Bound (usage outside 2/0 grew into the reserve) or more
// than 2×slack below ParentLimit (that usage shrank). Run it only while qgroups are consistent: 2/0's referenced count
// is wrong otherwise. agentbox-reconcile runs it at boot (Ensure) and rootd on its qgroup timer.
func Refresh() error {
	size, free, err := fsSpace(Agentbox)
	if err != nil {
		return err
	}
	qs, err := Show()
	if err != nil {
		return err
	}
	q, ok := qs[Parent]
	if !ok {
		return fmt.Errorf("quota: no qgroup %s", Parent)
	}
	if want := ParentLimit(size, free, q.Rfer); !keep(q.MaxRfer, want, Bound(size, free, q.Rfer)) {
		if _, err := run("btrfs", "qgroup", "limit", strconv.FormatUint(want, 10), Parent, Agentbox); err != nil {
			return err
		}
	}
	return nil
}

// keep says a 2/0 limit cur still holds: set, at most bound (or the 1-byte floor once bound is gone), and within
// 2×slack of want, so a limit isn't rewritten for every byte written outside 2/0.
func keep(cur, want, bound uint64) bool {
	return cur != 0 && (cur <= bound || cur == 1) && cur+2*slack >= want
}

// Verify checks the §4.1 state without changing anything.
func Verify() error {
	size, err := fsSize(Agentbox)
	if err != nil {
		return err
	}
	mode, err := quotaMode()
	if err != nil {
		return err
	}
	if mode != "qgroup" {
		return fmt.Errorf("quota: mode %q, want qgroup", mode)
	}
	qs, err := Show()
	if err != nil {
		return err
	}
	_, free, err := fsSpace(Agentbox)
	if err != nil {
		return err
	}
	// a limit that drifted (usage outside 2/0 changed since Refresh) is still fine while it leaves the reserve
	if q := qs[Parent]; q.MaxRfer == 0 || (q.MaxRfer > Bound(size, free, q.Rfer) && q.MaxRfer != 1) {
		return fmt.Errorf("quota: %s max referenced %d, but %d free and %d referenced leave the %d-byte reserve only below %d",
			Parent, q.MaxRfer, free, q.Rfer, Reserve(size), Bound(size, free, q.Rfer))
	}
	for _, p := range Members {
		id, err := rootID(p)
		if err != nil {
			return err
		}
		if !qs[id].hasParent(Parent) {
			return fmt.Errorf("quota: %s (%s) is not under %s", p, id, Parent)
		}
	}
	for _, p := range []string{Agentbox, "/"} {
		id, err := rootID(p)
		if err != nil {
			return err
		}
		if qs[id].hasParent(Parent) {
			return fmt.Errorf("quota: %s (%s) is under %s and would lose the reserve", p, id, Parent)
		}
	}
	cas, err := rootID(gens.CASDir)
	if err != nil {
		return err
	}
	if qs[cas].MaxExcl != CASMax(size) {
		return fmt.Errorf("quota: cas %s max exclusive %d, want %d", cas, qs[cas].MaxExcl, CASMax(size))
	}
	return nil
}

// Qgroup is one row of `btrfs qgroup show`. A zero limit means none.
type Qgroup struct {
	Rfer, MaxRfer, MaxExcl uint64
	Parents                []string
}

func (q Qgroup) hasParent(p string) bool {
	for _, v := range q.Parents {
		if v == p {
			return true
		}
	}
	return false
}

// Show returns every qgroup with its limits and parents.
func Show() (map[string]Qgroup, error) {
	out, err := run("btrfs", "--format=json", "qgroup", "show", "-p", "-r", "-e", Agentbox)
	if err != nil {
		return nil, err
	}
	return parseShow(out)
}

func parseShow(b []byte) (map[string]Qgroup, error) {
	var doc struct {
		Rows []struct {
			ID      string          `json:"qgroupid"`
			Rfer    json.RawMessage `json:"referenced"`
			MaxRfer json.RawMessage `json:"max_referenced"`
			MaxExcl json.RawMessage `json:"max_exclusive"`
			Parents []string        `json:"parents"`
		} `json:"qgroup-show"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("quota: qgroup show: %v", err)
	}
	lim := func(r json.RawMessage) (uint64, error) {
		if string(r) == `"none"` {
			return 0, nil
		}
		return strconv.ParseUint(strings.Trim(string(r), `"`), 10, 64)
	}
	qs := map[string]Qgroup{}
	for _, r := range doc.Rows {
		var q Qgroup
		var err error
		if q.Rfer, err = strconv.ParseUint(strings.Trim(string(r.Rfer), `"`), 10, 64); err != nil {
			return nil, fmt.Errorf("quota: %s referenced %s", r.ID, r.Rfer)
		}
		if q.MaxRfer, err = lim(r.MaxRfer); err != nil {
			return nil, fmt.Errorf("quota: %s max_referenced %s", r.ID, r.MaxRfer)
		}
		if q.MaxExcl, err = lim(r.MaxExcl); err != nil {
			return nil, fmt.Errorf("quota: %s max_exclusive %s", r.ID, r.MaxExcl)
		}
		q.Parents = r.Parents
		qs[r.ID] = q
	}
	if len(qs) == 0 {
		return nil, fmt.Errorf("quota: qgroup show listed no qgroups")
	}
	return qs, nil
}

// quotaMode is "" with quotas off, else the first word of `btrfs quota status`'s Mode (qgroup or squota).
func quotaMode() (string, error) {
	out, err := run("btrfs", "quota", "status", Agentbox)
	if err != nil {
		return "", err
	}
	return parseMode(string(out))
}

func parseMode(s string) (string, error) {
	on, mode := "", ""
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Enabled":
			on = strings.TrimSpace(v)
		case "Mode":
			if f := strings.Fields(v); len(f) > 0 {
				mode = f[0]
			}
		}
	}
	switch {
	case on == "no":
		return "", nil
	case on == "yes" && mode != "":
		return mode, nil
	}
	return "", fmt.Errorf("quota: unexpected quota status %q", s)
}

// Run runs a btrfs (or other) command with LC_ALL=C and returns its stdout; the error carries its stderr.
func Run(name string, args ...string) ([]byte, error) { return run(name, args...) }

// EnsureSubvol creates p as a subvolume, or checks that it is one.
func EnsureSubvol(p string) error { return ensureSubvol(p) }

// AgentMax is an agent's default 1/N exclusive limit: a quarter of the pool. 2/0 still caps all agents together.
// shortcut: budgets.toml isn't read yet; budget.set re-applies a per-agent value once it lands.
func AgentMax(size uint64) uint64 { return size / 4 }

// AgentQgroup is agent N's level-1 qgroup.
func AgentQgroup(n int) string { return "1/" + strconv.Itoa(n) }

// EnsureAgent puts agent n's subvolumes in its own qgroup 1/N under 2/0 (§4.1), idempotently. limit 0 keeps the
// limit 1/N already has, or sets AgentMax on a new one. Call it before the subvolumes hold data.
func EnsureAgent(n int, limit uint64, subvols ...string) error {
	q := AgentQgroup(n)
	qs, err := Show()
	if err != nil {
		return err
	}
	if _, ok := qs[q]; !ok {
		if _, err := run("btrfs", "qgroup", "create", q, Agentbox); err != nil {
			return err
		}
	}
	rescan := false
	if !qs[q].hasParent(Parent) {
		if _, err := run("btrfs", "qgroup", "assign", q, Parent, Agentbox); err != nil {
			return err
		}
		rescan = true
	}
	for _, p := range subvols {
		id, err := rootID(p)
		if err != nil {
			return err
		}
		if !qs[id].hasParent(q) {
			if _, err := run("btrfs", "qgroup", "assign", id, q, Agentbox); err != nil {
				return err
			}
			rescan = true
		}
	}
	if limit == 0 {
		if limit = qs[q].MaxExcl; limit == 0 {
			size, err := fsSize(Agentbox)
			if err != nil {
				return err
			}
			limit = AgentMax(size)
		}
	}
	if qs[q].MaxExcl != limit {
		if _, err := run("btrfs", "qgroup", "limit", "-e", strconv.FormatUint(limit, 10), q, Agentbox); err != nil {
			return err
		}
	}
	if rescan {
		_, err = run("btrfs", "quota", "rescan", "-W", Agentbox)
	}
	return err
}

// Inconsistent reads the file system's qgroups/inconsistent flag (#79). Full mode marks qgroups inconsistent when it
// skips the accounting of a large dropped subtree (qgroup_drop_subtree_thres), and from then on 2/0 limits nothing
// until a rescan. Simple quotas never get there, but they don't count shared extents (Ensure).
func Inconsistent() (bool, error) {
	out, err := run("btrfs", "filesystem", "show", Agentbox)
	if err != nil {
		return false, err
	}
	uuid, err := parseUUID(string(out))
	if err != nil {
		return false, err
	}
	b, err := os.ReadFile("/sys/fs/btrfs/" + uuid + "/qgroups/inconsistent")
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(b)) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	}
	return false, fmt.Errorf("quota: qgroups/inconsistent reads %q", b)
}

// parseUUID takes the fsid from `btrfs filesystem show`'s first line, the name of its /sys/fs/btrfs dir.
func parseUUID(s string) (string, error) {
	if _, rest, ok := strings.Cut(s, " uuid: "); ok {
		if f := strings.Fields(rest); len(f) > 0 && len(f[0]) == 36 && strings.Count(f[0], "-") == 4 {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("quota: no uuid in btrfs filesystem show: %q", s)
}

// Rescan starts a qgroup rescan and waits for it (-w; -W only waits for one that already runs). If one already runs,
// it waits for that one instead.
func Rescan() error {
	_, err := run("btrfs", "quota", "rescan", "-w", Agentbox)
	if err != nil && strings.Contains(err.Error(), "in progress") {
		_, err = run("btrfs", "quota", "rescan", "-W", Agentbox)
	}
	return err
}

// Nested lists the subvolumes below subvolume p (`btrfs subvolume list -o`): §4.1 refuses NESTED_SUBVOLUME on any.
func Nested(p string) ([]string, error) {
	out, err := run("btrfs", "subvolume", "list", "-o", p)
	if err != nil {
		return nil, err
	}
	return parseNested(string(out)), nil
}

func parseNested(s string) []string {
	var paths []string
	for _, l := range strings.Split(s, "\n") {
		if _, p, ok := strings.Cut(l, " path "); ok {
			paths = append(paths, p)
		}
	}
	return paths
}

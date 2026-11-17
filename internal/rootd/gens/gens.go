// Package gens builds, boots once, commits and prunes A/B OS generations (ARCHITECTURE.md §3.3).
//
// The functions in this file are pure: they parse what the box reports (/proc/cmdline, grubenv, boot dirs, fstab)
// and decide. box.go runs the commands.
package gens

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// SafeName is the charset 09_agentbox accepts for kernel names; the build refuses any other name in gens/gen-M.
var SafeName = regexp.MustCompile(`^[0-9A-Za-z.+~_-]+$`)

var reGen = regexp.MustCompile(`^gen-([1-9][0-9]{0,8})$`)

// GenNum returns N for "gen-N".
func GenNum(name string) (int, bool) {
	m := reGen.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// Gen is the name of generation n.
func Gen(n int) string { return "gen-" + strconv.Itoa(n) }

// Entry is the GRUB menu entry id that 09_agentbox emits for generation gen booting kernel k.
func Entry(gen, k string) string { return "agentbox-" + gen + "-" + k }

// ParseEntry splits an entry id into its generation and kernel.
func ParseEntry(id string) (gen, k string, ok bool) {
	rest, ok := strings.CutPrefix(id, "agentbox-gen-")
	if !ok {
		return "", "", false
	}
	n, k, ok := strings.Cut(rest, "-")
	if !ok || !SafeName.MatchString(k) {
		return "", "", false
	}
	if _, ok := GenNum("gen-" + n); !ok {
		return "", "", false
	}
	return "gen-" + n, k, true
}

// CmdlineGen returns CUR from the one rootflags=subvol=@gen-N on the kernel command line.
func CmdlineGen(cmdline string) (string, error) {
	var gens []string
	for _, f := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(f, "rootflags="); ok {
			g, ok := strings.CutPrefix(v, "subvol=@")
			if _, isGen := GenNum(g); !ok || !isGen {
				return "", fmt.Errorf("kernel command line has %q, want rootflags=subvol=@gen-N", f)
			}
			gens = append(gens, g)
		}
	}
	if len(gens) != 1 {
		return "", fmt.Errorf("kernel command line has %d rootflags=subvol=@gen-N, want 1", len(gens))
	}
	return gens[0], nil
}

// Kernels returns K for every vmlinuz-K in a boot dir listing, newest first (09_agentbox's `sort -rV`).
func Kernels(names []string) []string {
	var ks []string
	for _, n := range names {
		if k, ok := strings.CutPrefix(n, "vmlinuz-"); ok && SafeName.MatchString(k) {
			ks = append(ks, k)
		}
	}
	slices.SortFunc(ks, func(a, b string) int { return VerCmp(b, a) })
	return ks
}

// VerCmp orders like GNU `sort -V` on kernel names (Debian verrevcmp): non-digit runs by character, with '~'
// before everything and letters before other characters; digit runs by value.
func VerCmp(a, b string) int {
	order := func(c byte) int {
		switch {
		case c >= '0' && c <= '9':
			return 0
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
			return int(c)
		case c == '~':
			return -1
		}
		return int(c) + 256
	}
	digit := func(c byte) bool { return c >= '0' && c <= '9' }
	for a != "" || b != "" {
		for (a != "" && !digit(a[0])) || (b != "" && !digit(b[0])) {
			var ac, bc int
			if a != "" {
				ac = order(a[0])
			}
			if b != "" {
				bc = order(b[0])
			}
			if ac != bc {
				return ac - bc
			}
			a, b = a[1:], b[1:]
		}
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		i, j := 0, 0
		for i < len(a) && digit(a[i]) {
			i++
		}
		for j < len(b) && digit(b[j]) {
			j++
		}
		if i != j {
			return i - j
		}
		if c := strings.Compare(a[:i], b[:j]); c != 0 {
			return c
		}
		a, b = a[i:], b[j:]
	}
	return 0
}

// GrubEnv parses a grubenv block ("# GRUB Environment Block", name=value lines, '#' padding).
func GrubEnv(b []byte) map[string]string {
	env := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			env[k] = v
		}
	}
	return env
}

// Prune returns the generations to delete (§3.3 step 7): keep current, previous and one more, that is the three
// newest at or below the committed one, plus every protected generation (booted, saved_entry, committed, pending).
// Anything newer than the committed generation and unprotected is a failed trial or an interrupted build.
func Prune(all []int, committed int, protected []int) []int {
	var keep []int
	for _, n := range slices.Backward(slices.Sorted(slices.Values(all))) {
		if n <= committed && len(keep) < 3 {
			keep = append(keep, n)
		}
	}
	var drop []int
	for _, n := range all {
		if !slices.Contains(keep, n) && !slices.Contains(protected, n) {
			drop = append(drop, n)
		}
	}
	slices.Sort(drop)
	return slices.Compact(drop)
}

// BadNames returns every path under a generation's boot dir whose name 09_agentbox could not quote safely.
func BadNames(rel []string) []string {
	var bad []string
	for _, r := range rel {
		if !SafeName.MatchString(path.Base(r)) {
			bad = append(bad, r)
		}
	}
	return bad
}

// ErrBusy means an os.apply trial is pending: one build at a time, held across the reboot until commit or fallback.
var ErrBusy = errors.New("busy: an os.apply trial is pending")

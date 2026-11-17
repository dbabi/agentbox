package gens

import (
	"fmt"
	"path"
	"strings"
)

// RewriteBoot points the one fstab line whose mountpoint is /boot at src, keeping every other byte (§3.3 Build:
// a clone must not keep its parent's /boot bind). It fails unless exactly one line matched.
func RewriteBoot(fstab []byte, src string) ([]byte, error) {
	lines := strings.SplitAfter(string(fstab), "\n")
	n := 0
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") || path.Clean(f[1]) != "/boot" {
			continue
		}
		n++
		at := strings.Index(l, f[0])
		lines[i] = l[:at] + src + l[at+len(f[0]):]
	}
	if n != 1 {
		return nil, fmt.Errorf("fstab has %d lines with mountpoint /boot, want exactly 1", n)
	}
	return []byte(strings.Join(lines, "")), nil
}

// References reports whether any fstab line mounts src (the retention guard: a kept generation must not bind a
// generation's boot dir that is about to be deleted).
func References(fstab []byte, src string) bool {
	for _, l := range strings.Split(string(fstab), "\n") {
		if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") && path.Clean(f[0]) == src {
			return true
		}
	}
	return false
}

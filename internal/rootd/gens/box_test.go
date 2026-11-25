package gens

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestReplaceForGrub checks the order that keeps every on-disk state GRUB can read bootable: at the first checkpoint
// the new file is complete and nothing names it yet; at the second the rename is done and a hard link still holds the
// old inode; then only the new file is left. A link left by a cut goes, a missing dst (no grubenv yet) is fine, and a
// failed checkpoint changes nothing.
func TestReplaceForGrub(t *testing.T) {
	saved := checkpoint
	t.Cleanup(func() { checkpoint = saved })
	for _, tc := range []struct {
		name          string
		dst, leftover bool
		want          []string // the state at each checkpoint, then at the end
	}{
		{"replace", true, false, []string{"dst=old tmp=new old=-", "dst=new tmp=- old=old", "dst=new tmp=- old=-"}},
		{"link left by a cut", true, true, []string{"dst=old tmp=new old=older", "dst=new tmp=- old=old", "dst=new tmp=- old=-"}},
		{"no dst yet", false, false, []string{"dst=- tmp=new old=-", "dst=new tmp=- old=-", "dst=new tmp=- old=-"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			dst, tmp, old := filepath.Join(d, "grub.cfg"), filepath.Join(d, "grub.cfg.agentbox-new"), filepath.Join(d, "grub.cfg.agentbox-old")
			read := func(p string) string {
				if b, err := os.ReadFile(p); err == nil {
					return string(b)
				}
				return "-"
			}
			state := func() string { return "dst=" + read(dst) + " tmp=" + read(tmp) + " old=" + read(old) }
			if tc.dst {
				os.WriteFile(dst, []byte("old"), 0o644)
			}
			if tc.leftover {
				os.WriteFile(old, []byte("older"), 0o644)
			}
			os.WriteFile(tmp, []byte("new"), 0o644)
			before, _ := os.Stat(dst)
			var got []string
			checkpoint = func(dir string) error {
				if dir != d {
					t.Errorf("checkpoint(%q), want %q", dir, d)
				}
				if fi, err := os.Stat(old); len(got) == 1 && err == nil && !os.SameFile(fi, before) {
					t.Error("the old name is a copy, not a hard link to the replaced inode")
				}
				got = append(got, state())
				return nil
			}
			if err := replaceForGrub(tmp, dst); err != nil {
				t.Fatal(err)
			}
			if got = append(got, state()); !slices.Equal(got, tc.want) {
				t.Errorf("states %q, want %q", got, tc.want)
			}
		})
	}
	d := t.TempDir()
	dst, tmp := filepath.Join(d, "grubenv"), filepath.Join(d, "grubenv.new")
	os.WriteFile(dst, []byte("old"), 0o644)
	os.WriteFile(tmp, []byte("new"), 0o644)
	checkpoint = func(string) error { return errors.New("ENOTTY") }
	if err := replaceForGrub(tmp, dst); err == nil {
		t.Error("a failed checkpoint went unreported")
	}
	if b, _ := os.ReadFile(dst); string(b) != "old" {
		t.Errorf("a failed checkpoint replaced grubenv: %q", b)
	}
}

// TestStillBound checks the retention guard on fstabs laid out like the btrfs top level (@gen-N/etc/fstab).
func TestStillBound(t *testing.T) {
	own := func(n int) string {
		return GensDir + "/" + Gen(n) + " /boot none bind,x-systemd.requires-mounts-for=/bootpart 0 0\n"
	}
	for _, tc := range []struct {
		name   string
		fstabs map[int]string // "" makes etc/fstab a directory; a missing key, no subvolume
		all    []int
		drop   []int
		want   string // "" for no refusal
	}{
		{"each generation binds its own dir", map[int]string{1: own(1), 2: own(2), 3: own(3), 4: own(4)}, []int{1, 2, 3, 4}, []int{1}, ""},
		{"kept gen-3 binds doomed gen-1", map[int]string{1: own(1), 2: own(2), 3: own(1)}, []int{1, 2, 3}, []int{1},
			"retention refused: kept gen-3's fstab still binds /bootpart/agentbox/gens/gen-1"},
		{"a doomed trial binds its kept parent (apply-gate's fstab break)", map[int]string{4: own(4), 5: own(4)}, []int{4, 5}, []int{5}, ""},
		{"an extra noauto bind of a doomed dir", map[int]string{2: own(2) + GensDir + "/gen-5 /mnt none bind,noauto 0 0\n", 5: own(5)}, []int{2, 5}, []int{5},
			"kept gen-2's fstab still binds /bootpart/agentbox/gens/gen-5"},
		{"gen-10 is not gen-1", map[int]string{1: own(1), 10: own(10)}, []int{1, 10}, []int{1}, ""},
		{"a commented-out bind", map[int]string{1: own(1), 2: own(2) + "# " + own(1)}, []int{1, 2}, []int{1}, ""},
		{"a kept generation with no subvolume", map[int]string{1: own(1)}, []int{1, 2}, []int{1}, ""},
		{"an fstab that can't be read", map[int]string{1: own(1), 2: ""}, []int{1, 2}, []int{1}, "is a directory"},
	} {
		top := t.TempDir()
		for n, fstab := range tc.fstabs {
			etc := filepath.Join(top, "@"+Gen(n), "etc")
			if fstab == "" {
				os.MkdirAll(filepath.Join(etc, "fstab"), 0o755)
				continue
			}
			os.MkdirAll(etc, 0o755)
			os.WriteFile(filepath.Join(etc, "fstab"), []byte(fstab), 0o644)
		}
		alerted := false
		Alert = func(string, string, string) { alerted = true }
		err := stillBound(top, tc.all, tc.drop)
		Alert = nil
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
		if refused := strings.Contains(tc.want, "still binds"); alerted != refused { // a refusal alerts (#213), a read error doesn't
			t.Errorf("%s: alerted %v", tc.name, alerted)
		}
	}
}

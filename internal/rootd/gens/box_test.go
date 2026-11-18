package gens

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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

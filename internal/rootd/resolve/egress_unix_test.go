//go:build unix

package resolve

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// #282: under rootd's umask 0077 the egress dir and its lists stay readable for the brokers, which run as their own
// users; a dir an earlier release made 0700 is repaired at the next edit.
func TestEgressModeUnderRootdUmask(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0o077))
	dir := filepath.Join(t.TempDir(), "egress")
	if _, err := EditList(dir, "proxy", Entry{"pypi.org", 443}, true); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o755 {
			t.Fatalf("egress dir %v %v, want 0755", fi.Mode(), err)
		}
		if fi, err := os.Stat(filepath.Join(dir, "common.list")); err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("common.list %v %v, want 0644", fi.Mode(), err)
		}
	}
	check()
	os.Chmod(dir, 0o700)
	if _, err := EditList(dir, "proxy", Entry{"registry.npmjs.org", 443}, true); err != nil {
		t.Fatal(err)
	}
	check()
}

package audit

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// tempDir is t.TempDir whose files lose their chattr flags before its removal: a root run sets them, and RemoveAll cannot
// delete an append-only or immutable file.
func tempDir(t testing.TB) string {
	d := t.TempDir()
	t.Cleanup(func() {
		filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err == nil && e.Type().IsRegular() {
				unlock(t, p)
			}
			return nil
		})
	})
	return d
}

// unlock clears the append-only and immutable flags on p, as an attacker with CAP_LINUX_IMMUTABLE could.
func unlock(t testing.TB, p string) {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	v, err := getFlags(f)
	if err != nil {
		t.Fatalf("get flags %s: %v", p, err)
	}
	if v&(flagAppend|flagImmutable) == 0 {
		return
	}
	nv := int32(v &^ (flagAppend | flagImmutable))
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_SETFLAGS, uintptr(unsafe.Pointer(&nv))); e != 0 {
		t.Fatalf("chattr -ia %s: %v", p, e)
	}
}

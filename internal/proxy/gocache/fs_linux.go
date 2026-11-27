package gocache

import (
	"os"

	"golang.org/x/sys/unix"
)

// openBeneath opens name read-only beneath dir, refusing any symlink or path that leaves it (§6.2 Hit).
func openBeneath(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat2(int(dir.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), name), nil
}

// renameNoReplace moves from to to, failing with EEXIST if to exists (renameat2 RENAME_NOREPLACE).
func renameNoReplace(fromDir *os.File, from string, toDir *os.File, to string) error {
	if err := unix.Renameat2(int(fromDir.Fd()), from, int(toDir.Fd()), to, unix.RENAME_NOREPLACE); err != nil {
		return &os.LinkError{Op: "renameat2", Old: from, New: to, Err: err}
	}
	return nil
}

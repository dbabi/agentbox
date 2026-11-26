//go:build !linux

package gocache

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openBeneath is Linux's openat2 RESOLVE_BENEATH, for the tests on other systems: one name in dir, no symlink.
func openBeneath(dir *os.File, name string) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EXDEV}
	}
	return os.OpenFile(filepath.Join(dir.Name(), name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// renameNoReplace is renameat2 RENAME_NOREPLACE for the tests on other systems: a link fails with EEXIST likewise.
func renameNoReplace(fromDir *os.File, from string, toDir *os.File, to string) error {
	if err := os.Link(filepath.Join(fromDir.Name(), from), filepath.Join(toDir.Name(), to)); err != nil {
		return err
	}
	return os.Remove(filepath.Join(fromDir.Name(), from))
}

//go:build !linux

package wsfs

import (
	"strings"

	"golang.org/x/sys/unix"
)

// openat stands in for openat2 off Linux (the unit tests on a Mac): one name at a time, none of them a symlink.
func openat(dir int, rel string, flags int) (int, error) {
	parts := strings.Split(rel, "/")
	fd := dir
	for i, p := range parts {
		f := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i == len(parts)-1 {
			f = flags | unix.O_NOFOLLOW
		}
		if p == "" || p == "." || p == ".." {
			err := error(unix.EXDEV)
			if fd != dir {
				unix.Close(fd)
			}
			return -1, err
		}
		next, err := unix.Openat(fd, p, f, 0)
		if fd != dir {
			unix.Close(fd)
		}
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

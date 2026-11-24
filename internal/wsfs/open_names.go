package wsfs

import (
	"strings"

	"golang.org/x/sys/unix"
)

// openatNames is openat2's walk done one name at a time, none of them a symlink (O_NOFOLLOW) or "..": a magic link is
// a symlink too, so it is refused as well.
func openatNames(dir int, rel string, flags int) (int, error) {
	parts := strings.Split(rel, "/")
	fd := dir
	for i, p := range parts {
		f := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i == len(parts)-1 {
			f = flags | unix.O_NOFOLLOW
		}
		if p == "" || p == "." || p == ".." {
			if fd != dir {
				unix.Close(fd)
			}
			return -1, unix.EXDEV
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

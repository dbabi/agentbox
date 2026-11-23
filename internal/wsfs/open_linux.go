package wsfs

import (
	"errors"

	"golang.org/x/sys/unix"
)

// openat opens rel below dir and never leaves it: no symlink, no magic link (/proc/self/fd/N), no "..". Under a
// seccomp filter that can't read openat2's flags, systemd answers it with ENOSYS (RestrictSUIDSGID, which DynamicUser
// implies): then the same walk is done one name at a time.
func openat(dir int, rel string, flags int) (int, error) {
	fd, err := unix.Openat2(dir, rel, &unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if errors.Is(err, unix.ENOSYS) {
		return openatNames(dir, rel, flags)
	}
	return fd, err
}

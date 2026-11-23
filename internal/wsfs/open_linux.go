package wsfs

import "golang.org/x/sys/unix"

// openat opens rel below dir and never leaves it: no symlink, no magic link (/proc/self/fd/N), no "..".
func openat(dir int, rel string, flags int) (int, error) {
	return unix.Openat2(dir, rel, &unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

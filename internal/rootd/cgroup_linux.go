package rootd

import (
	"fmt"
	"math"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// watchEvents sends on the channel after each IN_MODIFY of path, until path goes (IN_IGNORED). The fd stays open only that long.
func watchEvents(path string) <-chan struct{} {
	ch := make(chan struct{}, 1)
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return ch
	}
	if _, err := unix.InotifyAddWatch(fd, path, unix.IN_MODIFY); err != nil {
		unix.Close(fd)
		return ch
	}
	go func() {
		defer unix.Close(fd)
		b := make([]byte, 4096)
		for {
			n, err := unix.Read(fd, b)
			if err != nil || n <= 0 {
				return
			}
			select {
			case ch <- struct{}{}:
			default:
			}
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&b[off]))
				if ev.Mask&unix.IN_IGNORED != 0 {
					return
				}
				off += unix.SizeofInotifyEvent + int(ev.Len)
			}
		}
	}()
	return ch
}

// makeTaskDir is §2.1's per-task dir: mkdirat in the parent's dirfd, fchownat without following symlinks, then mode
// 2750, so the service's 0660 socket inherits the agent's group.
func makeTaskDir(path, owner string, gid uint32) error {
	uid, ok := lookupUID(owner)
	if !ok {
		return fmt.Errorf("no user %s", owner)
	}
	if uid > math.MaxInt32 || gid > math.MaxInt32 { // Fchownat takes ints; -1 there would mean "unchanged"
		return fmt.Errorf("uid %d or gid %d out of range", uid, gid)
	}
	dir, name := filepath.Split(path)
	pfd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_PATH, 0)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	if err := unix.Mkdirat(pfd, name, 0o700); err != nil {
		return err
	}
	if err := unix.Fchownat(pfd, name, int(uid), int(gid), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	fd, err := unix.Openat(pfd, name, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fchmod(fd, 0o2750)
}

package attach

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// credEvents gets a value after any write, create or rename in session-home or the dirs of its credential files, so
// Watch reads a token version as soon as a CLI writes it. It returns nil if inotify is unavailable; stop ends it.
func credEvents(home string) (ev <-chan struct{}, stop func()) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, func() {}
	}
	f := os.NewFile(uintptr(fd), "inotify") // nonblocking, so Close wakes a pending Read
	dirs := []string{home}
	for _, c := range CredFiles {
		dirs = append(dirs, filepath.Join(home, filepath.Dir(c)))
	}
	watch := func() {
		for _, d := range dirs { // a dir made since the last call is added; a watched one keeps its watch
			unix.InotifyAddWatch(fd, d, unix.IN_CLOSE_WRITE|unix.IN_MODIFY|unix.IN_MOVED_TO|unix.IN_CREATE|unix.IN_ONLYDIR|unix.IN_DONT_FOLLOW)
		}
	}
	watch()
	ch := make(chan struct{}, 1)
	go func() {
		defer close(ch)
		buf := make([]byte, 64<<10)
		for {
			if _, err := f.Read(buf); err != nil {
				return
			}
			watch()
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	return ch, func() { f.Close() }
}

//go:build !linux

// Stand-ins so the package builds and its tests run on a developer Mac; auditd itself runs only on Linux.
package audit

import (
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

var procStart = time.Now()

func fdatasync(f *os.File) error { return f.Sync() }
func dropCache(string) error     { return nil }
func bootTimeMs() int64          { return time.Since(procStart).Milliseconds() }
func bootID() string             { return "test-boot" }

func peerCred(c *net.UnixConn) (uint32, int32, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var x *unix.Xucred
	var xerr error
	if err := rc.Control(func(fd uintptr) { x, xerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) }); err != nil {
		return 0, 0, err
	}
	if xerr != nil {
		return 0, 0, xerr
	}
	return x.Uid, 0, nil
}

const (
	flagAppend    = 0x20
	flagImmutable = 0x10
)

func getFlags(*os.File) (int, error)      { return 0, nil }
func addFlags(*os.File, int) error        { return nil }
func fallocate(f *os.File, n int64) error { return f.Truncate(n) }

func availBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

package audit

import (
	"net"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func fdatasync(f *os.File) error { return unix.Fdatasync(int(f.Fd())) }

func bootTimeMs() int64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
		return 0
	}
	return ts.Nano() / 1e6
}

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

func peerCred(c *net.UnixConn) (uid uint32, pid int32, err error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, 0, err
	}
	if cerr != nil {
		return 0, 0, cerr
	}
	return cred.Uid, cred.Pid, nil
}

// Inode flags (chattr): setting either needs CAP_LINUX_IMMUTABLE, which only rootd has (§9).
const (
	flagAppend    = 0x20 // FS_APPEND_FL, linux/fs.h
	flagImmutable = 0x10 // FS_IMMUTABLE_FL
)

func getFlags(f *os.File) (int, error) {
	var v int32
	_, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_GETFLAGS, uintptr(unsafe.Pointer(&v)))
	if e != 0 {
		return 0, e
	}
	return int(v), nil
}

func addFlags(f *os.File, add int) error {
	v, err := getFlags(f)
	if err != nil || v&add == add {
		return err
	}
	nv := int32(v | add)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_SETFLAGS, uintptr(unsafe.Pointer(&nv))); e != 0 {
		return e
	}
	return nil
}

func fallocate(f *os.File, n int64) error { return unix.Fallocate(int(f.Fd()), 0, 0, n) }

func availBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

package seccomp

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// InstallService installs the service filter on every thread of this process (TSYNC), after setting no_new_privs,
// and returns the process's Seccomp_filters count before and after. A service exits if it fails.
func InstallService() (before, after int, err error) {
	p, err := ServiceProgram(runtime.GOARCH)
	if err != nil {
		return 0, 0, err
	}
	if before, err = Filters(); err != nil {
		return 0, 0, err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return before, 0, fmt.Errorf("seccomp: no_new_privs: %v", err)
	}
	f := make([]unix.SockFilter, len(p))
	for i, x := range p {
		f[i] = unix.SockFilter{Code: x.Code, Jt: x.Jt, Jf: x.Jf, K: x.K}
	}
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	r, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(f)
	if e != 0 {
		return before, 0, fmt.Errorf("seccomp: install the service filter: %v", e)
	}
	if r != 0 { // TSYNC: the id of a thread that could not take the filter
		return before, 0, fmt.Errorf("seccomp: thread %d could not take the service filter", r)
	}
	after, err = Filters()
	return before, after, err
}

// Filters is this process's Seccomp_filters count from /proc/self/status.
func Filters() (int, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := bytes.CutPrefix(sc.Bytes(), []byte("Seccomp_filters:")); ok {
			return strconv.Atoi(string(bytes.TrimSpace(v)))
		}
	}
	return 0, fmt.Errorf("seccomp: no Seccomp_filters line in /proc/self/status")
}

package seccomp

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const subvolCreate = 0x5000940e // BTRFS_IOC_SUBVOL_CREATE

// ioctl with a NULL argument: with no filter the kernel answers ENOTTY, or EFAULT on btrfs, and never makes anything.
func ioctl(fd int, cmd uint64) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(cmd), 0)
	if e != 0 {
		return e
	}
	return nil
}

// The filter as a service installs it, in a child process since it can't be lifted: BTRFS_IOC_SUBVOL_CREATE gets
// EOPNOTSUPP, also with 0xdead00000000 in cmd; another ioctl still reaches the kernel; every thread has exactly one
// filter more than before (A-G13).
func TestInstallService(t *testing.T) {
	if os.Getenv("AGENTBOX_SECCOMP_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestInstallService$", "-test.v")
		cmd.Env = append(os.Environ(), "AGENTBOX_SECCOMP_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS: TestInstallService") {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}
	d, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioctl(d, subvolCreate); errors.Is(err, unix.EOPNOTSUPP) {
		t.Fatalf("before the filter: %v, so this check can't tell the filter from the kernel", err)
	}
	before, after, err := InstallService()
	if err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Errorf("Seccomp_filters %d -> %d, want one more", before, after)
	}
	for _, cmd := range []uint64{subvolCreate, 0xdead00000000 | subvolCreate, 0x9400} {
		if err := ioctl(d, cmd); !errors.Is(err, unix.EOPNOTSUPP) {
			t.Errorf("ioctl %#x: %v, want EOPNOTSUPP", cmd, err)
		}
	}
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.IoctlGetInt(p[0], unix.TIOCINQ); err != nil {
		t.Errorf("FIONREAD (TIOCINQ) on a pipe under the filter: %v", err)
	}
	tasks, _ := filepath.Glob("/proc/self/task/*/status")
	for _, f := range tasks {
		b, _ := os.ReadFile(f)
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "Seccomp_filters:"); ok {
				if n, _ := strconv.Atoi(strings.TrimSpace(v)); n != after {
					t.Errorf("%s: %d filters, want %d on every thread (TSYNC)", f, n, after)
				}
			}
		}
	}
	if len(tasks) < 2 {
		t.Errorf("%d threads: the TSYNC check needs the Go runtime's", len(tasks))
	}
}

package taskrun

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const (
	route4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	route6 = "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"
	unix      = "Num       RefCount Protocol Flags    Type St Inode Path\n0000000000000000: 00000002 00000000 00000000 0001 03 1234\n"
	mountinfo = "1 0 0:30 / / ro - overlay overlay ro\n" +
		"2 1 0:25 /agentbox-gate/t/task_A /run/agentbox/gate ro - tmpfs tmpfs rw\n" +
		"3 1 0:25 /agentbox-witness/t/task_A /run/agentbox/witness ro - tmpfs tmpfs rw\n"
)

// tree writes a task's view of the box under a temp dir, with files overridden by name.
func tree(t *testing.T, over map[string]string) string {
	t.Helper()
	r := t.TempDir()
	files := map[string]string{"/proc/net/route": route4, "/proc/net/ipv6_route": route6, "/proc/net/unix": unix,
		"/proc/self/mountinfo": mountinfo, "/etc/resolv.conf": "# generated\nnameserver 127.0.0.1\noptions timeout:1\n",
		"/sys/class/net/lo/x": "", "/run/agentbox/gate/gate.sock": ""}
	for k, v := range over {
		files[k] = v
	}
	for k, v := range files {
		if v == "-" {
			continue
		}
		os.MkdirAll(filepath.Dir(filepath.Join(r, k)), 0o755)
		if err := os.WriteFile(filepath.Join(r, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func unreachable(string, string) error {
	return &os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH}
}

// #106: a clean task passes; each broken layer fails its own check with TASK_ISOLATION_PROBE.
func TestProbe(t *testing.T) {
	if _, err := (&Probe{Root: tree(t, nil), Task: "task_A", Dial: unreachable}).Run(); err != nil {
		t.Fatalf("clean task: %v", err)
	}
	for _, c := range []struct {
		check string
		over  map[string]string
		dial  func(string, string) error
	}{
		{"netdev", map[string]string{"/sys/class/net/eth0/x": ""}, nil},
		{"route", map[string]string{"/proc/net/route": route4 + "lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"}, nil},
		{"route", map[string]string{"/proc/net/ipv6_route": route6 +
			"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"}, nil},
		{"connect", nil, func(string, string) error { return nil }},
		{"connect", nil, func(string, string) error { return syscall.ECONNREFUSED }},
		{"connect", nil, func(string, string) error { return syscall.EAFNOSUPPORT }}, // only IPv6 may be missing
		{"resolv", map[string]string{"/etc/resolv.conf": "nameserver 127.0.0.1\nnameserver 1.1.1.1\n"}, nil},
		{"resolv", map[string]string{"/etc/resolv.conf": "nameserver 127.0.0.53\n"}, nil},
		{"resolv", map[string]string{"/etc/resolv.conf": "search x\n"}, nil},
		{"sibling_socket", map[string]string{"/run/agentbox-gate/t/task_B/gate.sock": ""}, nil},
		{"sibling_socket", map[string]string{"/proc/self/mountinfo": mountinfo + "4 1 0:25 /agentbox-proxy/t/task_B /mnt ro - tmpfs tmpfs rw\n"}, nil},
		{"abstract_socket", map[string]string{"/proc/net/unix": unix + "0000000000000000: 00000002 00000000 00010000 0001 01 99 @agentbox-proxy\n"}, nil},
	} {
		dial := c.dial
		if dial == nil {
			dial = unreachable
		}
		_, err := (&Probe{Root: tree(t, c.over), Task: "task_A", Dial: dial}).Run()
		var pe *ProbeError
		if !errors.As(err, &pe) || pe.Check != c.check {
			t.Errorf("%s %v: %v", c.check, c.over, err)
		}
	}
	// no IPv6 at all (ipv6.disable=1: no ipv6_route, and an IPv6 socket gets EAFNOSUPPORT, as net.Dial reports it) is
	// fine; a missing /proc file is a failure, not a pass
	noIPv6 := func(network, addr string) error {
		if addr[0] == '[' {
			return &net.OpError{Op: "dial", Net: network, Err: &os.SyscallError{Syscall: "socket", Err: syscall.EAFNOSUPPORT}}
		}
		return unreachable(network, addr)
	}
	if _, err := (&Probe{Root: tree(t, map[string]string{"/proc/net/ipv6_route": "-"}), Task: "task_A", Dial: noIPv6}).Run(); err != nil {
		t.Errorf("no ipv6_route: %v", err)
	}
	if _, err := (&Probe{Root: tree(t, map[string]string{"/proc/net/unix": "-"}), Task: "task_A", Dial: unreachable}).Run(); err == nil {
		t.Error("no /proc/net/unix: passed")
	}
}

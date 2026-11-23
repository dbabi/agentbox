package taskrun

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ProbeFailed is the code a task stops with when its isolation probe finds a way out.
const ProbeFailed = "TASK_ISOLATION_PROBE"

// ProbeChecks name the probe's checks, in the order it runs them; rootd accepts only these in an alert.
var ProbeChecks = []string{"netdev", "route", "connect", "resolv", "sibling_socket", "abstract_socket"}

// Probe checks the task's boundary from inside the container, before the CLI starts: config says Network=none and
// per-task socket dirs, this checks that it holds. Root is "/" on the box; tests point it at a fake tree.
type Probe struct {
	Root string
	Task string                           // this task's id: its own socket dirs are the only ones it may see
	Dial func(network, addr string) error // connects and closes; nil: net.Dial
}

// ProbeError is the first check that failed.
type ProbeError struct{ Check, Detail string }

func (e *ProbeError) Error() string { return ProbeFailed + ": " + e.Check + ": " + e.Detail }

// publicIPs are the addresses the connect check tries: with no route out, each connect gives ENETUNREACH.
var publicIPs = []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"}

// sibling is a host per-task socket dir, relative to /run: /run/agentbox-<svc>/t/<task>.
var sibling = regexp.MustCompile(`^/agentbox-[a-z]+/t/([^/]+)`)

// Run runs every check and returns the first failure, or nil and how long it took.
func (p *Probe) Run() (time.Duration, error) {
	t0 := time.Now()
	for _, c := range []struct {
		name string
		f    func() error
	}{{"netdev", p.netdev}, {"route", p.route}, {"connect", p.connect}, {"resolv", p.resolv},
		{"sibling_socket", p.siblings}, {"abstract_socket", p.abstract}} {
		if err := c.f(); err != nil {
			return time.Since(t0), &ProbeError{c.name, err.Error()}
		}
	}
	return time.Since(t0), nil
}

func (p *Probe) path(s string) string { return filepath.Join(p.Root, s) }

// netdev: lo is the only interface.
func (p *Probe) netdev() error {
	es, err := os.ReadDir(p.path("/sys/class/net"))
	if err != nil {
		return err
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"lo"}) {
		return fmt.Errorf("interfaces %v, want only lo", names)
	}
	return nil
}

// route: no usable default route, IPv4 or IPv6. The kernel's IPv6 null entry is a reject route, so it doesn't count.
func (p *Probe) route() error {
	const up, reject = 0x1, 0x200
	for _, f := range []struct {
		file              string
		dst, plen, flags  int
		zeroDst, zeroPlen string
	}{{"/proc/net/route", 1, 7, 3, "00000000", "00000000"}, {"/proc/net/ipv6_route", 0, 1, 8, strings.Repeat("0", 32), "00"}} {
		b, err := os.ReadFile(p.path(f.file))
		if errors.Is(err, os.ErrNotExist) && f.file == "/proc/net/ipv6_route" {
			continue // IPv6 off
		} else if err != nil {
			return err
		}
		for _, l := range strings.Split(string(b), "\n") {
			x := strings.Fields(l)
			if len(x) <= max(f.dst, f.plen, f.flags) || x[f.dst] != f.zeroDst || x[f.plen] != f.zeroPlen {
				continue
			}
			fl, err := strconv.ParseUint(x[f.flags], 16, 32)
			if err != nil || fl&up != 0 && fl&reject == 0 {
				return fmt.Errorf("a default route in %s: %s", f.file, strings.Join(x, " "))
			}
		}
	}
	return nil
}

// connect: a connect to a public IP fails with ENETUNREACH. With IPv6 off (ipv6.disable=1) there is no AF_INET6, so
// the IPv6 address gives EAFNOSUPPORT, which is no way out either.
func (p *Probe) connect() error {
	dial := p.Dial
	if dial == nil {
		dial = func(network, addr string) error {
			c, err := net.DialTimeout(network, addr, time.Second)
			if err == nil {
				c.Close()
			}
			return err
		}
	}
	for _, a := range publicIPs {
		err := dial("udp", a)
		if a[0] == '[' && errors.Is(err, syscall.EAFNOSUPPORT) {
			continue
		}
		if !errors.Is(err, syscall.ENETUNREACH) {
			return fmt.Errorf("connect %s: %v, want ENETUNREACH", a, err)
		}
	}
	return nil
}

// resolv: /etc/resolv.conf names only 127.0.0.1, where nothing answers.
func (p *Probe) resolv() error {
	b, err := os.ReadFile(p.path("/etc/resolv.conf"))
	if err != nil {
		return err
	}
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if x := strings.Fields(l); len(x) > 0 && x[0] == "nameserver" {
			if len(x) != 2 || x[1] != "127.0.0.1" {
				return fmt.Errorf("resolv.conf: %q", l)
			}
			n++
		}
	}
	if n == 0 {
		return fmt.Errorf("resolv.conf names no nameserver, want 127.0.0.1")
	}
	return nil
}

// siblings: the host's per-task socket dirs give ENOENT, and no mount comes from another task's dir.
func (p *Probe) siblings() error {
	es, err := os.ReadDir(p.path("/run"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range es {
		if strings.HasPrefix(e.Name(), "agentbox-") {
			return fmt.Errorf("/run/%s exists, want ENOENT", e.Name())
		}
	}
	f, err := os.Open(p.path("/proc/self/mountinfo"))
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		x := strings.Fields(s.Text())
		if len(x) < 5 {
			continue
		}
		if m := sibling.FindStringSubmatch(x[3]); m != nil && m[1] != p.Task {
			return fmt.Errorf("%s is mounted from %s", x[4], x[3])
		}
	}
	return s.Err()
}

// abstract: no abstract socket is bound in the task's network namespace. Abstract names are per netns, and nothing in
// the task binds one before the CLI starts, so one here means another netns's sockets, a broker's included, are reachable.
func (p *Probe) abstract() error {
	b, err := os.ReadFile(p.path("/proc/net/unix"))
	if err != nil {
		return err
	}
	for _, l := range strings.Split(string(b), "\n")[1:] {
		if x := strings.Fields(l); len(x) >= 8 && strings.HasPrefix(x[7], "@") {
			return fmt.Errorf("abstract socket %s", x[7])
		}
	}
	return nil
}

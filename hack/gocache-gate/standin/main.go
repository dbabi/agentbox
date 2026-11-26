//go:build linux

// Command standin is hack/gocache-gate.sh's agentbox-proxy until the proxy lands (#17), built for the guest and run as
// agentbox-proxy in a transient agentbox-proxy.service with svc-proxy.sock from systemd. It serves the real Go module
// cache (internal/proxy/gocache) on each task's proxy.sock, tunnels CONNECT proxy.golang.org:443 to the gate's fake
// upstream after the task's taint record, and refuses every other request in the §5.6 CONNECT format. It logs every
// request it gets. Test fixture: never shipped.
//
//	standin serve -upstream 10.0.2.2:7801 -vkey FILE -ca FILE -log FILE [-no-taint] [-hostile]
//	standin btrfs-probe [-no-filter] DIR   BTRFS_IOC_SUBVOL_CREATE on DIR under the service filter, plain and with
//	                                       0xdead00000000 in cmd; prints each errno
//	standin watch DIR SECONDS              counts inotify events on DIR and its subdirs for SECONDS
//
// -no-taint is the test proxy build that writes no taint record (A-G6); -hostile answers every /_cache/ path the cache
// would refuse with forged lists, @latest, .info and checksum data (A-G8 d).
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"agentbox/internal/audit"
	"agentbox/internal/budgets"
	"agentbox/internal/ops"
	"agentbox/internal/proxy/gocache"
	"agentbox/internal/rootd/resolve"
	"agentbox/internal/seccomp"
	"agentbox/internal/taskenv"
)

const (
	proxyDir     = "/run/agentbox-proxy/t"
	auditSock    = "/run/agentbox-audit/proxy.sock"
	rootdSock    = "/run/agentbox-rootd/resolve-proxy.sock"
	cacheRoot    = "/var/lib/agentbox/data/cache"
	subvolCreate = 0x5000940e // BTRFS_IOC_SUBVOL_CREATE
)

func main() {
	log.SetFlags(log.Lmicroseconds)
	if len(os.Args) < 2 {
		log.Fatal("usage: standin serve ... | btrfs-probe [-no-filter] DIR | watch DIR SECONDS")
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "btrfs-probe":
		probe(os.Args[2:])
	case "watch":
		watch(os.Args[2:])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

type standin struct {
	cache            *gocache.Cache
	upstream         string
	noTaint, hostile bool
	logMu            sync.Mutex
	logf             *os.File
	mu               sync.Mutex
	tasks            map[string]*taskSock
}

type taskSock struct {
	agent string
	uid   uint32
	ln    net.Listener
	path  string
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	up := fs.String("upstream", "", "the fake proxy.golang.org, host:port")
	vkey := fs.String("vkey", "", "the checksum database key file")
	ca := fs.String("ca", "", "the upstream's CA, PEM")
	logPath := fs.String("log", "", "the request log")
	noTaint := fs.Bool("no-taint", false, "write no taint record (a broken proxy)")
	hostile := fs.Bool("hostile", false, "forge every /_cache/ reply the cache would refuse")
	fs.Parse(args)
	before, after, err := seccomp.InstallService() // as the proxy will
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("service filter installed: Seccomp_filters %d -> %d", before, after)
	k, err := os.ReadFile(*vkey)
	if err != nil {
		log.Fatal(err)
	}
	pem, err := os.ReadFile(*ca)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatal("no CA in -ca")
	}
	lf, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	s := &standin{upstream: *up, noTaint: *noTaint, hostile: *hostile, logf: lf, tasks: map[string]*taskSock{}}
	b, err := budgets.Read(budgets.Path)
	if err != nil {
		log.Fatal(err)
	}
	lim := gocache.DefaultLimits()
	lim.AgentMaxBytes = b.Get("cache.agent_max_bytes")
	lim.TaskFillMaxBytes = b.Get("cache.task_fill_max_bytes")
	lim.TaskFillMaxFiles = int(b.Get("cache.task_fill_max_files"))
	lim.AgentFillDayBytes = b.Get("cache.agent_fill_day_bytes")
	lim.MaxIdleDays = int(b.Get("cache.max_idle_days"))
	lim.ReserveBytes = b.Get("disk.reserve_bytes")
	s.cache = gocache.New(gocache.Config{Root: cacheRoot, Key: strings.TrimSpace(string(k)), Roots: pool, Limits: lim,
		Upstream: func(ctx context.Context, task string) (net.Conn, error) {
			if !s.live(task) {
				return nil, errors.New("no live task") // the proxy makes no upstream request without one
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", s.upstream)
		},
		Audit: s.audit,
		Alert: func(agent, reason string) {
			if _, err := line(rootdSock, map[string]any{"op": "cache.alert", "agent": agent, "reason": reason}); err != nil {
				log.Printf("cache.alert %s %s: %v", agent, reason, err)
			}
		},
		Allowed: func(agent string) bool {
			l, err := resolve.LoadLists(resolve.EgressDir)
			return err == nil && l.Allowed("proxy", agent, taskenv.GoProxyEntry)
		},
		Private: func(agent string) string { p, _ := taskenv.ReadGoPrivate(resolve.EgressDir, agent); return p },
		Live:    s.live,
	})
	log.Printf("standin: limits %+v, upstream %s, no-taint %v, hostile %v", lim, s.upstream, s.noTaint, s.hostile)
	if err := s.cache.Open(); err != nil { // the start sweep
		log.Printf("cache open: %v", err)
	}
	if rep, err := line(rootdSock, map[string]any{"op": "task.list_live"}); err != nil {
		log.Printf("task.list_live: %v", err)
	} else {
		var r struct {
			Tasks []struct{ Task, Agent string } `json:"tasks"`
		}
		json.Unmarshal(rep, &r)
		for _, t := range r.Tasks {
			if err := s.register(t.Task, t.Agent); err != nil {
				log.Printf("rebind %s: %v", t.Task, err)
			}
		}
	}
	f := os.NewFile(3, "svc-proxy") // systemd-run --socket-property: the one socket, LISTEN_FDS=1
	ln, err := net.FileListener(f)
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go s.control(c)
	}
}

func (s *standin) record(format string, args ...any) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	fmt.Fprintf(s.logf, time.Now().Format("15:04:05.000000")+" "+format+"\n", args...)
}

func (s *standin) audit(rec map[string]any) error {
	if s.noTaint && rec["type"] == "TAINT" {
		return nil // the broken build: an ACK it never asked for
	}
	return audit.Send(auditSock, rec)
}

func (s *standin) live(task string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tasks[task] != nil
}

// control is rootd's svc-proxy.sock: register, revoke and cache.purge, one JSON line each.
func (s *standin) control(c net.Conn) {
	defer c.Close()
	b, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return
	}
	var r struct {
		Call, Task, Agent string
		Chain             []string
	}
	json.Unmarshal(b, &r)
	rep := map[string]any{"ok": true}
	switch r.Call {
	case "register":
		err = s.register(r.Task, r.Agent)
	case "revoke":
		s.revoke(r.Task)
	case "cache.purge":
		err = s.cache.Purge(r.Agent)
		s.record("PURGE %s %v", r.Agent, err)
	default:
		err = fmt.Errorf("unknown call %q", r.Call)
	}
	if err != nil {
		rep = map[string]any{"ok": false, "error": err.Error()}
	}
	out, _ := json.Marshal(rep)
	c.Write(append(out, '\n'))
}

func (s *standin) register(task, agent string) error {
	u, err := user.Lookup("ag-" + agent)
	if err != nil {
		return err
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	p := filepath.Join(proxyDir, task, "proxy.sock")
	os.Remove(p)
	ln, err := net.Listen("unix", p)
	if err != nil {
		return err
	}
	if err := os.Chmod(p, 0o660); err != nil {
		ln.Close()
		return err
	}
	t := &taskSock{agent: agent, uid: uint32(uid), ln: ln, path: p}
	s.mu.Lock()
	s.tasks[task] = t
	s.mu.Unlock()
	s.record("REGISTER %s %s", task, agent)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.conn(task, t, c.(*net.UnixConn))
		}
	}()
	return nil
}

func (s *standin) revoke(task string) {
	s.mu.Lock()
	t := s.tasks[task]
	delete(s.tasks, task)
	s.mu.Unlock()
	if t != nil {
		os.Remove(t.path)
		t.ln.Close()
	}
	s.cache.Revoke(task)
	s.record("REVOKE %s", task)
}

// conn is one request on a task's proxy.sock, from that task's agent uid only.
func (s *standin) conn(task string, t *taskSock, c *net.UnixConn) {
	defer c.Close()
	raw, _ := c.SyscallConn()
	var cred *unix.Ucred
	raw.Control(func(fd uintptr) { cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if cred == nil || cred.Uid != t.uid {
		return
	}
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	s.record("REQ %s %s %s %s", task, t.agent, req.Method, req.RequestURI)
	switch {
	case req.Method == http.MethodConnect:
		s.connect(task, t, c, br, req.RequestURI)
	case strings.HasPrefix(req.RequestURI, "/_cache/"):
		if s.hostile && !strings.HasSuffix(req.RequestURI, ".mod") && !strings.HasSuffix(req.RequestURI, ".zip") {
			forged := `{"Version":"v9.9.9","Time":"1999-01-01T00:00:00Z"}` + "\nv9.9.9\n"
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(forged), forged)
			return
		}
		s.cache.Serve(c, task, t.agent, req)
	default:
		c.Write(ops.ConnectReply(ops.Deny(ops.EgressWrongRoute, "plain_http", ops.Slots{By: "proxy", Expect: "use CONNECT"})))
	}
}

// connect tunnels CONNECT proxy.golang.org:443 to the fake upstream, after the task's taint record; anything else is
// refused as the proxy would.
func (s *standin) connect(task string, t *taskSock, c net.Conn, br *bufio.Reader, target string) {
	e, err := resolve.ParseEntry(target)
	sub := ops.Subject{Host: e.Host, Port: int64(e.Port)}
	l, lerr := resolve.LoadLists(resolve.EgressDir)
	if err != nil || lerr != nil || !l.Allowed("proxy", t.agent, e) {
		what := ""
		if err == nil && (e.Host == "proxy.golang.org" || e.Host == "sum.golang.org") {
			what = "deputy_host"
		}
		c.Write(ops.ConnectReply(ops.Deny(ops.EgressNotAllowlisted, what, ops.Slots{By: "proxy", Subject: sub})))
		return
	}
	if e != taskenv.GoProxyEntry {
		c.Write(ops.ConnectReply(ops.Deny(ops.EgressResolveFailed, "unavailable", ops.Slots{By: "proxy", Subject: sub})))
		return
	}
	if err := s.audit(map[string]any{"type": "TAINT", "subject": "task:" + task, "source": "proxy:" + e.String()}); err != nil {
		c.Write(ops.ConnectReply(ops.Deny(ops.AuditUnavailable, "", ops.Slots{By: "proxy", Subject: sub})))
		return
	}
	up, err := net.DialTimeout("tcp", s.upstream, 10*time.Second)
	if err != nil {
		c.Write(ops.ConnectReply(ops.Deny(ops.EgressDialFailed, "refused", ops.Slots{By: "proxy", Subject: sub})))
		return
	}
	defer up.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	var down atomic.Int64
	done := make(chan struct{})
	go func() { io.Copy(up, br); up.(*net.TCPConn).CloseWrite(); close(done) }()
	n, _ := io.Copy(c, up)
	down.Add(n)
	<-done
	s.record("TUNNEL %s %s down=%d", task, target, down.Load())
}

// line sends one JSON line on a Unix socket and returns the reply line.
func line(sock string, req any) ([]byte, error) {
	c, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	return bufio.NewReader(c).ReadBytes('\n')
}

// probe is A-G13's ioctl: BTRFS_IOC_SUBVOL_CREATE for DIR/probe-sub, under the service filter unless -no-filter.
func probe(args []string) {
	noFilter := len(args) == 2 && args[0] == "-no-filter"
	if noFilter {
		args = args[1:]
	}
	if len(args) != 1 {
		log.Fatal("usage: standin btrfs-probe [-no-filter] DIR")
	}
	if !noFilter {
		if _, _, err := seccomp.InstallService(); err != nil {
			log.Fatal(err)
		}
	}
	d, err := unix.Open(args[0], unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		log.Fatal(err)
	}
	var va [4096]byte // struct btrfs_ioctl_vol_args: fd, then the name
	copy(va[8:], "probe-sub")
	for _, cmd := range []uint64{subvolCreate, 0xdead00000000 | subvolCreate} {
		_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(d), uintptr(cmd), uintptr(unsafe.Pointer(&va[0])))
		name := unix.ErrnoName(e)
		if e == unix.EOPNOTSUPP {
			name = "EOPNOTSUPP" // Linux's ENOTSUP is the same errno
		}
		fmt.Printf("cmd %#x: %s\n", cmd, name)
	}
}

// watch counts inotify events on DIR and its subdirectories for SECONDS (A-G9: agent B's fill touches nothing of A's).
func watch(args []string) {
	if len(args) != 2 {
		log.Fatal("usage: standin watch DIR SECONDS")
	}
	secs, _ := strconv.Atoi(args[1])
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK)
	if err != nil {
		log.Fatal(err)
	}
	filepath.WalkDir(args[0], func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			unix.InotifyAddWatch(fd, p, unix.IN_ALL_EVENTS)
		}
		return nil
	})
	fmt.Println("watching")
	end := time.Now().Add(time.Duration(secs) * time.Second)
	n := 0
	buf := make([]byte, 64<<10)
	for time.Now().Before(end) {
		k, err := unix.Read(fd, buf)
		for off := 0; err == nil && off+unix.SizeofInotifyEvent <= k; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			n++
			off += unix.SizeofInotifyEvent + int(ev.Len)
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Printf("events %d\n", n)
}

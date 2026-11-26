package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"agentbox/internal/audit"
)

const auditDir = "/var/lib/agentbox/audit"

// producers maps each producer socket's name (its FileDescriptorName=) to the user whose uid may use it (§2.1).
var producers = map[string]string{"rootd": "root", "agentboxd": "agentbox", "proxy": "agentbox-proxy", "keys": "agentbox-keys", "git": "agentbox-git"}

func uidOf(name string) (uint32, uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	return uint32(uid), uint32(gid), nil
}

// listenFDs returns systemd's socket-activation listeners by FileDescriptorName (sd_listen_fds).
func listenFDs() (map[string]net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, errors.New("no sockets from systemd (LISTEN_PID): run from its .socket units")
	}
	n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	ls := map[string]net.Listener{}
	for i := 0; i < n; i++ {
		f := os.NewFile(uintptr(3+i), "listen")
		l, err := net.FileListener(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		if i >= len(names) || names[i] == "" {
			return nil, fmt.Errorf("socket fd %d has no FileDescriptorName", 3+i)
		}
		ls[names[i]] = l
	}
	return ls, nil
}

func sdNotify(state string) {
	p := os.Getenv("NOTIFY_SOCKET")
	if p == "" {
		return
	}
	if p[0] == '@' {
		p = "\x00" + p[1:]
	}
	if c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: p, Net: "unixgram"}); err == nil {
		c.Write([]byte(state))
		c.Close()
	}
}

// crashHook is the crash-mid-seal gate's fault injection: AGENTBOX_TEST_CRASH=<point>:<marker> kills the process with
// SIGKILL at <point>, once (the marker file records that it fired). Unset, it does nothing.
func crashHook() func(string) {
	v := os.Getenv("AGENTBOX_TEST_CRASH")
	point, marker, ok := strings.Cut(v, ":")
	if !ok {
		return nil
	}
	return func(p string) {
		if p != point {
			return
		}
		f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		f.Close()
		fmt.Fprintf(os.Stderr, "AGENTBOX_TEST_CRASH: SIGKILL at %s\n", p)
		syscall.Kill(os.Getpid(), syscall.SIGKILL)
		select {}
	}
}

func logf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }

// cmdAuditd is agentbox-auditd.service (§9): the producer sockets come from its .socket units.
func cmdAuditd(args []string) error {
	fs := flag.NewFlagSet("auditd", flag.ContinueOnError)
	dir := fs.String("dir", auditDir, "audit directory (segments, taint.db, .reserve)")
	sealSock := fs.String("seal-socket", "/run/agentbox-rootd/audit-seal.sock", "rootd's audit.create/audit.seal socket")
	segBytes := fs.Int64("segment-bytes", audit.DefaultSegmentBytes, "rotate a segment at this size")
	reserve := fs.Int64("reserve-bytes", audit.DefaultReserveBytes, "size of audit/.reserve")
	if err := parse(fs, args); err != nil {
		return err
	}
	ls, err := listenFDs()
	if err != nil {
		return err
	}
	s := &audit.Server{Dir: *dir, Seal: audit.SealClient{Path: *sealSock}, SegmentBytes: *segBytes, ReserveBytes: *reserve, Logf: logf, Crash: crashHook()}
	type served struct {
		l net.Listener
		p audit.Producer
	}
	var srv []served
	for name, l := range ls {
		uname, ok := producers[name]
		if !ok {
			return fmt.Errorf("socket %q is not a producer socket", name)
		}
		uid, _, err := uidOf(uname)
		if err != nil {
			return fmt.Errorf("producer %s: %w", name, err)
		}
		srv = append(srv, served{l, audit.Producer{Name: name, UID: uid}})
	}
	if err := s.Start(); err != nil {
		return err
	}
	errc := make(chan error, len(srv))
	for _, x := range srv {
		go func() { errc <- s.Serve(x.l, x.p) }()
	}
	sdNotify("READY=1")
	// only now: agentbox-rootd.service starts after auditd, so it stops before auditd and its drained RESULTs get here.
	// The seal work Start left needs rootd; until it is done nothing is ACKed, and each record tries again.
	if err := s.Settle(); err != nil {
		logf("audit: %v; nothing is ACKed until the seal succeeds", err)
	}
	return <-errc
}

func cmdAudit(args []string) error {
	if len(args) == 0 {
		return errors.New("audit: expected verify or send")
	}
	fs := flag.NewFlagSet("audit "+args[0], flag.ContinueOnError)
	switch args[0] {
	case "verify":
		dir := fs.String("dir", auditDir, "audit directory")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		rep, err := audit.VerifyDir(*dir)
		records := 0
		for i, r := range rep {
			records += r.Records
			fmt.Printf("%s: %d records", audit.SegName(r.Seg), r.Records)
			if r.Closed {
				fmt.Print(", closed")
			}
			for _, t := range r.Torn {
				fmt.Printf(", torn bytes %d-%d skipped", t.Offset, t.Offset+t.Len)
			}
			if r.ClockSteps > 0 {
				fmt.Printf(", %d clock_step", r.ClockSteps)
			}
			if r.Undeclared > 0 && i == len(rep)-1 {
				fmt.Printf(", %d trailing bytes not yet marked torn (auditd marks them at its next start)", r.Undeclared)
			}
			fmt.Println()
		}
		if err != nil {
			return fmt.Errorf("audit verify: FAILED: %w", err)
		}
		fmt.Printf("audit verify: OK: %d segments, %d records\n", len(rep), records)
		return nil
	case "send":
		sock := fs.String("socket", "", "producer socket, e.g. /run/agentbox-audit/rootd.sock")
		timeout := fs.Duration("timeout", 10*time.Second, "give up on a reply after this long")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		if *sock == "" || fs.NArg() == 0 {
			return errors.New("audit send: --socket and at least one JSON record are required")
		}
		return auditSend(*sock, *timeout, fs.Args())
	}
	return fmt.Errorf("audit: unknown subcommand %q", args[0])
}

// auditSend is a producer: it sends each record and waits for its reply, which it prints. It fails unless every reply
// is an ACK, so `agentbox audit send ... && <effect>` runs the effect only after a durable ACK.
func auditSend(sock string, timeout time.Duration, recs []string) error {
	c, err := net.DialTimeout("unix", sock, timeout)
	if err != nil {
		return fmt.Errorf("%s: %w", audit.CodeUnavailable, err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	for _, r := range recs {
		c.SetDeadline(time.Now().Add(timeout))
		if _, err := c.Write([]byte(strings.TrimSpace(r) + "\n")); err != nil {
			return fmt.Errorf("%s: %w", audit.CodeUnavailable, err)
		}
		line, err := br.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("%s: no reply: %w", audit.CodeUnavailable, err)
		}
		os.Stdout.Write(line)
		var rep audit.Reply
		if err := json.Unmarshal(line, &rep); err != nil || !rep.OK {
			return fmt.Errorf("NACK: %s", strings.TrimSpace(string(line)))
		}
	}
	return nil
}

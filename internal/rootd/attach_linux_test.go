package rootd

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/rootd/attach"
)

// fakeRunner stands in for the container: it is the session, writing to and reading from the PTY slave rootd made.
type fakeRunner struct {
	run     func(s attach.Session) error
	stopped []string
}

func (f *fakeRunner) Run(_ context.Context, s attach.Session) error { return f.run(s) }
func (f *fakeRunner) Stop(_, id string) error                       { f.stopped = append(f.stopped, id); return nil }

const leaked = "gate-oauth-at-gate-FFFFFFFFFFFFFFFFFFFFFFFF"

// §4.2: the session's output reaches the admin filtered, input reaches the session, the session is a tainted writer
// of its workspace for exactly its lifetime, and a token it wrote into the workspace leaves tasks blocked and alerts,
// even after the CLI rotated it.
func TestAttach(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	root := t.TempDir()
	db, err := OpenDB(filepath.Join(root, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	lookupAgent = func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }
	p := attach.AgentPaths(root, "at", "x")
	os.MkdirAll(p.Workspace, 0o755)
	os.MkdirAll(filepath.Join(p.SessionHome, ".claude"), 0o700)
	writeCreds := func(tok string) {
		os.WriteFile(filepath.Join(p.SessionHome, ".claude", ".credentials.json"), []byte(`{"claudeAiOauth":{"accessToken":"`+tok+`"}}`), 0o600)
	}
	writeCreds(leaked)
	var mu sync.Mutex
	var recs []string
	var alerts []string
	fr := &fakeRunner{}
	s := &server{db: db, cfg: Config{AttachRoot: root, Attach: fr, Alert: func(_, m string) error { alerts = append(alerts, m); return nil }},
		audit: func(r map[string]any) error {
			mu.Lock()
			defer mu.Unlock()
			b, _ := json.Marshal(r)
			recs = append(recs, string(b))
			return nil
		}}
	fr.run = func(sess attach.Session) error {
		if b, ok, _ := attach.Blocked(db, "at"); !ok || b.Reason != attach.Live {
			t.Error("tasks must be blocked while the attach is live")
		}
		tty, err := os.OpenFile(sess.TTY, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer tty.Close()
		tty.Write([]byte("hello \x1b]52;c;ZXZpbA==\x07\x1b[6n\x1bPq\x1b\\world\r\n"))
		line, _ := bufio.NewReader(tty).ReadString('\n')
		tty.Write([]byte("got " + strings.TrimSpace(line) + "\r\n"))
		os.WriteFile(filepath.Join(p.Workspace, "notes.md"), []byte("token: "+leaked+"\n"), 0o644)
		writeCreds("gate-oauth-at-rotated-GGGGGGGGGGGGGGGGGGGGG") // the CLI refreshed: the old one is still a hit
		return nil
	}
	cli, srv := pair(t)
	done := make(chan struct{})
	go func() {
		s.attach(srv, request{Op: "agent.attach", Name: "at", CLI: "bash"}, []byte("typed input\n"))
		close(done)
	}()
	out, _ := io.ReadAll(cli)
	cli.CloseWrite()
	<-done
	got := string(out)
	for _, want := range []string{`"ok":true`, "hello world", "got typed input", "tasks blocked"} {
		if !strings.Contains(got, want) {
			t.Errorf("admin output lacks %q:\n%q", want, got)
		}
	}
	for _, bad := range []string{"ZXZpbA", "\x1b]", "\x1b[6n", "\x1bP"} {
		if strings.Contains(got, bad) {
			t.Errorf("admin output has %q", bad)
		}
	}
	if b, ok, _ := attach.Blocked(db, "at"); !ok || b.Reason != attach.Token || b.Detail != "notes.md" {
		t.Fatalf("block %+v %v", b, ok)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts %q", alerts)
	}
	var types []string
	for _, r := range recs {
		var m map[string]any
		json.Unmarshal([]byte(r), &m)
		types = append(types, m["type"].(string))
		if strings.Contains(r, leaked) {
			t.Fatalf("a token reached audit: %s", r)
		}
	}
	if strings.Join(types, " ") != "INTENT WRITER_ADD TAINT WRITER_DEL RESULT" {
		t.Fatalf("audit %q", recs)
	}
	if _, err := os.Stat(filepath.Join(root, "control", "attach")); err == nil {
		if ents, _ := os.ReadDir(filepath.Join(root, "control", "attach")); len(ents) != 0 {
			t.Fatalf("session dirs left: %v", ents)
		}
	}

	// a second attach is refused while the block stands; rescan keeps it until the token is gone
	cli, srv = pair(t)
	go s.attach(srv, request{Op: "agent.attach", Name: "at"}, nil)
	if l, _ := bufio.NewReader(cli).ReadString('\n'); !strings.Contains(l, `"ok":false`) {
		t.Fatalf("attach over a block: %s", l)
	}
	writeCreds(leaked) // the admin's session-home still holds it, or the admin re-logged with it
	if rep := s.rescan("at", false); rep["blocked"] != true {
		t.Fatalf("rescan with the token still there: %v", rep)
	}
	os.Remove(filepath.Join(p.Workspace, "notes.md"))
	if rep := s.rescan("at", false); rep["ok"] != true || rep["blocked"] != false {
		t.Fatalf("rescan after removal: %v", rep)
	}
	if _, ok, _ := attach.Blocked(db, "at"); ok {
		t.Fatal("still blocked")
	}

	// rootd stopped mid-attach: a restarted rootd lost the session's token versions, so a clean rescan keeps the block
	// until the admin acks it
	attach.Begin(db, "at", "ses_old", time.Now())
	s2 := &server{db: db, cfg: s.cfg, audit: s.audit}
	if rep := s2.rescan("at", false); rep["blocked"] != true || !strings.Contains(rep["error"].(string), "--ack-restart") {
		t.Fatalf("clean rescan after a restart: %v", rep)
	}
	if rep := s2.rescan("at", true); rep["blocked"] != false {
		t.Fatalf("rescan --ack-restart: %v", rep)
	}

	// the control-path gate: a planted .mcp.json refuses the attach, with no block left, until --ack-control-changes
	// quotes the digest of that list (#210): a change made after the refusal needs a new one
	refused := func(ack string) (line, digest string) {
		t.Helper()
		cli, srv := pair(t)
		go s.attach(srv, request{Op: "agent.attach", Name: "at", CLI: "bash", AckControlChanges: ack}, nil)
		l, _ := bufio.NewReader(cli).ReadString('\n')
		if !strings.Contains(l, "control paths changed") || !strings.Contains(l, ".mcp.json") {
			t.Fatalf("attach, ack %q: %s", ack, l)
		}
		if _, ok, _ := attach.Blocked(db, "at"); ok {
			t.Fatal("a refused attach left a block")
		}
		_, d, _ := strings.Cut(l, "--ack-control-changes=")
		return l, d[:min(len(d), 64)]
	}
	os.WriteFile(filepath.Join(p.Workspace, ".mcp.json"), []byte(`{"mcpServers":{}}`), 0o644)
	_, d := refused("")
	os.WriteFile(filepath.Join(p.Workspace, "AGENTS.md"), []byte("planted after the refusal"), 0o644)
	l, d2 := refused(d)
	if d2 == d || len(d2) != 64 || !strings.Contains(l, "AGENTS.md") || !strings.Contains(l, "digest does not match this list") {
		t.Fatalf("a change after the refusal, acked with the old digest %s: %s", d, l)
	}
	d = d2
	fr.run = func(attach.Session) error { return nil }
	for _, ack := range []string{d, ""} { // acked once, the next attach needs no flag
		cli, srv = pair(t)
		go s.attach(srv, request{Op: "agent.attach", Name: "at", CLI: "bash", AckControlChanges: ack}, nil)
		if l, _ := bufio.NewReader(cli).ReadString('\n'); !strings.Contains(l, `"ok":true`) {
			t.Fatalf("attach, ack %q: %s", ack, l)
		}
		io.ReadAll(cli)
		for i := 0; i < 100; i++ {
			if _, ok, _ := attach.Blocked(db, "at"); !ok {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// auditd down: no session, no block left behind
	s.audit = func(map[string]any) error { return io.ErrUnexpectedEOF }
	cli, srv = pair(t)
	go s.attach(srv, request{Op: "agent.attach", Name: "at"}, nil)
	if l, _ := bufio.NewReader(cli).ReadString('\n'); !strings.Contains(l, "INTENT was not ACKed") {
		t.Fatalf("auditd down: %s", l)
	}
	if _, ok, _ := attach.Blocked(db, "at"); ok {
		t.Fatal("a refused attach left a block")
	}
}

func pair(t *testing.T) (cli, srv *net.UnixConn) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	t.Cleanup(func() { c.Close(); sc.Close() })
	return c, sc
}

// #79: while the qgroup fence is up, agent.attach is refused BUSY before any session starts.
func TestAttachFenced(t *testing.T) {
	fr := &fakeRunner{run: func(attach.Session) error { t.Error("an attach ran while fenced"); return nil }}
	s := &server{cfg: Config{Attach: fr}}
	s.fenced.Store(true)
	cli, srv := pair(t)
	go func() { s.attach(srv, request{Op: "agent.attach", Name: "at", CLI: "bash"}, nil); srv.Close() }()
	out, _ := io.ReadAll(cli)
	if !strings.Contains(string(out), `"code":"BUSY"`) || !strings.Contains(string(out), `"ok":false`) {
		t.Fatalf("got %s", out)
	}
}

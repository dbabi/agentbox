package git

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/broker"
	"agentbox/internal/ids"
)

// A write whose request left but whose outcome GitHub didn't settle is unknown (#316): a 502, a timeout or a reset
// after the request was sent, and a 201 whose body doesn't read. One that never left (a refused dial, no token), a 4xx
// and any read are not: rootd records those as failed and reconciles only the unknown.
func TestGitHubUnknown(t *testing.T) {
	ctx := context.Background()
	mode := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		switch mode {
		case "502":
			w.WriteHeader(502)
		case "422":
			w.WriteHeader(422)
			io.WriteString(w, `{"message":"Validation Failed"}`)
		case "reset": // the request came; the connection goes before any answer
			c, _, _ := http.NewResponseController(w).Hijack()
			c.Close()
		case "short201": // GitHub stored it, and the reply body is cut
			c, _, _ := http.NewResponseController(w).Hijack()
			fmt.Fprintf(c, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"id\":1")
			c.Close()
		case "html201":
			w.WriteHeader(201)
			io.WriteString(w, "<html>")
		case "slow":
			time.Sleep(300 * time.Millisecond)
			w.WriteHeader(201)
		}
	}))
	t.Cleanup(srv.Close)
	g := &GitHub{API: srv.URL, HTTP: &http.Client{Timeout: 100 * time.Millisecond}, Token: func() (string, error) { return "tok", nil }}
	for _, c := range []struct {
		mode    string
		unknown bool
	}{{"502", true}, {"reset", true}, {"short201", true}, {"html201", true}, {"slow", true}, {"422", false}} {
		mode = c.mode
		_, err := g.Comment(ctx, "acme", "app", 7, "hello")
		var ae *APIError
		if !errors.As(err, &ae) || ae.Unknown != c.unknown {
			t.Errorf("POST, %s: %+v", c.mode, err)
		}
		if r := refused(err); (r["unknown"] == true) != c.unknown {
			t.Errorf("POST, %s: exec answers %v", c.mode, r)
		}
		if _, err := g.Repo(ctx, "acme", "app"); errors.As(err, &ae) && ae.Unknown {
			t.Errorf("GET, %s: a read is never unknown: %+v", c.mode, ae)
		}
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close() // nothing listens: the request never leaves
	g.API = dead.URL
	var ae *APIError
	if _, err := g.Comment(ctx, "acme", "app", 7, "hello"); !errors.As(err, &ae) || ae.What != "unreachable" || ae.Unknown {
		t.Errorf("a refused dial: %+v", err)
	}
	g.Token = func() (string, error) { return "", errNoToken }
	if _, err := g.Comment(ctx, "acme", "app", 7, "hello"); !errors.As(err, &ae) || ae.Unknown {
		t.Errorf("no token: %+v", err)
	}
}

// regTask registers a task the way rootd does and returns its git.sock, served through internal/broker's admission.
func regTask(t *testing.T, b *httpBox) (string, string) {
	t.Helper()
	b.s.AgentIDs = func(string) (uint32, uint32, error) { return uint32(os.Getuid()), uint32(os.Getgid()), nil }
	b.s.Peer = func(net.Conn) (uint32, error) { return uint32(os.Getuid()), nil }
	b.s.adm.Peer = b.s.Peer
	id := ids.New(ids.Task)
	dir := filepath.Join(b.s.TaskDir, "t", id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	os.Chown(dir, -1, os.Getgid())
	os.Chmod(dir, 0o750|os.ModeSetgid)
	l, _ := json.Marshal(map[string]any{"call": "register", "task": id, "agent": "claude"})
	if r := b.s.Control(l); r["ok"] != true {
		t.Fatalf("register: %v", r)
	}
	t.Cleanup(func() { b.s.revoke(id) })
	return id, filepath.Join(dir, "git.sock")
}

// denialOf reads a raw reply's status and its CAP_REACHED what, from the git text body.
func denialOf(t *testing.T, c net.Conn) (int, string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(broker.BodyGrace + 10*time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(b), "agentbox CAP_REACHED: ") {
		return resp.StatusCode, ""
	}
	var d struct{ What string }
	json.Unmarshal([]byte(strings.TrimPrefix(strings.Split(string(b), "\n")[1], "agentbox-denial/v1 ")), &d)
	return resp.StatusCode, d.What
}

// git.sock has the brokers' admission (#316): past broker.DefaultConns connections the next gets
// CAP_REACHED{connections} in git's text format; a chunked POST that stops sending gets CAP_REACHED{read_timeout}
// after broker.BodyGrace, and leaves no spool file.
func TestSocketAdmission(t *testing.T) {
	b := newHTTPBox(t)
	_, sock := regTask(t, b)
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for range broker.DefaultConns {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	time.Sleep(100 * time.Millisecond)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if st, what := denialOf(t, c); st != 429 || what != "connections" {
		t.Errorf("connection %d: %d %q", broker.DefaultConns+1, st, what)
	}
	c.Close()
	for _, c := range held {
		c.Close()
	}
	held = nil
	time.Sleep(100 * time.Millisecond)

	c, err = net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t0 := time.Now()
	io.WriteString(c, "POST /app/git-receive-pack HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-git-receive-pack-request\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
	spool := filepath.Join(b.s.Root, ".spool")
	for i := 0; i < 100; i++ {
		if l, _ := os.ReadDir(spool); len(l) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if l, _ := os.ReadDir(spool); len(l) != 1 {
		t.Errorf("the body is not spooling: %v", l)
	}
	if st, what := denialOf(t, c); st != 408 || what != "read_timeout" || time.Since(t0) < broker.BodyGrace {
		t.Errorf("a stalled chunked push: %d %q after %v", st, what, time.Since(t0))
	}
	if l, _ := os.ReadDir(spool); len(l) != 0 {
		t.Errorf("spool files left: %v", l)
	}
}

package git

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"agentbox/internal/canary"
	"agentbox/internal/ids"
)

func backend(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
}

type httpBox struct {
	s           *Server
	t           *task
	url         string
	audit, rd   *fake
	c           string
	taintedPush bool
}

func newHTTPBox(t *testing.T) *httpBox {
	t.Helper()
	b := &httpBox{c: canary.Mint()}
	b.audit = newFake(t, "audit.sock", ack)
	b.rd = newFake(t, "rootd.sock", func(m map[string]any) map[string]any {
		return map[string]any{"ok": true, "tainted": b.taintedPush}
	})
	b.s = &Server{Root: t.TempDir(), TaskDir: shortDir(t), Hooks: hooksDir(t), Backend: backend(t), Audit: Auditor{b.audit.path},
		Rootd: Rootd{b.rd.path}, Budgets: filepath.Join(t.TempDir(), "budgets.toml"), Peer: func(net.Conn) (uint32, error) { return 0, nil }}
	if err := b.s.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.s.store.Close() })
	b.t = &task{id: ids.New(ids.Task), agent: "claude", canary: b.c}
	b.s.tasks[b.t.id] = b.t
	srv := httptest.NewServer(b.s.handler(b.t))
	t.Cleanup(srv.Close)
	b.url = srv.URL
	for _, p := range [][2]string{{"claude", "app"}, {"other", "secret"}} {
		if err := CreateRepo(b.s.Root, p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

var reID = regexp.MustCompile(`dn_[0-9A-Z]{26}`)

// The git 404 floor (C-G4): a missing repo and another agent's give the same text/plain body apart from the id, both
// 200 ms or more after receipt.
func TestServe404Floor(t *testing.T) {
	b := newHTTPBox(t)
	var bodies []string
	for _, p := range []string{"/nosuch/info/refs?service=git-upload-pack", "/secret/info/refs?service=git-upload-pack", "/app/HEAD",
		"/app/objects/info/packs", "/app/info/refs", "/../other/secret.git/info/refs?service=git-upload-pack"} {
		t0 := time.Now()
		resp, err := httpGet(b.url + p)
		if err != nil {
			t.Fatal(err)
		}
		d := time.Since(t0)
		if resp.status != 404 || resp.ctype != "text/plain; charset=utf-8" || d < 200*time.Millisecond {
			t.Fatalf("%s: %d %q after %v", p, resp.status, resp.ctype, d)
		}
		bodies = append(bodies, reID.ReplaceAllString(resp.body, "dn_X"))
	}
	for _, x := range bodies[1:] {
		if x != bodies[0] {
			t.Fatalf("404 bodies differ:\n%s\n%s", bodies[0], x)
		}
	}
	if !strings.HasPrefix(bodies[0], "agentbox NOT_FOUND_OR_NOT_OWNED: ") || !strings.Contains(bodies[0], "\nagentbox-denial/v1 {") {
		t.Fatalf("body %q", bodies[0])
	}
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

type resp struct {
	status      int
	ctype, body string
}

func httpGet(u string) (resp, error) {
	r, err := httpClient.Get(u)
	if err != nil {
		return resp{}, err
	}
	defer r.Body.Close()
	var b bytes.Buffer
	b.ReadFrom(r.Body)
	return resp{r.StatusCode, r.Header.Get("Content-Type"), b.String()}, nil
}

// A push and a fetch through http-backend: the hook runs on the push, and a fetch that may deliver a tainted ref gets
// read taint first; one that wants only clean tips doesn't.
func TestServePushFetchTaint(t *testing.T) {
	b := newHTTPBox(t)
	w := work(t, "a.txt", "a\n")
	env := []string{"GIT_TERMINAL_PROMPT=0"}
	if out, err := gitTry(w, env, "push", b.url+"/app", "HEAD:refs/heads/agent/claude/x"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	if out, err := gitTry(w, env, "push", b.url+"/app.git", "HEAD:refs/heads/main"); err == nil || !strings.Contains(out, "REF_OUTSIDE_NAMESPACE") {
		t.Fatalf("push to main: %v\n%s", err, out)
	}
	// the canary in a push over smart HTTP: refused, canary.hit to rootd
	w2 := work(t, "k.txt", "key "+b.c+"\n")
	if out, err := gitTry(w2, env, "push", b.url+"/app", "HEAD:refs/heads/agent/claude/k"); err == nil || !strings.Contains(out, "remote: agentbox EXFIL_CANARY") {
		t.Fatalf("canary push: %v\n%s", err, out)
	}
	if len(b.rd.seen("op", "canary.hit")) != 1 {
		t.Fatal("rootd heard no canary hit")
	}
	// a tainted task's push taints its ref
	b.taintedPush = true
	commit(t, w, "b.txt", "b\n")
	if out, err := gitTry(w, env, "push", b.url+"/app", "HEAD:refs/heads/agent/claude/t"); err != nil {
		t.Fatalf("tainted push: %v\n%s", err, out)
	}
	if refs, _ := taintedRefs(b.s.store, "claude/app"); fmt.Sprint(refs) != "[refs/heads/agent/claude/t]" {
		t.Fatalf("tainted refs %v", refs)
	}
	// a clone wants every tip, the tainted one too: one READ_INTENT for it, before the pack
	c := t.TempDir()
	if out, err := gitTry(c, env, "clone", "-q", b.url+"/app", "x"); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	ri := b.audit.seen("type", "READ_INTENT")
	if len(ri) != 1 || ri[0]["reader"] != "task:"+b.t.id || ri[0]["source"] != "ref:claude/app:refs/heads/agent/claude/t" {
		t.Fatalf("READ_INTENT %v", ri)
	}
	// fetching only the clean branch needs no read taint
	if out, err := gitTry(filepath.Join(c, "x"), env, "fetch", "-q", "origin", "refs/heads/agent/claude/x"); err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	if n := len(b.audit.seen("type", "READ_INTENT")); n != 1 {
		t.Fatalf("a clean fetch sent READ_INTENT (%d)", n)
	}
	// auditd down: a fetch that needs read taint fails closed
	b.audit.reply = func(map[string]any) map[string]any { return map[string]any{"ok": false, "code": "AUDIT_UNAVAILABLE"} }
	if out, err := gitTry(t.TempDir(), env, "clone", "-q", b.url+"/app", "y"); err == nil || !strings.Contains(out, "503") {
		t.Fatalf("clone with auditd down: %v\n%s", err, out)
	}
}

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func TestWants(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	v0 := pkt("want "+a+" multi_ack side-band-64k\n") + pkt("want "+b+"\n") + "0000" + pkt("done\n")
	v2 := pkt("command=fetch\n") + pkt("agent=git/2\n") + "0001" + pkt("thin-pack\n") + pkt("want "+a+"\n") + pkt("done\n") + "0000"
	for name, body := range map[string]string{"v0": v0, "v2": v2} {
		w, ok := Wants([]byte(body), "")
		if !ok || len(w) < 1 || w[0] != a {
			t.Errorf("%s: %v %v", name, w, ok)
		}
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write([]byte(v0))
	zw.Close()
	if w, ok := Wants(z.Bytes(), "gzip"); !ok || len(w) != 2 {
		t.Errorf("gzip: %v %v", w, ok)
	}
	for name, body := range map[string]string{"want-ref": pkt("want-ref refs/heads/main\n"), "short": "00", "bad length": "zzzzwant",
		"bad oid": pkt("want 1234\n"), "over": "00ffwant"} {
		if _, ok := Wants([]byte(body), ""); ok {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, ok := Wants([]byte(v0), "br"); ok {
		t.Error("an unknown encoding parsed")
	}
}

// The control socket's register refuses a dir rootd didn't make, and a bad canary.
func TestRegisterChecks(t *testing.T) {
	b := newHTTPBox(t)
	b.s.AgentIDs = func(string) (uint32, uint32, error) { return uint32(os.Getuid()), uint32(os.Getgid()), nil }
	id := ids.New(ids.Task)
	dir := filepath.Join(b.s.TaskDir, "t", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	line := func(m map[string]any) map[string]any { l, _ := json.Marshal(m); return b.s.Control(l) }
	if r := line(map[string]any{"call": "register", "task": id, "agent": "claude"}); r["ok"] == true {
		t.Fatal("registered in a 0755 dir")
	}
	os.Chown(dir, -1, os.Getgid()) // macOS gives a new dir its parent's group
	os.Chmod(dir, 0o750|os.ModeSetgid)
	if r := line(map[string]any{"call": "register", "task": id, "agent": "claude", "canary": canary.Prefix + "x"}); r["ok"] == true {
		t.Fatal("registered with a malformed canary")
	}
	c := canary.Mint()
	if r := line(map[string]any{"call": "register", "task": id, "agent": "claude", "canary": c, "chain": []string{"human:x"},
		"trace": ids.New(ids.Trace)}); r["ok"] != true {
		t.Fatalf("register: %v", r)
	}
	// the service's rebind can take a task before rootd's own register of it arrives: the same one again is a no-op
	if r := line(map[string]any{"call": "register", "task": id, "agent": "claude", "canary": c}); r["ok"] != true {
		t.Fatalf("the same registration again: %v", r)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "git.sock")); err != nil || fi.Mode()&0o777 != 0o660 {
		t.Fatalf("git.sock %v %v", fi, err)
	}
	if r := line(map[string]any{"call": "register", "task": id, "agent": "claude"}); r["ok"] == true {
		t.Fatal("registered again with another canary")
	}
	if r := line(map[string]any{"call": "revoke", "task": id}); r["revoked"] != true {
		t.Fatalf("revoke: %v", r)
	}
	if _, err := os.Lstat(filepath.Join(dir, "git.sock")); !os.IsNotExist(err) {
		t.Fatal("revoke left the socket")
	}
	if r := line(map[string]any{"call": "nope", "extra": 1}); r["ok"] == true {
		t.Fatal("an unknown field was accepted")
	}
}

// A push over git's http.postBuffer goes out chunked, with no Content-Length: http-backend still gets all of it, and
// the hook sizes it from the quarantine.
func TestServeChunkedPush(t *testing.T) {
	b := newHTTPBox(t)
	big := make([]byte, 3<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	w := work(t, "big.bin", string(big))
	if out, err := gitTry(w, []string{"GIT_TERMINAL_PROMPT=0"}, "-c", "http.postBuffer=65536", "push", b.url+"/app", "HEAD:refs/heads/agent/claude/big"); err != nil {
		t.Fatalf("chunked push: %v\n%s", err, out)
	}
	if got := gitIn(t, Repo(b.s.Root, "claude", "app"), "rev-parse", "refs/heads/agent/claude/big"); got != gitIn(t, w, "rev-parse", "HEAD") {
		t.Fatalf("pushed %s", got)
	}
	var n int64
	b.s.store.QueryRow(`SELECT bytes FROM push_days WHERE agent='claude'`).Scan(&n)
	if n < 3<<20 {
		t.Fatalf("day total %d, want the 3 MiB pack counted", n)
	}
}

// The day cap is budgets.toml's git.push_bytes_day, read at each push: a budget.set applies to the next push, and a
// budgets.toml that doesn't parse refuses the push before git stores any of it.
func TestServeDayCapFromBudgets(t *testing.T) {
	b := newHTTPBox(t)
	env := []string{"GIT_TERMINAL_PROMPT=0"}
	w := work(t, "a.txt", "a\n")
	if out, err := gitTry(w, env, "push", b.url+"/app", "HEAD:refs/heads/agent/claude/a"); err != nil {
		t.Fatalf("push under the default cap: %v\n%s", err, out)
	}
	if err := os.WriteFile(b.s.Budgets, []byte("git.push_bytes_day = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commit(t, w, "b.txt", "b\n")
	out, err := gitTry(w, env, "push", b.url+"/app", "HEAD:refs/heads/agent/claude/b")
	if err == nil || !strings.Contains(out, "remote: agentbox CAP_REACHED") || !strings.Contains(out, `"what":"push_bytes_day"`) || !strings.Contains(out, `"limit":1,`) {
		t.Fatalf("push over a 1-byte cap: %v\n%s", err, out)
	}
	os.WriteFile(b.s.Budgets, []byte("git.push_bytes_day = -1\n"), 0o644)
	if out, err := gitTry(w, env, "push", b.url+"/app", "HEAD:refs/heads/agent/claude/c"); err == nil || !strings.Contains(out, "500") {
		t.Fatalf("push with a bad budgets.toml: %v\n%s", err, out)
	}
	for _, r := range []string{"refs/heads/agent/claude/b", "refs/heads/agent/claude/c"} {
		if _, err := gitTry(Repo(b.s.Root, "claude", "app"), nil, "rev-parse", "-q", "--verify", r); err == nil {
			t.Fatalf("%s was stored", r)
		}
	}
}

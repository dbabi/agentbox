package git

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/canary"
	"agentbox/internal/ids"
)

type pushBox struct {
	root, bare, hooks, req string
	rootd, audit           *fake
	tainted                bool
}

func newPushBox(t *testing.T, dayCap int64, c string) *pushBox {
	t.Helper()
	b := &pushBox{root: t.TempDir(), hooks: hooksDir(t)}
	if err := CreateRepo(b.root, "claude", "app"); err != nil {
		t.Fatal(err)
	}
	b.bare = Repo(b.root, "claude", "app")
	// in the repo's own config: a local push clears GIT_CONFIG_* for receive-pack (git's local_repo_env), which the
	// service's http-backend path doesn't
	gitIn(t, b.bare, "config", "core.hooksPath", b.hooks)
	b.rootd = newFake(t, "rootd.sock", func(m map[string]any) map[string]any {
		if m["op"] == "push.report" {
			return map[string]any{"ok": true, "tainted": b.tainted}
		}
		return map[string]any{"ok": true}
	})
	b.audit = newFake(t, "audit.sock", ack)
	req, _ := json.Marshal(HookRequest{Task: ids.New(ids.Task), Agent: "claude", Project: "app", Canary: c, DayCap: dayCap, Store: b.root,
		Resolve: b.rootd.path, Audit: b.audit.path})
	b.req = filepath.Join(t.TempDir(), "push.json")
	if err := os.WriteFile(b.req, req, 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

// push pushes HEAD of dir to ref of the box's bare repo, with the hook in place, as the service runs receive-pack.
func (b *pushBox) push(dir, ref string) (string, error) {
	return gitTry(dir, []string{HookEnv + "=" + b.req}, "push", b.bare, "HEAD:"+ref)
}

func (b *pushBox) has(t *testing.T, oid string) bool {
	t.Helper()
	_, err := gitTry(b.bare, nil, "cat-file", "-e", oid)
	return err == nil
}

func TestHookNamespaceAndCanary(t *testing.T) {
	c := canary.Mint()
	b := newPushBox(t, DayPushBytes, c)
	netrc := "machine github.com\n  login x\n  password " + c + "\n"
	for name, body := range map[string]string{
		"in a file":   "token = " + c + "\n",
		"base64":      base64.StdEncoding.EncodeToString([]byte(netrc)) + "\n",
		"split lines": "a = '" + c[:50] + "'\n  '" + c[50:] + "'\n",
	} {
		w := work(t, "f.txt", body)
		head := gitIn(t, w, "rev-parse", "HEAD")
		out, err := b.push(w, "refs/heads/agent/claude/x")
		if err == nil || !strings.Contains(out, "remote: agentbox EXFIL_CANARY: ") || !strings.Contains(out, "remote: agentbox-denial/v1 {") {
			t.Fatalf("%s: push with the canary: %v\n%s", name, err, out)
		}
		if b.has(t, head) {
			t.Fatalf("%s: the refused push's commit was stored", name)
		}
		if strings.Contains(out, c) || strings.Contains(out, c[:40]) {
			t.Fatalf("%s: the denial echoes the canary", name)
		}
	}
	// the canary counts first: a push of it to main is an exfiltration attempt, not only a namespace mistake
	wm := work(t, "m.txt", "key: "+c+"\n")
	if out, err := b.push(wm, "refs/heads/main"); err == nil || !strings.Contains(out, "remote: agentbox EXFIL_CANARY: ") {
		t.Fatalf("canary to main: %v\n%s", err, out)
	}
	if n := len(b.rootd.seen("op", "canary.hit")); n != 4 {
		t.Fatalf("rootd heard %d canary hits, want 4", n)
	}
	if n := len(b.audit.seen("code", "EXFIL_CANARY")); n != 4 {
		t.Fatalf("auditd got %d EXFIL_CANARY DENY records, want 4", n)
	}
	// outside the namespace: the two §5.6 lines, nothing stored
	w := work(t, "ok.txt", "clean\n")
	head := gitIn(t, w, "rev-parse", "HEAD")
	for _, ref := range []string{"refs/heads/main", "refs/heads/agent/other/x", "refs/tags/v1", "refs/heads/agent/claude", "refs/heads/agent/claudex/y"} {
		out, err := b.push(w, ref)
		if err == nil || !strings.Contains(out, "remote: agentbox REF_OUTSIDE_NAMESPACE: ") || !strings.Contains(out, `"expect":"refs/heads/agent/\u003cname\u003e/*"`) {
			t.Fatalf("push to %s: %v\n%s", ref, err, out)
		}
	}
	if b.has(t, head) {
		t.Fatal("a refused push's commit was stored")
	}
	// a clean push succeeds, and rootd heard it with its ref
	if out, err := b.push(w, "refs/heads/agent/claude/x"); err != nil {
		t.Fatalf("clean push: %v\n%s", err, out)
	}
	if !b.has(t, head) || gitIn(t, b.bare, "rev-parse", "refs/heads/agent/claude/x") != head {
		t.Fatal("the clean push did not land")
	}
	rep := b.rootd.seen("op", "push.report")
	if len(rep) != 1 || fmt.Sprint(rep[0]["refs"]) != "[refs/heads/agent/claude/x]" || rep[0]["repo"] != "claude/app" {
		t.Fatalf("push.report: %v", rep)
	}
}

func TestHookDayCap(t *testing.T) {
	b := newPushBox(t, 200, "")
	w := work(t, "big.bin", strings.Repeat("0123456789abcdef", 4096)) // the pack is well over 200 bytes
	head := gitIn(t, w, "rev-parse", "HEAD")
	out, err := b.push(w, "refs/heads/agent/claude/big")
	if err == nil || !strings.Contains(out, "remote: agentbox CAP_REACHED: ") || !strings.Contains(out, `"what":"push_bytes_day"`) ||
		!strings.Contains(out, `"limit":200`) || !strings.Contains(out, `"resetsAt":`) {
		t.Fatalf("over the cap: %v\n%s", err, out)
	}
	if b.has(t, head) {
		t.Fatal("the pack over the cap was stored")
	}
	db, err := OpenStore(b.root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// a push that fits is counted
	b2 := newPushBox(t, DayPushBytes, "")
	w2 := work(t, "a.txt", "a\n")
	if out, err := b2.push(w2, "refs/heads/agent/claude/a"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	db2, _ := OpenStore(b2.root)
	defer db2.Close()
	var n int64
	if err := db2.QueryRow(`SELECT bytes FROM push_days WHERE agent='claude'`).Scan(&n); err != nil || n <= 0 {
		t.Fatalf("day total %d %v", n, err)
	}
}

func TestHookTaintAndSecrets(t *testing.T) {
	b := newPushBox(t, DayPushBytes, canary.Mint())
	b.tainted = true
	pat := "ghp_" + strings.Repeat("aB3dE6gH9k", 3) + "mN0pQr" // a real-looking token, built at run time
	w := work(t, "cfg.txt", "token: "+pat+"\n")
	head := gitIn(t, w, "rev-parse", "HEAD")
	if out, err := b.push(w, "refs/heads/agent/claude/t"); err != nil {
		t.Fatalf("tainted push: %v\n%s", err, out)
	}
	rep := b.rootd.seen("op", "push.report")
	if len(rep) != 1 || fmt.Sprint(rep[0]["secrets"]) != "[github-pat]" {
		t.Fatalf("push.report secrets: %v", rep)
	}
	db, err := OpenStore(b.root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	refs, _ := taintedRefs(db, "claude/app")
	if fmt.Sprint(refs) != "[refs/heads/agent/claude/t]" {
		t.Fatalf("tainted refs %v", refs)
	}
	if ok, _ := anyTaintedCommit(db, "claude/app", []string{head}); !ok {
		t.Fatal("the tainted push's commit is not recorded")
	}
}

func TestHookRootdDown(t *testing.T) {
	b := newPushBox(t, DayPushBytes, "")
	b.rootd.reply = func(map[string]any) map[string]any { return map[string]any{"ok": false, "reason": "unavailable"} }
	w := work(t, "a.txt", "a\n")
	out, err := b.push(w, "refs/heads/agent/claude/a")
	if err == nil || !strings.Contains(out, "remote: agentbox AUDIT_UNAVAILABLE: ") {
		t.Fatalf("rootd refusing push.report: %v\n%s", err, out)
	}
	// and with no request file at all, the hook refuses
	out, err = gitTry(w, nil, "push", b.bare, "HEAD:refs/heads/agent/claude/a")
	if err == nil || !strings.Contains(out, "no push request") {
		t.Fatalf("no request: %v\n%s", err, out)
	}
}

func TestParseRefUpdates(t *testing.T) {
	z, a := strings.Repeat("0", 40), strings.Repeat("a", 40)
	u, err := ParseRefUpdates(strings.NewReader(z + " " + a + " refs/heads/agent/c/x\n" + a + " " + z + " refs/heads/agent/c/y\n"))
	if err != nil || len(u) != 2 || u[1].Ref != "refs/heads/agent/c/y" || !zero(u[1].New) {
		t.Fatalf("%v %v", u, err)
	}
	for _, bad := range []string{"x y z\n", z + " " + a + "\n", z + " " + a + " r extra\n", "AAAA" + a[4:] + " " + a + " r\n"} {
		if _, err := ParseRefUpdates(strings.NewReader(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

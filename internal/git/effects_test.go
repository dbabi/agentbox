package git

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/ids"
)

// fakeGitHub is the REST endpoints the service uses, for one repo acme/app.
type fakeGitHub struct {
	mu       sync.Mutex
	comments map[int64][]Item
	prs      []Item
	posts    int
	fail     func(r *http.Request) (int, string) // a forced reply, or 0
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(401)
		return
	}
	if f.fail != nil {
		if st, body := f.fail(r); st != 0 {
			w.WriteHeader(st)
			w.Write([]byte(body))
			return
		}
	}
	out := func(st int, v any) { w.WriteHeader(st); json.NewEncoder(w).Encode(v) }
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/user":
		out(200, map[string]string{"login": "bot"})
	case r.Method == "GET" && p == "/repos/acme/app":
		out(200, map[string]string{"node_id": "R_1", "visibility": "private"})
	case r.Method == "POST" && p == "/repos/acme/app/pulls":
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		f.posts++
		it := Item{Number: int64(len(f.prs) + 1), URL: "https://github.com/acme/app/pull/" + strconv.Itoa(len(f.prs)+1), Body: in["body"]}
		it.User.Login = "bot"
		f.prs = append(f.prs, it)
		out(201, it)
	case r.Method == "GET" && p == "/repos/acme/app/pulls":
		out(200, f.prs)
	case strings.HasPrefix(p, "/repos/acme/app/issues/") && strings.HasSuffix(p, "/comments"):
		n, _ := strconv.ParseInt(strings.Split(p, "/")[5], 10, 64)
		if r.Method == "POST" {
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			f.posts++
			it := Item{ID: int64(1000 + f.posts), URL: fmt.Sprintf("https://github.com/acme/app/issues/%d#c%d", n, f.posts), Body: in["body"]}
			it.User.Login = "bot"
			f.comments[n] = append(f.comments[n], it)
			out(201, it)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		l := f.comments[n]
		from, to := min((page-1)*100, len(l)), min(page*100, len(l))
		out(200, l[from:to])
	default:
		w.WriteHeader(404)
	}
}

func newGitHub(t *testing.T) (*fakeGitHub, *GitHub) {
	f := &fakeGitHub{comments: map[int64][]Item{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &GitHub{API: srv.URL, HTTP: srv.Client(), Token: func() (string, error) { return "tok", nil }}
}

func TestGitHubClient(t *testing.T) {
	f, g := newGitHub(t)
	ctx := context.Background()
	info, err := g.Repo(ctx, "acme", "app")
	if err != nil || info.NodeID != "R_1" || info.Visibility != "private" {
		t.Fatalf("repo %+v %v", info, err)
	}
	id := ids.New(ids.Pending)
	pr, err := g.CreatePR(ctx, "acme", "app", "t", "agent/claude/x", "main", "body"+Marker(id))
	if err != nil || pr.Number != 1 {
		t.Fatalf("pr %+v %v", pr, err)
	}
	if it, found, err := g.FindPR(ctx, "acme", "app", "agent/claude/x", "main", id); err != nil || !found || it.Number != 1 {
		t.Fatalf("find pr %+v %v %v", it, found, err)
	}
	// 150 comments: the marked one on page 2; another user's comment with the same marker never matches
	for i := range 150 {
		it := Item{ID: int64(i), Body: "c" + strconv.Itoa(i)}
		it.User.Login = "bot"
		if i == 120 {
			it.Body += Marker(id)
		}
		if i == 10 {
			it.Body, it.User.Login = "forged"+Marker(id), "attacker"
		}
		f.comments[7] = append(f.comments[7], it)
	}
	if it, found, err := g.FindComment(ctx, "acme", "app", 7, time.Now(), id); err != nil || !found || it.ID != 120 {
		t.Fatalf("find comment %+v %v %v", it, found, err)
	}
	if _, found, _ := g.FindComment(ctx, "acme", "app", 7, time.Now(), ids.New(ids.Pending)); found {
		t.Fatal("an unmarked op was found")
	}
	for _, c := range []struct {
		st   int
		body string
		hdr  string
		what string
	}{{422, `{"message":"Validation Failed","errors":[{"message":"A pull request already exists for acme:x."}]}`, "", "pr_exists"},
		{422, `{"message":"Validation Failed","errors":[{"message":"No commits between main and x"}]}`, "", "no_commits"},
		{404, `{"message":"Not Found"}`, "", "not_found"}, {403, `{"message":"API rate limit exceeded"}`, "", "rate_limited"},
		{429, `{}`, "", "rate_limited"}, {502, `bad gateway`, "", "unreachable"}, {422, `{"message":"Validation Failed"}`, "", "other"}} {
		f.fail = func(*http.Request) (int, string) { return c.st, c.body }
		_, err := g.CreatePR(ctx, "acme", "app", "t", "agent/claude/x", "main", "b")
		var ae *APIError
		if !errors.As(err, &ae) || ae.What != c.what || !strings.Contains(ae.Detail, strconv.Itoa(c.st)) {
			t.Errorf("%d %s: %v", c.st, c.body, err)
		}
	}
	f.fail = nil
	g.Token = func() (string, error) { return "", errNoToken }
	if _, err := g.Repo(ctx, "acme", "app"); err == nil || !strings.Contains(err.Error(), "no GitHub token") {
		t.Fatalf("no token: %v", err)
	}
	g2 := &GitHub{API: "http://127.0.0.1:1", HTTP: http.DefaultClient, Token: func() (string, error) { return "tok", nil }}
	var ae *APIError
	if _, err := g2.Repo(ctx, "acme", "app"); !errors.As(err, &ae) || ae.What != "unreachable" {
		t.Fatalf("unreachable: %v", err)
	}
}

func execLine(s *Server, m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	return s.Control(b)
}

// exec runs an op once; reconcile finds it again by its marker, and finds nothing for an op that never ran.
func TestExecReconcileComment(t *testing.T) {
	f, g := newGitHub(t)
	b := newHTTPBox(t)
	b.s.GitHub = g
	id := ids.New(ids.Pending)
	bound := Bound{Remote: "origin", URL: "https://github.com/acme/app", NodeID: "R_1", Project: "app", Number: 7, Marker: id}
	req := map[string]any{"call": "exec", "id": id, "name": "gh.pr.comment", "agent": "claude", "bound": bound,
		"args": map[string]any{"remote": "origin", "number": 7, "body": "hi" + Marker(id)}}
	r := execLine(b.s, req)
	out, _ := r["outputs"].(map[string]any)
	if r["ok"] != true || out["remote"] != "origin" || out["url"] == "" {
		t.Fatalf("exec: %v", r)
	}
	if r := execLine(b.s, req); r["ok"] == true || f.posts != 1 {
		t.Fatalf("a second exec of the same op ran: %v, %d posts", r, f.posts)
	}
	rc := execLine(b.s, map[string]any{"call": "reconcile", "id": id, "name": "gh.pr.comment", "agent": "claude", "bound": bound,
		"since": time.Now().UnixMilli()})
	ro, _ := rc["outputs"].(map[string]any)
	if rc["found"] != true || ro["url"] != out["url"] || fmt.Sprint(ro["id"]) != fmt.Sprint(out["id"]) {
		t.Fatalf("reconcile: %v (exec gave %v)", rc, out)
	}
	bound.Marker = ids.New(ids.Pending)
	if rc := execLine(b.s, map[string]any{"call": "reconcile", "id": id, "name": "gh.pr.comment", "agent": "claude", "bound": bound,
		"since": time.Now().UnixMilli()}); rc["ok"] != true || rc["found"] != false {
		t.Fatalf("reconcile of an op that never ran: %v", rc)
	}
	// GitHub's refusal: the what for the task, GitHub's text for humans only
	f.fail = func(*http.Request) (int, string) { return 422, `{"message":"boom sk-secret"}` }
	r = execLine(b.s, map[string]any{"call": "exec", "id": ids.New(ids.Pending), "name": "gh.issue.comment", "agent": "claude", "bound": bound,
		"args": map[string]any{"body": "x"}})
	if r["ok"] == true || r["what"] != "other" || !strings.Contains(fmt.Sprint(r["detail"]), "422") {
		t.Fatalf("refused exec: %v", r)
	}
}

func TestMergeEffect(t *testing.T) {
	b := newHTTPBox(t)
	bare := Repo(b.s.Root, "claude", "app")
	w := work(t, "a.txt", "a\n")
	src := gitIn(t, w, "rev-parse", "HEAD")
	gitIn(t, w, "push", "-q", bare, "HEAD:refs/heads/agent/claude/x")
	merge := func(src, dst string) map[string]any {
		return execLine(b.s, map[string]any{"call": "exec", "id": ids.New(ids.Pending), "name": "repo.merge", "agent": "claude", "task": b.t.id,
			"bound": Bound{Project: "app", SrcOID: src, DstOID: dst}})
	}
	// main doesn't exist yet: it becomes the source, untainted
	r := merge(src, "")
	if out, _ := r["outputs"].(map[string]any); r["ok"] != true || out["oid"] != src || out["tainted"] != false {
		t.Fatalf("first merge: %v", r)
	}
	// a stale dst is refused, and main stays
	if r := merge(src, strings.Repeat("1", 40)); r["stale"] != "ref_moved" {
		t.Fatalf("stale merge: %v", r)
	}
	// a tainted branch: diverged from main, its commit recorded tainted by pre-receive
	gitIn(t, w, "checkout", "-q", "-b", "t")
	tc := commit(t, w, "b.txt", "b\n")
	gitIn(t, w, "push", "-q", bare, "HEAD:refs/heads/agent/claude/t")
	gitIn(t, w, "checkout", "-q", "main")
	commit(t, w, "c.txt", "c\n")
	gitIn(t, w, "push", "-q", bare, "HEAD:refs/heads/agent/claude/m")
	markTainted(b.s.store, "claude/app", b.t.id, []string{"refs/heads/agent/claude/t"}, []string{tc}, 1)
	gitIn(t, bare, "update-ref", "refs/heads/main", gitIn(t, w, "rev-parse", "HEAD"))
	dst := gitIn(t, bare, "rev-parse", "refs/heads/main")
	r = merge(tc, dst)
	out, _ := r["outputs"].(map[string]any)
	if r["ok"] != true || out["tainted"] != true {
		t.Fatalf("tainted merge: %v", r)
	}
	parents := strings.Fields(gitIn(t, bare, "rev-list", "--parents", "-n", "1", "refs/heads/main"))
	if len(parents) != 3 || parents[0] != out["oid"] || parents[1] != dst || parents[2] != tc {
		t.Fatalf("merge commit %v", parents)
	}
	ta := b.audit.seen("type", "TAINT")
	if len(ta) != 1 || ta[0]["subject"] != "ref:claude/app:refs/heads/main" {
		t.Fatalf("TAINT %v", ta)
	}
	if refs, _ := taintedRefs(b.s.store, "claude/app"); !strings.Contains(fmt.Sprint(refs), "refs/heads/main") {
		t.Fatalf("main not recorded tainted: %v", refs)
	}
	rc := execLine(b.s, map[string]any{"call": "reconcile", "name": "repo.merge", "agent": "claude", "bound": Bound{Project: "app", SrcOID: tc, DstOID: dst}})
	if rc["found"] != true {
		t.Fatalf("reconcile merge: %v", rc)
	}
	// a conflict: nothing moves
	gitIn(t, w, "checkout", "-q", "-b", "k", dst)
	k1 := commit(t, w, "b.txt", "other\n")
	gitIn(t, w, "push", "-q", bare, "HEAD:refs/heads/agent/claude/k")
	main := gitIn(t, bare, "rev-parse", "refs/heads/main")
	if r := merge(k1, main); r["failed"] != true || gitIn(t, bare, "rev-parse", "refs/heads/main") != main {
		t.Fatalf("conflicting merge: %v", r)
	}
}

func TestRemoteURL(t *testing.T) {
	for u, want := range map[string]string{"https://github.com/acme/app": "acme/app", "https://github.com/acme/app.git": "acme/app",
		"https://github.com/Acme-1/my.repo": "Acme-1/my.repo"} {
		o, r, err := ParseRemoteURL(u)
		if err != nil || o+"/"+r != want {
			t.Errorf("%s: %s/%s %v", u, o, r, err)
		}
	}
	for _, u := range []string{"http://github.com/a/b", "https://evil.example/a/b", "https://github.com/a", "https://github.com/a/b/c",
		"https://u@github.com/a/b", "https://github.com/a/b?x=1", "https://github.com:8443/a/b", "ssh://github.com/a/b", "https://github.com//b",
		"git@github.com:a/b.git", "https://github.com/a/.b", "https://github.com/a/b%2fc", "https://github.com/a/b#x"} {
		if _, _, err := ParseRemoteURL(u); err == nil {
			t.Errorf("%s: accepted", u)
		}
	}
	for _, r := range []string{"refs/heads/agent/claude/x", "refs/heads/agent/claude/a/b-1.2"} {
		if !InNamespace("claude", r) {
			t.Errorf("%s: not in the namespace", r)
		}
	}
	for _, r := range []string{"refs/heads/agent/claude/", "refs/heads/agent/claude", "refs/heads/agent/claudex/y", "refs/heads/main",
		"refs/heads/agent/claude/a..b", "refs/heads/agent/claude/x.lock", "refs/heads/agent/claude/x@{1}", "refs/tags/agent/claude/x",
		"refs/heads/agent/claude//x", "refs/heads/agent/claude/x/"} {
		if InNamespace("claude", r) {
			t.Errorf("%s: in the namespace", r)
		}
	}
}

func TestStore(t *testing.T) {
	db, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 11, 26, 23, 59, 0, 0, time.UTC)
	if err := addToday(db, "a", 60, 100, now); err != nil {
		t.Fatal(err)
	}
	if err := addToday(db, "a", 50, 100, now); !errors.Is(err, errDayCap) {
		t.Fatalf("over the cap: %v", err)
	}
	if err := addToday(db, "b", 100, 100, now); err != nil {
		t.Fatal("another agent's cap is its own:", err)
	}
	if err := addToday(db, "a", 50, 100, now.Add(2*time.Minute)); err != nil {
		t.Fatal("a new UTC day starts at 0:", err)
	}
	id := ids.New(ids.Pending)
	if err := startOp(db, id, "repo.push", 1); err != nil {
		t.Fatal(err)
	}
	if err := startOp(db, id, "repo.push", 2); !errors.Is(err, errOpSeen) {
		t.Fatalf("second start: %v", err)
	}
}

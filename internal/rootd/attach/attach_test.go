package attach

import (
	"bytes"
	"compress/zlib"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const (
	access  = "gate-oauth-at-access-AAAAAAAAAAAAAAAAAAAA"
	refresh = "gate-oauth-rt-refresh-BBBBBBBBBBBBBBBBBBB"
)

func creds(t *testing.T, home, acc string) {
	t.Helper()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o700)
	b, _ := json.Marshal(map[string]any{"claudeAiOauth": map[string]any{"accessToken": acc, "refreshToken": refresh,
		"expiresAt": 1790000000000, "scopes": []string{"user:inference"}, "subscriptionType": "max-subscription-xxxx"}})
	os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), b, 0o600)
	os.WriteFile(filepath.Join(home, ".codex", "auth.json"), []byte(`{"tokens":{"access_token":"codex-access-CCCCCCCCCCCCCCCC","account_id":"acct"}}`), 0o600)
}

func TestTokens(t *testing.T) {
	home := t.TempDir()
	creds(t, home, access)
	got, err := Tokens(home)
	slices.Sort(got)
	want := []string{"codex-access-CCCCCCCCCCCCCCCC", access, refresh}
	slices.Sort(want)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("tokens %q %v, want %q", got, err, want)
	}
	// a symlinked credential file is not read: it could point anywhere. The CLI still reads it, so the token list is
	// not known, and that is an error (#224); the other file's tokens still count
	auth := filepath.Join(home, ".codex", "auth.json")
	os.Remove(auth)
	other := filepath.Join(t.TempDir(), "x.json")
	os.WriteFile(other, []byte(`{"token":"outside-session-home-DDDDDDDDD"}`), 0o600)
	os.Symlink(other, auth)
	if got, err := Tokens(home); slices.Contains(got, "outside-session-home-DDDDDDDDD") || !slices.Contains(got, access) || err == nil ||
		!strings.Contains(err.Error(), ".codex/auth.json") {
		t.Fatalf("a linked credential file: %q %v", got, err)
	}
	for name, mk := range map[string]func() error{
		"a FIFO":     func() error { return syscall.Mkfifo(auth, 0o600) },
		"over 1 MiB": func() error { return os.WriteFile(auth, bytes.Repeat([]byte(" "), 1<<20+1), 0o600) },
		"not JSON":   func() error { return os.WriteFile(auth, []byte(`{"tokens":{"access_token":"codex-access-`), 0o600) },
		"a dir":      func() error { return os.Mkdir(auth, 0o700) },
		"in a linked dir": func() error {
			os.RemoveAll(filepath.Join(home, ".codex"))
			return os.Symlink(t.TempDir(), filepath.Join(home, ".codex"))
		},
	} {
		os.RemoveAll(auth)
		if err := mk(); err != nil {
			t.Fatal(err)
		}
		if _, err := Tokens(home); err == nil {
			t.Errorf("%s: no error", name)
		}
		os.RemoveAll(filepath.Join(home, ".codex"))
		os.MkdirAll(filepath.Join(home, ".codex"), 0o700)
	}
	// no file, no dir, or an empty file: no login
	os.WriteFile(auth, []byte(" \n"), 0o600)
	if got, err := Tokens(home); err != nil || len(got) != 2 {
		t.Fatalf("an empty file: %q %v", got, err)
	}
	os.RemoveAll(filepath.Join(home, ".codex"))
	os.Remove(filepath.Join(home, ".claude", ".credentials.json"))
	if got, err := Tokens(home); err != nil || len(got) != 0 {
		t.Fatalf("no login: %q %v", got, err)
	}
}

// #224: the credential files a session leaves must be readable: Watch returns the last read's error. A read that
// fails mid-session (a CLI mid-write) does not count.
func TestWatchLastRead(t *testing.T) {
	home := t.TempDir()
	creds(t, home, access)
	cred := filepath.Join(home, ".claude", ".credentials.json")
	watch := func(during func()) error {
		var s Seen
		stop, done := make(chan struct{}), make(chan error)
		go func() { done <- s.Watch(home, 5*time.Millisecond, stop) }()
		time.Sleep(30 * time.Millisecond)
		during()
		time.Sleep(30 * time.Millisecond)
		close(stop)
		return <-done
	}
	if err := watch(func() { os.WriteFile(cred, []byte(`{"claudeAiOauth":`), 0o600) }); err == nil {
		t.Fatal("a credential file left as broken JSON: no error")
	}
	if err := watch(func() { os.Rename(cred, cred+".real"); os.Symlink(".credentials.json.real", cred) }); err == nil {
		t.Fatal("a credential file left a symlink: no error")
	}
	os.Remove(cred)
	creds(t, home, access)
	if err := watch(func() {
		os.WriteFile(cred, []byte(`{"claudeAiOauth":`), 0o600)
		time.Sleep(20 * time.Millisecond)
		creds(t, home, access)
	}); err != nil {
		t.Fatalf("a bad read mid-session, a good one at the end: %v", err)
	}
}

func TestSeenKeepsRotatedTokens(t *testing.T) {
	home := t.TempDir()
	creds(t, home, access)
	var s Seen
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { s.Watch(home, 10*time.Millisecond, stop); close(done) }()
	time.Sleep(50 * time.Millisecond)
	creds(t, home, "gate-oauth-at-rotated-EEEEEEEEEEEEEEEEEEE")
	close(stop)
	<-done
	if all, err := s.All(); err != nil || !slices.Contains(all, access) || !slices.Contains(all, "gate-oauth-at-rotated-EEEEEEEEEEEEEEEEEEE") {
		t.Fatalf("seen %q %v", all, err)
	}
}

// #222 R49: a session that rotates its token past maxSeen leaves an incomplete history, and a scan against it fails.
func TestSeenCap(t *testing.T) {
	defer func(n int) { maxSeen = n }(maxSeen)
	maxSeen = 3 * len(access)
	var s Seen
	s.Add([]string{access, access, access})
	if all, err := s.All(); err != nil || len(all) != 1 {
		t.Fatalf("one version: %q %v", all, err)
	}
	s.Add([]string{access + "1", access + "2"})
	s.Add([]string{access + "3"})
	if all, err := s.All(); err != ErrSeenFull || all != nil {
		t.Fatalf("past the cap: %q %v", all, err)
	}
}

// #222 R49: a control-path tree past maxEntries or maxBytes is refused, not held in rootd's heap.
func TestManifestCap(t *testing.T) {
	defer func(n, b int) { maxEntries, maxBytes = n, b }(maxEntries, maxBytes)
	ws := t.TempDir()
	os.MkdirAll(filepath.Join(ws, ".claude", "rules"), 0o755)
	for i := range 4 {
		os.WriteFile(filepath.Join(ws, ".claude", "rules", fmt.Sprint(i)), nil, 0o644)
	}
	maxEntries = 4
	if m, err := Manifest(ws); err != nil || len(m) != 4 {
		t.Fatalf("at the cap: %d %v", len(m), err)
	}
	maxEntries = 3
	if _, err := Manifest(ws); err != ErrTooMany {
		t.Fatalf("past the entry cap: %v", err)
	}
	maxEntries, maxBytes = 100, 100
	os.Symlink(strings.Repeat("x", 200), filepath.Join(ws, ".claude", "rules", "long"))
	if _, err := Manifest(ws); err != ErrTooMany {
		t.Fatalf("past the byte cap: %v", err)
	}
}

func TestScan(t *testing.T) {
	ws := t.TempDir()
	os.WriteFile(filepath.Join(ws, "old.txt"), []byte(access), 0o644) // before start: an earlier scan's business
	old := time.Now().Add(-time.Hour)
	os.Chtimes(filepath.Join(ws, "old.txt"), old, old) // mtime only; ctime stays now
	start := time.Now().Add(2 * time.Second)           // so old.txt's ctime is before start - 1s
	time.Sleep(10 * time.Millisecond)
	if hits, err := Scan(ws, start, []string{access}); err != nil || len(hits) != 0 {
		t.Fatalf("a file unchanged since start: %v %v", hits, err)
	}
	os.Remove(filepath.Join(ws, "old.txt"))
	start = time.Now()
	os.MkdirAll(filepath.Join(ws, "src"), 0o755)
	os.WriteFile(filepath.Join(ws, "src", "leak.go"), []byte("const k = \""+refresh+"\"\n"), 0o644)
	os.WriteFile(filepath.Join(ws, "clean.go"), []byte("package x\n"), 0o644)
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write([]byte("blob 60\x00" + access))
	w.Close()
	obj := filepath.Join(ws, ".git", "objects", "ab")
	os.MkdirAll(obj, 0o755)
	os.WriteFile(filepath.Join(obj, strings.Repeat("c", 38)), z.Bytes(), 0o444)
	outside := filepath.Join(t.TempDir(), "o")
	os.WriteFile(outside, []byte(access), 0o644)
	os.Symlink(outside, filepath.Join(ws, "link"))
	hits, err := Scan(ws, start, []string{access, refresh})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, h := range hits {
		paths = append(paths, h.Path)
	}
	slices.Sort(paths)
	if want := []string{".git/objects/ab/" + strings.Repeat("c", 38), "src/leak.go"}; !slices.Equal(paths, want) {
		t.Fatalf("hits %q, want %q", paths, want)
	}
}

// A token in a file name, a dir name, a symlink target, past 64 MiB of a file, or split across the 1 MiB read chunks
// is a hit; no hit path carries the token.
func TestScanEverywhere(t *testing.T) {
	ws := t.TempDir()
	start := time.Now()
	os.WriteFile(filepath.Join(ws, "plain"), []byte(access), 0o644)
	os.Symlink(access, filepath.Join(ws, "link"))
	os.WriteFile(filepath.Join(ws, "x-"+access), nil, 0o644)
	os.MkdirAll(filepath.Join(ws, "d", access, "sub"), 0o755)
	os.WriteFile(filepath.Join(ws, "d", access, "sub", "f"), []byte(access), 0o644)
	big, _ := os.Create(filepath.Join(ws, "big"))
	big.Write(make([]byte, 65<<20))
	big.WriteString(access)
	big.Close()
	split := append(make([]byte, 1<<20-5), access...) // straddles the first chunk boundary
	os.WriteFile(filepath.Join(ws, "split"), split, 0o644)
	hits, err := Scan(ws, start, []string{access, refresh})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, h := range hits {
		if strings.Contains(h.Path, access) {
			t.Fatalf("a hit names the token: %q", h.Path)
		}
		paths = append(paths, h.Path)
	}
	slices.Sort(paths)
	want := []string{"(an entry named with a token)", "big", "d/(an entry named with a token)", "link", "plain", "split"}
	if !slices.Equal(paths, want) {
		t.Fatalf("hits %q, want %q", paths, want)
	}
}

// §4.2 control-path gate: an empty workspace needs no ack; a planted control path, an exec bit and a removal each
// show up until saved as the baseline; lockfiles and git objects and refs never do.
func TestControlChanges(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(BaselineSchema)
	ws := t.TempDir()
	changes := func() []string {
		m, err := Manifest(ws)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ControlChanges(db, "a", m)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	accept := func() { m, _ := Manifest(ws); SaveBaseline(db, "a", m) }
	if c := changes(); len(c) != 0 {
		t.Fatalf("empty workspace: %q", c)
	}
	for _, d := range []string{".git/objects/ab", ".git/refs/heads", ".git/hooks", "p/.claude"} {
		os.MkdirAll(filepath.Join(ws, d), 0o755)
	}
	for f, b := range map[string]string{"go.sum": "x", "package-lock.json": "{}", ".git/objects/ab/cd": "o", ".git/refs/heads/main": "r",
		".git/HEAD": "ref", ".git/index": "i"} {
		os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
	}
	if c := changes(); len(c) != 0 {
		t.Fatalf("lockfiles and git objects need no ack: %q", c)
	}
	os.WriteFile(filepath.Join(ws, ".git", "config"), []byte("[core]\n\tpager = evil\n"), 0o644)
	os.WriteFile(filepath.Join(ws, ".mcp.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(ws, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\n"), 0o644)
	os.Symlink("/etc/passwd", filepath.Join(ws, "p", ".claude", "settings.json"))
	if c := changes(); !slices.Equal(c, []string{".git/config", ".git/hooks/pre-commit", ".mcp.json", "p/.claude/settings.json"}) {
		t.Fatalf("planted: %q", c)
	}
	accept()
	if c := changes(); len(c) != 0 {
		t.Fatalf("after the ack: %q", c)
	}
	os.Chmod(filepath.Join(ws, ".git", "hooks", "pre-commit"), 0o755)
	os.Remove(filepath.Join(ws, ".mcp.json"))
	if c := changes(); !slices.Equal(c, []string{".git/hooks/pre-commit", ".mcp.json"}) {
		t.Fatalf("exec bit and removal: %q", c)
	}
	ForgetBaseline(db, "a")
	if c := changes(); len(c) != 3 {
		t.Fatalf("a forgotten baseline is the empty workspace: %q", c)
	}
}

func TestBlock(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(Schema)
	db.Exec(`CREATE TABLE task_registry(task TEXT, agent TEXT, ended_at INTEGER)`) // rootd's, the columns Begin reads
	now := time.Now()
	// a live task of the agent refuses the attach: it would see what the session writes into the workspace
	db.Exec(`INSERT INTO task_registry VALUES('t1','a',NULL)`)
	if err := Begin(db, "a", "ses_0", now); err != ErrTaskLive {
		t.Fatalf("attach with a live task: %v", err)
	}
	if _, ok, _ := Blocked(db, "a"); ok {
		t.Fatal("a refused attach left a block")
	}
	db.Exec(`UPDATE task_registry SET ended_at=1`)
	if err := Begin(db, "a", "ses_1", now); err != nil {
		t.Fatal(err)
	}
	if err := Begin(db, "a", "ses_2", now); err != ErrLive {
		t.Fatalf("a second attach: %v", err)
	}
	if b, ok, _ := Blocked(db, "a"); !ok || b.Reason != Live {
		t.Fatalf("live attach must block tasks: %+v", b)
	}
	End(db, "a", "ses_1", []Hit{{"x"}, {"y\x1b[2K z"}}) // #198: the agent names the files, so the detail quotes them
	if b, ok, _ := Blocked(db, "a"); !ok || b.Reason != Token || b.Detail != `"x" "y\x1b[2K z"` {
		t.Fatalf("a hit must keep tasks blocked: %+v", b)
	}
	End(db, "a", "ses_1", nil)
	if _, ok, _ := Blocked(db, "a"); ok {
		t.Fatal("a clean scan lifts the block")
	}
	if l, _ := List(db); len(l) != 0 {
		t.Fatalf("list %+v", l)
	}
}

func TestPrepare(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0o077)) // rootd's UMask=0077
	root := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	p := AgentPaths(root, "at", "ses_1")
	os.MkdirAll(p.Workspace, 0o755)
	if _, err := Prepare(root, "ses_1", "at", "claude", nil, uid, gid, "/dev/pts/9", ""); err == nil {
		t.Fatal("no session-home: must refuse")
	}
	os.MkdirAll(p.SessionHome, 0o700)
	s, err := Prepare(root, "ses_1", "at", "claude", []string{"-p", "hi"}, uid, gid, "/dev/pts/9", "screen")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(p.SessionHome, ".claude", "settings.json")); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the bind target: %v %v", fi, err)
	}
	want := []string{"claude", "--setting-sources", "user", "--strict-mcp-config", "--settings", Exports + "/" + SettingsFile, "-p", "hi"}
	if !slices.Equal(s.Argv, want) {
		t.Fatalf("argv %q", s.Argv)
	}
	if !slices.Contains(s.Mounts, Mount{Src: filepath.Join(p.Exports, SettingsFile), Dst: Home + "/.claude/settings.json", RO: true}) {
		t.Fatalf("no read-only settings bind: %+v", s.Mounts)
	}
	for _, g := range GitConfigs { // an empty read-only git config over session-home's, with a regular file to bind over
		if fi, err := os.Lstat(filepath.Join(p.SessionHome, g)); err != nil || !fi.Mode().IsRegular() ||
			!slices.Contains(s.Mounts, Mount{Src: filepath.Join(p.Exports, EmptyGitConfig), Dst: Home + "/" + g, RO: true}) {
			t.Fatalf("~/%s: %v %v %+v", g, fi, err, s.Mounts)
		}
	}
	for _, e := range append(append(GitEnv, sessionEnv...), "TERM=screen", "CLAUDE_CODE_DISABLE_AUTO_MEMORY=1", "CODEX_HOME="+CodexHome, "DISABLE_UPDATES=1") {
		if !slices.Contains(s.Env, e) {
			t.Errorf("env lacks %s", e)
		}
	}
	var set map[string]any
	b, _ := os.ReadFile(filepath.Join(p.Exports, SettingsFile))
	if json.Unmarshal(b, &set) != nil || set["disableAllHooks"] != true || set["autoMemoryEnabled"] != false || fmt.Sprint(set["allowedMcpServers"]) != "[]" ||
		set["allowManagedMcpServersOnly"] != true || set["allowManagedHooksOnly"] != true {
		t.Fatalf("attach settings %s", b)
	}
	for _, f := range []string{p.Exports, filepath.Join(p.Exports, NoHooks), filepath.Join(p.Exports, SettingsFile),
		filepath.Join(p.Codex, "config.toml")} {
		if fi, err := os.Stat(f); err != nil || fi.Mode().Perm()&0o004 == 0 {
			t.Errorf("%s: the session uid can't read it: %v %v", f, fi, err)
		}
	}
	if l, _ := os.Readlink(filepath.Join(p.Codex, "auth.json")); l != Home+"/.codex/auth.json" {
		t.Fatalf("codex auth link %q", l)
	}
	// CODEX_HOME is in session-home, under the agent's own quota (#210), and it is the session's own: no bind
	if fi, err := os.Lstat(p.Codex); err != nil || !fi.IsDir() || filepath.Dir(p.Codex) != p.SessionHome || CodexHome != Home+"/"+CodexDir {
		t.Fatalf("CODEX_HOME %s: %v %v", p.Codex, fi, err)
	}
	for _, m := range s.Mounts {
		if strings.Contains(m.Dst, CodexDir) || strings.HasPrefix(m.Src, filepath.Join(root, "control", "attach")) {
			t.Fatalf("a CODEX_HOME bind: %+v", m)
		}
	}
	if c, _ := os.ReadFile(filepath.Join(p.Codex, "config.toml")); strings.Contains(string(c), "[projects") || !strings.Contains(string(c), "\nweb_search = \"disabled\"\n") {
		t.Fatalf("codex config %s", c)
	}
	RemoveRun(p)
	if _, err := os.Lstat(p.Codex); err == nil {
		t.Fatal("RemoveRun left CODEX_HOME")
	}
	// one a session left as a link is removed, not followed
	elsewhere := t.TempDir()
	os.WriteFile(filepath.Join(elsewhere, "keep"), nil, 0o600)
	os.Symlink(elsewhere, p.Codex)
	if _, err := Prepare(root, "ses_1", "at", "codex", nil, uid, gid, "/dev/pts/9", ""); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(p.Codex); err != nil || !fi.IsDir() {
		t.Fatalf("CODEX_HOME over a planted link: %v %v", fi, err)
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 1 {
		t.Fatalf("rootd wrote or removed through the link: %v", ents)
	}
	RemoveRun(p)
	for _, bad := range []string{"--dangerously-bypass-hook-trust", "--trust", "--trust=yes"} {
		if _, err := Prepare(root, "ses_2", "at", "codex", []string{"exec", bad}, uid, gid, "/dev/pts/9", ""); err == nil {
			t.Fatalf("codex %s: must refuse", bad)
		}
	}
	// a planted symlink in session-home makes rootd refuse, not follow it
	os.RemoveAll(filepath.Join(p.SessionHome, ".config"))
	cfg := t.TempDir()
	os.Symlink(cfg, filepath.Join(p.SessionHome, ".config"))
	if _, err := Prepare(root, "ses_3", "at", "claude", nil, uid, gid, "/dev/pts/9", ""); err == nil {
		t.Fatal("~/.config as a symlink: must refuse")
	}
	if ents, _ := os.ReadDir(cfg); len(ents) != 0 {
		t.Fatal("rootd wrote through the ~/.config symlink")
	}
	os.Remove(filepath.Join(p.SessionHome, ".config"))
	os.RemoveAll(filepath.Join(p.SessionHome, ".claude"))
	target := t.TempDir()
	os.Symlink(target, filepath.Join(p.SessionHome, ".claude"))
	if _, err := Prepare(root, "ses_2", "at", "claude", nil, uid, gid, "/dev/pts/9", ""); err == nil {
		t.Fatal("~/.claude as a symlink: must refuse")
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatal("rootd wrote through the symlink")
	}
	os.Remove(filepath.Join(p.SessionHome, ".claude"))
	os.MkdirAll(filepath.Join(p.SessionHome, ".claude"), 0o700)
	os.Symlink(filepath.Join(target, "s"), filepath.Join(p.SessionHome, ".claude", "settings.json"))
	if _, err := Prepare(root, "ses_3", "at", "claude", nil, uid, gid, "/dev/pts/9", ""); err == nil {
		t.Fatal("settings.json as a symlink: must refuse")
	}
	if _, err := os.Lstat(filepath.Join(target, "s")); err == nil {
		t.Fatal("rootd created the symlink's target")
	}
	if _, err := Prepare(root, "ses_4", "at", "vim", nil, uid, gid, "/dev/pts/9", ""); err == nil {
		t.Fatal("an unknown cli must be refused")
	}
}

// The session container gets a task's hardening (§4.2) and session-home in place of the tmpfs HOME, as ag-<agent>.
func TestPodmanArgv(t *testing.T) {
	s := Session{ID: "ses_1", Agent: "at", UID: 70002, GID: 70002, TTY: "/dev/pts/3", Dir: Workspace, Env: []string{"HOME=" + Home}, Argv: []string{"bash", "--noprofile", "--norc", "-i"},
		Mounts: []Mount{{Src: "/sh", Dst: Home}, {Src: "/x.json", Dst: Home + "/.claude/settings.json", RO: true}}}
	a := strings.Join(Podman{Seccomp: "/s.json", Image: "img", HostUsr: []string{"/usr/bin"}}.Argv(s), " ")
	for _, want := range []string{
		"systemd-run --user -M ag-at@ --wait --collect --quiet --service-type=exec --unit=agentbox-attach-ses_1.service",
		"-p TTYPath=/dev/pts/3 -p StandardInput=tty", "-p Delegate=yes -p KillMode=mixed",
		"-p ExecStopPost=-/usr/bin/podman rm -f -i -t 0 attach-ses_1 /usr/bin/podman run --cgroups=split --rm -it --name attach-ses_1",
		"--network=none --userns=keep-id --user=70002:70002 --security-opt=no-new-privileges --cap-drop=all --security-opt=seccomp=/s.json --read-only",
		"-w /workspace -v /sh:/home/agent -v /x.json:/home/agent/.claude/settings.json:ro", "-v /usr/bin:/usr/bin:ro",
		"-e HOME=/home/agent img bash --noprofile --norc -i",
	} {
		if !strings.Contains(a, want) {
			t.Errorf("argv lacks %q:\n%s", want, a)
		}
	}
	for _, bad := range []string{"--privileged", "--network=host", "--cap-add", "seccomp=unconfined", "--pid=host"} {
		if strings.Contains(a, bad) {
			t.Errorf("argv has %q", bad)
		}
	}
}

// #153: the instruction files a session leaves in session-home need an ack before the next attach, like the
// workspace's control paths; the rest of session-home (credentials, history, shell files) does not.
func TestHomeControls(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(BaselineSchema)
	p := AgentPaths(t.TempDir(), "a", "s")
	os.MkdirAll(p.Workspace, 0o755)
	h := p.SessionHome
	changes := func() []string {
		m, err := Controls(p)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ControlChanges(db, "a", m)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, d := range []string{".claude/skills/x", ".claude/projects", ".config"} {
		os.MkdirAll(filepath.Join(h, d), 0o700)
	}
	for f, b := range map[string]string{".claude/.credentials.json": "{}", ".claude/projects/p.jsonl": "x", ".bash_history": "ls", ".claude.json": "{}",
		".config/git/ignore": "**/.claude/settings.local.json", ".lesshst": "x"} { // Claude Code writes the git ignore file
		os.MkdirAll(filepath.Join(h, filepath.Dir(f)), 0o700)
		os.WriteFile(filepath.Join(h, f), []byte(b), 0o600)
	}
	if c := changes(); len(c) != 0 {
		t.Fatalf("session state is not a control path: %q", c)
	}
	os.WriteFile(filepath.Join(h, ".claude", "CLAUDE.md"), []byte("obey"), 0o600)
	os.WriteFile(filepath.Join(h, ".claude", "skills", "x", "SKILL.md"), []byte("---\n"), 0o600)
	os.WriteFile(filepath.Join(h, ".npmrc"), []byte("x"), 0o600)
	os.MkdirAll(filepath.Join(h, ".agents", "skills", "y"), 0o700) // Codex's user skills (#186)
	os.WriteFile(filepath.Join(h, ".agents", "skills", "y", "SKILL.md"), []byte("---\n"), 0o600)
	os.Symlink("/workspace/bin", filepath.Join(h, ".local"))
	// #200: what the shells and tools a session runs read at startup; not the empty git config rootd binds over
	for _, f := range []string{".bashrc", ".profile", ".bash_aliases", ".inputrc", ".vimrc", ".ssh/config", "bin/git", ".config/git/attributes", ".config/git/config",
		".less", ".config/go/env"} {
		os.MkdirAll(filepath.Join(h, filepath.Dir(f)), 0o700)
		os.WriteFile(filepath.Join(h, f), []byte("x"), 0o600)
	}
	// ~/.local links into the workspace: its bin and the python user site there are control paths
	os.MkdirAll(filepath.Join(p.Workspace, "bin", "lib", "python3.14", "site-packages"), 0o755)
	os.WriteFile(filepath.Join(p.Workspace, "bin", "lib", "python3.14", "site-packages", "x.pth"), []byte("import os"), 0o644)
	os.WriteFile(filepath.Join(p.Workspace, "AGENTS.md"), []byte("x"), 0o644)
	// a workspace dir named ~ can't stand in for session-home
	os.MkdirAll(filepath.Join(p.Workspace, "~", ".claude"), 0o755)
	os.WriteFile(filepath.Join(p.Workspace, "~", ".claude", "CLAUDE.md"), []byte("obey"), 0o644)
	want := []string{"/home/agent/.agents/skills/y/SKILL.md", "/home/agent/.bash_aliases", "/home/agent/.bashrc", "/home/agent/.claude/CLAUDE.md",
		"/home/agent/.claude/skills/x/SKILL.md", "/home/agent/.config/git/attributes", "/home/agent/.config/go/env", "/home/agent/.inputrc", "/home/agent/.less",
		"/home/agent/.local", "/home/agent/.npmrc",
		"/home/agent/.profile", "/home/agent/.ssh/config", "/home/agent/.vimrc", "/home/agent/bin/git", "AGENTS.md", "bin/lib/python3.14/site-packages/x.pth", "~/.claude/CLAUDE.md"}
	if c := changes(); !slices.Equal(c, want) {
		t.Fatalf("planted:\n got %q\nwant %q", c, want)
	}
	m, _ := Controls(p)
	SaveBaseline(db, "a", m)
	if c := changes(); len(c) != 0 {
		t.Fatalf("after the ack: %q", c)
	}
	os.WriteFile(filepath.Join(h, ".claude", "skills", "x", "SKILL.md"), []byte("---\nhooks: x\n"), 0o600)
	os.Remove(filepath.Join(h, ".claude", "CLAUDE.md"))
	os.WriteFile(filepath.Join(h, ".bashrc"), []byte("git() { :; }"), 0o600)
	if c := changes(); !slices.Equal(c, []string{"/home/agent/.bashrc", "/home/agent/.claude/CLAUDE.md", "/home/agent/.claude/skills/x/SKILL.md"}) {
		t.Fatalf("changed and removed: %q", c)
	}
}

// #154: a token committed and then packed by git gc is still found, as a whole object and as the bytes a delta
// inserts; a long token is cut into 127-byte inserts there. A pack with no token, or a corrupt one, is no hit.
func TestScanPack(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	tok := "gate-oauth-at-packed-" + strings.Repeat("P", 300)
	git := func(dir string, args ...string) {
		t.Helper()
		c := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "gc.auto=0"}, args...)...)
		c.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	packs := func(ws string) []string {
		start := time.Now().Add(-time.Hour)
		hits, err := Scan(ws, start, []string{tok})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, h := range hits {
			out = append(out, h.Path)
		}
		return out
	}
	body := strings.Repeat("line of ordinary source text\n", 400)
	for _, tc := range []struct {
		name     string
		versions []string // committed in order; the last is in the work tree, then removed
	}{
		{"whole object", []string{"x := `" + tok + "`\n"}},
		// git keeps the larger version whole and the smaller as a delta against it: the token is a delta insert
		{"delta", []string{body[:len(body)/2] + tok + "\n" + body[len(body)/2:], body + strings.Repeat("more\n", 200)}},
	} {
		ws := t.TempDir()
		git(ws, "init", "-q")
		for i, v := range tc.versions {
			os.WriteFile(filepath.Join(ws, "f.go"), []byte(v), 0o644)
			git(ws, "add", "f.go")
			git(ws, "commit", "-qm", fmt.Sprint(i))
		}
		git(ws, "rm", "-q", "f.go")
		git(ws, "commit", "-qm", "gone")
		git(ws, "gc", "-q", "--prune=now")
		if loose, _ := filepath.Glob(filepath.Join(ws, ".git", "objects", "??", "*")); len(loose) != 0 {
			t.Fatalf("%s: gc left loose objects %q", tc.name, loose)
		}
		got := packs(ws)
		if len(got) != 1 || !packRe.MatchString(filepath.Base(got[0])) {
			t.Fatalf("%s: hits %q, want the pack", tc.name, got)
		}
		p := filepath.Join(ws, got[0])
		if tc.name == "delta" {
			if out, _ := exec.Command("git", "-C", ws, "verify-pack", "-v", p).Output(); !bytes.Contains(out, []byte(" 1 ")) {
				t.Fatalf("no delta in the pack:\n%s", out)
			}
		}
		b, _ := os.ReadFile(p)
		os.Chmod(p, 0o644)
		os.WriteFile(p, b[:40], 0o644) // cut inside the first object: no hit, and no error
		if got := packs(ws); len(got) != 0 {
			t.Fatalf("%s: a truncated pack: %q", tc.name, got)
		}
	}
}

// #123: an IDE task file, a nested repo, a gitdir file and the git dir it names, and a venv not named .venv each
// need an ack; the venv's modules and the git dir's objects don't.
func TestManifestRoots(t *testing.T) {
	ws := t.TempDir()
	for f, b := range map[string]string{".vscode/tasks.json": `{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}`, "sub/.git/config": "", "sub/.git/objects/ab": "o",
		"wt/.git": "gitdir: ../meta\n", "meta/hooks/pre-commit": "", "meta/objects/cd": "o", "env/pyvenv.cfg": "", "env/bin/python": "", "env/lib/m.py": ""} {
		os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
		os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
	}
	m, err := Manifest(ws)
	if err != nil {
		t.Fatal(err)
	}
	got := slices.Sorted(maps.Keys(m))
	if want := []string{".vscode/tasks.json", "env/bin/python", "env/pyvenv.cfg", "meta/hooks/pre-commit", "sub/.git/config", "wt/.git"}; !slices.Equal(got, want) {
		t.Fatalf("manifest %q, want %q", got, want)
	}
}

// #182: a root venv, a commondir target and a bare repo need an ack, their objects don't; a git dir in session-home
// refuses the attach.
func TestManifestContentRoots(t *testing.T) {
	ws := t.TempDir()
	for f, b := range map[string]string{"pyvenv.cfg": "", "bin/python": "", "lib/m.py": "", "wt/.git": "gitdir: ../meta\n", "meta/commondir": "../common",
		"meta/HEAD": "", "common/config": "", "common/objects/ab": "o", "b/HEAD": "", "b/config": "", "b/objects/cd": "o", "b/refs/heads/main": ""} {
		os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
		os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
	}
	m, err := Manifest(ws)
	if err != nil {
		t.Fatal(err)
	}
	got := slices.Sorted(maps.Keys(m))
	if want := []string{"b/config", "bin/python", "common/config", "meta/commondir", "pyvenv.cfg", "wt/.git"}; !slices.Equal(got, want) {
		t.Fatalf("manifest %q, want %q", got, want)
	}
	os.WriteFile(filepath.Join(ws, "wt", ".git"), []byte("gitdir: /home/agent/g\n"), 0o644)
	if _, err := Controls(Paths{Workspace: ws, SessionHome: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "session-home") {
		t.Fatalf("a gitdir in session-home: %v", err)
	}
}

// #206, #207: the config of a git dir behind a .git file padded past 4 KiB, and of git dirs planted in another one's
// refs or objects, need an ack; what those git dirs keep as inert, and the real ones' refs and objects, don't.
func TestManifestPlantedGitDirs(t *testing.T) {
	ws := t.TempDir()
	for f, b := range map[string]string{"p/.git": "gitdir: ../gd" + strings.Repeat("\n", 5000), "gd/HEAD": "", "gd/commondir": "../gd2", "gd2/config": "",
		"gd2/objects/ab": "o", ".git/HEAD": "", ".git/refs/heads/main": "r", ".git/objects/cd/ef": "o", "sub/.git": "gitdir: ../.git/refs/evil\n",
		".git/refs/evil/HEAD": "", ".git/refs/evil/commondir": ".", ".git/refs/evil/refs/heads/main": "r", ".git/refs/evil/config": "",
		"q/.git": "gitdir: ../.git/objects/fake\n", ".git/objects/fake/HEAD": "", ".git/objects/fake/hooks/post-checkout": ""} {
		os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
		os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
	}
	m, err := Manifest(ws)
	if err != nil {
		t.Fatal(err)
	}
	got := slices.Sorted(maps.Keys(m))
	want := []string{".git/objects/fake/hooks/post-checkout", ".git/refs/evil/commondir", ".git/refs/evil/config", "gd/commondir", "gd2/config", "p/.git", "q/.git", "sub/.git"}
	if !slices.Equal(got, want) {
		t.Fatalf("manifest %q, want %q", got, want)
	}
}

// #202: a symlink at or under a control path is recorded by its target and by what it resolves to in the session, so
// an edit behind an acked link needs an ack too; a link into session-home is followed there, and refused without it.
func TestManifestLinks(t *testing.T) {
	ws, home := t.TempDir(), t.TempDir()
	write := func(dir string, files map[string]string) {
		for f, b := range files {
			os.MkdirAll(filepath.Join(dir, filepath.Dir(f)), 0o755)
			os.WriteFile(filepath.Join(dir, f), []byte(b), 0o644)
		}
	}
	link := func(dir, at, to string) {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(at)), 0o755)
		if err := os.Symlink(to, filepath.Join(dir, at)); err != nil {
			t.Fatal(err)
		}
	}
	write(ws, map[string]string{"docs/guide.txt": "obey", "store/HEAD": "", "store/config": "[alias]\n", "store/objs/ab": "o", "store/refs/heads/main": "",
		"stuff/settings.json": "{}", "payload": "[core]\n", "notes/r.md": "rule", "src/main.go": ""})
	link(ws, "CLAUDE.md", "docs/guide.txt")
	link(ws, "proj/.git", "../store")
	link(ws, "store/objects", "objs")
	link(ws, ".claude", "stuff")
	link(ws, "sub/.git", "../.gitdir-real")
	write(ws, map[string]string{".gitdir-real/config": "", "sub/x": ""})
	link(ws, "a/.mcp.json", "/home/agent/mcp.json")
	write(home, map[string]string{"mcp.json": "{}", "notes.md": "obey", ".claude/x": ""})
	link(home, ".claude/CLAUDE.md", "../notes.md")
	link(home, ".claude/rules/r", "/workspace/notes/r.md")
	m, err := Controls(Paths{Workspace: ws, SessionHome: home})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"CLAUDE.md", "docs/guide.txt", "proj/.git", "store/config", ".claude", "stuff/settings.json", "sub/.git", ".gitdir-real/config",
		"a/.mcp.json", Home + "/mcp.json", Home + "/.claude/CLAUDE.md", Home + "/notes.md", Home + "/.claude/rules/r", "notes/r.md"} {
		if _, ok := m[k]; !ok {
			t.Errorf("no %s in %q", k, slices.Sorted(maps.Keys(m)))
		}
	}
	for _, k := range []string{"src/main.go", "store/objects", "store/HEAD", "store/refs/heads/main", "sub/x", Home + "/.claude/x"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s is not a control path", k)
		}
	}
	// an edit behind each link changes the state
	for _, f := range []string{"docs/guide.txt", "store/config", "stuff/settings.json"} {
		os.WriteFile(filepath.Join(ws, f), []byte("changed"), 0o644)
	}
	os.WriteFile(filepath.Join(home, "notes.md"), []byte("changed"), 0o644)
	m2, _ := Controls(Paths{Workspace: ws, SessionHome: home})
	for _, k := range []string{"docs/guide.txt", "store/config", "stuff/settings.json", Home + "/notes.md"} {
		if m2[k] == m[k] {
			t.Errorf("%s changed, the state did not", k)
		}
	}
	// without session-home, a workspace control link into it is refused
	if _, err := Manifest(ws); err == nil || !strings.Contains(err.Error(), "session-home") {
		t.Errorf("Manifest with a link into session-home: %v", err)
	}
	// a link to what git keeps as inert, and a link on the way, are recorded too: retargeting either needs an ack
	write(ws, map[string]string{".git/description": "obey", "d1/agents.txt": "obey", "d2/agents.txt": "obey"})
	link(ws, "CLAUDE.local.md", ".git/description")
	link(ws, "AGENTS.md", "via/agents.txt")
	link(ws, "via", "d1")
	m3, err := Controls(Paths{Workspace: ws, SessionHome: home})
	for _, k := range []string{"CLAUDE.local.md", ".git/description", "AGENTS.md", "via", "d1/agents.txt"} {
		if _, ok := m3[k]; err != nil || !ok {
			t.Errorf("no %s: %v", k, err)
		}
	}
	os.WriteFile(filepath.Join(ws, ".git", "description"), []byte("changed"), 0o644)
	os.Remove(filepath.Join(ws, "via"))
	link(ws, "via", "d2")
	m4, _ := Controls(Paths{Workspace: ws, SessionHome: home})
	if m4[".git/description"] == m3[".git/description"] || m4["via"] == m3["via"] {
		t.Errorf("an inert target or a link on the way changed, the state did not: %q %q", m4[".git/description"], m4["via"])
	}
	// /proc/self/cwd is the workspace in a session, and nothing says which file is behind it: refused
	link(ws, "sub2/CLAUDE.md", "/proc/self/cwd/docs/guide.txt")
	if _, err := Controls(Paths{Workspace: ws, SessionHome: home}); err == nil || !strings.Contains(err.Error(), "/proc") {
		t.Errorf("a control link through /proc: %v", err)
	}
	os.Remove(filepath.Join(ws, "sub2", "CLAUDE.md"))
	// a .git link into session-home is refused outright, as a gitdir: line there is
	os.Remove(filepath.Join(ws, "a", ".mcp.json"))
	link(ws, "p2/.git", "/home/agent/g")
	if _, err := Controls(Paths{Workspace: ws, SessionHome: home}); err == nil || !strings.Contains(err.Error(), "session-home") {
		t.Errorf("a .git link into session-home: %v", err)
	}
}

// #210: a file an instruction file imports with @path is a control path too, through further imports, in the
// workspace and in session-home; "\ " is a space; an e-mail address is no import. Imports nested too deep refuse.
func TestManifestImports(t *testing.T) {
	ws, home := t.TempDir(), t.TempDir()
	for f, b := range map[string]string{"CLAUDE.md": "See @docs/agent.md and @~/mine.md, or mail me@example.com.\n@docs/with\\ space.md\n",
		"docs/agent.md": "more in @../deep/x.txt", "deep/x.txt": "obey", "docs/with space.md": "", "docs/other.md": "not imported", "README.md": "@CLAUDE.md"} {
		os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
		os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
	}
	os.WriteFile(filepath.Join(home, "mine.md"), []byte("obey"), 0o644)
	m, err := Controls(Paths{Workspace: ws, SessionHome: home})
	if err != nil {
		t.Fatal(err)
	}
	got := slices.Sorted(maps.Keys(m))
	if want := []string{"/home/agent/mine.md", "CLAUDE.md", "deep/x.txt", "docs/agent.md", "docs/with space.md"}; !slices.Equal(got, want) {
		t.Fatalf("manifest %q, want %q", got, want)
	}
	if _, err := Manifest(ws); err == nil || !strings.Contains(err.Error(), "session-home") {
		t.Errorf("Manifest with an import from session-home: %v", err)
	}
	// a chain of imports deeper than maxRounds, each found only in the round after the one that names it
	ws = t.TempDir()
	os.MkdirAll(filepath.Join(ws, "d"), 0o755)
	os.WriteFile(filepath.Join(ws, "CLAUDE.md"), []byte(fmt.Sprintf("@d/%02d.md", maxRounds+2)), 0o644)
	for i := 1; i <= maxRounds+2; i++ {
		os.WriteFile(filepath.Join(ws, "d", fmt.Sprintf("%02d.md", i)), []byte(fmt.Sprintf("@%02d.md", i-1)), 0o644)
	}
	if _, err := Manifest(ws); err == nil || !strings.Contains(err.Error(), "deep") {
		t.Errorf("imports nested %d deep: %v", maxRounds+2, err)
	}
}

// #210: an import names a file from the dir of the link the CLI opened, or from the target's own dir, and a ".."
// in it can climb from a name through a dir link, as Node's path.resolve does: every one of those is recorded.
func TestManifestImportNames(t *testing.T) {
	ws := t.TempDir()
	for f, b := range map[string]string{"docs/inner/real.md": "@evil.md", "sub/evil.md": "obey", "a/b/c/CLAUDE.md": "@../../x.md", "x.md": "obey",
		"a/x.md": "obey", "unrelated.md": ""} {
		os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
		os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
	}
	os.Symlink("../docs/inner/real.md", filepath.Join(ws, "sub", "CLAUDE.md")) // read as sub/CLAUDE.md, @evil.md is sub/evil.md
	os.MkdirAll(filepath.Join(ws, "deep"), 0o755)
	os.Symlink("../a/b/c", filepath.Join(ws, "deep", "n")) // deep/n/CLAUDE.md is a/b/c/CLAUDE.md
	m, err := Manifest(ws)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"sub/CLAUDE.md", "docs/inner/real.md", "sub/evil.md", "a/b/c/CLAUDE.md", "a/x.md", "x.md"} {
		if _, ok := m[k]; !ok {
			t.Errorf("no %s in %q", k, slices.Sorted(maps.Keys(m)))
		}
	}
	if _, ok := m["unrelated.md"]; ok {
		t.Error("unrelated.md is not imported")
	}
}

func TestDigest(t *testing.T) {
	cur := map[string]string{".mcp.json": "-rw-r--r-- ab", "AGENTS.md": "-rw-r--r-- cd"}
	d := Digest([]string{".mcp.json", "AGENTS.md"}, cur)
	if len(d) != 64 || d != Digest([]string{".mcp.json", "AGENTS.md"}, maps.Clone(cur)) {
		t.Fatalf("digest %q", d)
	}
	for _, other := range []string{Digest([]string{".mcp.json"}, cur), Digest([]string{".mcp.json", "AGENTS.md", "x"}, cur),
		Digest([]string{".mcp.json", "AGENTS.md"}, map[string]string{".mcp.json": "-rw-r--r-- ab", "AGENTS.md": "-rw-r--r-- ce"})} {
		if other == d {
			t.Fatal("a different list or state has the same digest")
		}
	}
}

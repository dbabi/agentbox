package attach

import (
	"bytes"
	"compress/zlib"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
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
	got := Tokens(home)
	slices.Sort(got)
	want := []string{"codex-access-CCCCCCCCCCCCCCCC", access, refresh}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("tokens %q, want %q", got, want)
	}
	// a symlinked credential file is not read: it could point anywhere
	os.Remove(filepath.Join(home, ".codex", "auth.json"))
	other := filepath.Join(t.TempDir(), "x.json")
	os.WriteFile(other, []byte(`{"token":"outside-session-home-DDDDDDDDD"}`), 0o600)
	os.Symlink(other, filepath.Join(home, ".codex", "auth.json"))
	if slices.Contains(Tokens(home), "outside-session-home-DDDDDDDDD") {
		t.Fatal("followed a symlink")
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
	if all := s.All(); !slices.Contains(all, access) || !slices.Contains(all, "gate-oauth-at-rotated-EEEEEEEEEEEEEEEEEEE") {
		t.Fatalf("seen %q", all)
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

func TestBlock(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(Schema)
	now := time.Now()
	if err := Begin(db, "a", "ses_1", now); err != nil {
		t.Fatal(err)
	}
	if err := Begin(db, "a", "ses_2", now); err != ErrLive {
		t.Fatalf("a second attach: %v", err)
	}
	if b, ok, _ := Blocked(db, "a"); !ok || b.Reason != Live {
		t.Fatalf("live attach must block tasks: %+v", b)
	}
	End(db, "a", "ses_1", []Hit{{"x"}})
	if b, ok, _ := Blocked(db, "a"); !ok || b.Reason != Token || b.Detail != "x" {
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
	for _, e := range append(GitEnv, "TERM=screen", "CLAUDE_CODE_DISABLE_AUTO_MEMORY=1", "CODEX_HOME="+CodexHome) {
		if !slices.Contains(s.Env, e) {
			t.Errorf("env lacks %s", e)
		}
	}
	var set map[string]any
	b, _ := os.ReadFile(filepath.Join(p.Exports, SettingsFile))
	if json.Unmarshal(b, &set) != nil || set["disableAllHooks"] != true || set["autoMemoryEnabled"] != false || fmt.Sprint(set["allowedMcpServers"]) != "[]" {
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
	if c, _ := os.ReadFile(filepath.Join(p.Codex, "config.toml")); strings.Contains(string(c), "[projects") {
		t.Fatal("codex config trusts a project")
	}
	RemoveRun(p)
	// a planted symlink in session-home makes rootd refuse, not follow it
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
	s := Session{ID: "ses_1", Agent: "at", TTY: "/dev/pts/3", Dir: Workspace, Env: []string{"HOME=" + Home}, Argv: []string{"bash", "-l"},
		Mounts: []Mount{{Src: "/sh", Dst: Home}, {Src: "/x.json", Dst: Home + "/.claude/settings.json", RO: true}}}
	a := strings.Join(Podman{Seccomp: "/s.json", Image: "img", HostUsr: []string{"/usr/bin"}}.Argv(s), " ")
	for _, want := range []string{
		"systemd-run --user -M ag-at@ --wait --collect --quiet --service-type=exec --unit=agentbox-attach-ses_1.service",
		"-p TTYPath=/dev/pts/3 -p StandardInput=tty", "-p Delegate=yes -p KillMode=mixed",
		"-p ExecStopPost=-/usr/bin/podman rm -f -i -t 0 attach-ses_1 /usr/bin/podman run --cgroups=split --rm -it --name attach-ses_1",
		"--network=none --userns=keep-id --security-opt=no-new-privileges --cap-drop=all --security-opt=seccomp=/s.json --read-only",
		"-w /workspace -v /sh:/home/agent -v /x.json:/home/agent/.claude/settings.json:ro", "-v /usr/bin:/usr/bin:ro",
		"-e HOME=/home/agent img bash -l",
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

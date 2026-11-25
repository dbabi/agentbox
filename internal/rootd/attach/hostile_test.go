package attach

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestHostileWorkspace is #107's fixture: links to /etc/shadow and to an approvers stand-in outside the tree, a
// symlinked .claude/, a FIFO package-lock.json and a 2 GiB sparse go.sum, and the same tricks in session-home. Every
// reader (the token scan, the session-home token read, the control-path manifest and its roots) refuses or caps:
// none blocks, and none reads anything outside the tree.
func TestHostileWorkspace(t *testing.T) {
	const outTok = "gate-oauth-outside-OOOOOOOOOOOOOOOOOOOO"
	out, ws, home := t.TempDir(), t.TempDir(), t.TempDir()
	cred := `{"claudeAiOauth":{"accessToken":"` + outTok + `"}}`
	os.WriteFile(filepath.Join(out, "approvers"), []byte(cred), 0o600)
	os.MkdirAll(filepath.Join(out, "claude"), 0o700)
	os.WriteFile(filepath.Join(out, "claude", "settings.json"), []byte(cred), 0o600)
	os.WriteFile(filepath.Join(out, "pyvenv.cfg"), nil, 0o600)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink("/etc/shadow", filepath.Join(ws, "shadow")))
	must(os.Symlink(filepath.Join(out, "approvers"), filepath.Join(ws, "approvers")))
	must(os.Symlink(filepath.Join(out, "claude"), filepath.Join(ws, ".claude")))
	must(syscall.Mkfifo(filepath.Join(ws, "package-lock.json"), 0o644))
	must(syscall.Mkfifo(filepath.Join(ws, ".mcp.json"), 0o644))
	for _, f := range []string{"go.sum", "AGENTS.md"} { // AGENTS.md: a control path the manifest would hash
		g, err := os.Create(filepath.Join(ws, f))
		must(err)
		must(g.Truncate(2 << 30))
		g.Close()
	}
	must(os.MkdirAll(filepath.Join(ws, "venv"), 0o755))
	must(os.Symlink(filepath.Join(out, "pyvenv.cfg"), filepath.Join(ws, "venv", "pyvenv.cfg")))
	must(os.WriteFile(filepath.Join(ws, "venv", "x.pth"), nil, 0o644))
	must(os.MkdirAll(filepath.Join(home, ".claude", "rules"), 0o700))
	must(os.MkdirAll(filepath.Join(home, ".codex"), 0o700))
	must(os.Symlink(filepath.Join(out, "approvers"), filepath.Join(home, ".claude", ".credentials.json")))
	must(syscall.Mkfifo(filepath.Join(home, ".codex", "auth.json"), 0o600))
	must(os.Symlink(filepath.Join(out, "claude"), filepath.Join(home, ".claude", "rules", "r")))

	done := make(chan struct{})
	go func() {
		defer close(done)
		if got, err := Tokens(home); len(got) != 0 || err == nil {
			t.Errorf("Tokens read through a link or FIFO, or gave no error for them: %q %v", got, err)
		}
		hits, err := Scan(ws, time.Time{}, []string{outTok})
		if err != nil || len(hits) != 0 {
			t.Errorf("Scan = %v, %v; want no hit (nothing outside is read)", hits, err)
		}
		m, err := Controls(Paths{Workspace: ws, SessionHome: home})
		if err != nil {
			t.Errorf("Controls: %v", err)
			return
		}
		want := map[string]string{
			".claude":                 "link " + filepath.Join(out, "claude"),
			".mcp.json":               "special p---------",
			Home + "/.claude/rules/r": "link " + filepath.Join(out, "claude"),
		}
		for k, v := range want {
			if m[k] != v {
				t.Errorf("Controls[%s] = %q, want %q", k, m[k], v)
			}
		}
		if !strings.HasPrefix(m["AGENTS.md"], "-rw-r--r-- large 2147483648 ") {
			t.Errorf("Controls[AGENTS.md] = %q: a 2 GiB control file is recorded by size and ctime, not hashed", m["AGENTS.md"])
		}
		for k := range m {
			if strings.HasPrefix(k, ".claude/") || strings.HasPrefix(k, "venv/") || k == "package-lock.json" || k == "go.sum" {
				t.Errorf("Controls has %s: through a link, or not a control path", k)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("a reader blocked on the hostile workspace")
	}
}

package git

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain doubles as the pre-receive hook: the test repos' hooks dir holds a script that runs this binary with
// AGENTBOX_TEST_HOOK=1, so a real git push runs Hook as git runs it on the box.
func TestMain(m *testing.M) {
	if os.Getenv("AGENTBOX_TEST_HOOK") == "1" {
		os.Exit(Hook(os.Stdin, os.Stdout, os.Stderr, os.Getenv, time.Now()))
	}
	os.Exit(m.Run())
}

// hooksDir writes a hooks dir whose pre-receive runs this test binary as the hook.
func hooksDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nAGENTBOX_TEST_HOOK=1 exec '" + exe + "'\n"
	if err := os.WriteFile(filepath.Join(d, "pre-receive"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

// shortDir is a temp dir with a short path: a Unix socket path must fit in 104 bytes on macOS.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "agb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// fake is a line server on a Unix socket that records each request and answers with reply.
type fake struct {
	mu    sync.Mutex
	reqs  []map[string]any
	reply func(map[string]any) map[string]any
	path  string
}

func newFake(t *testing.T, name string, reply func(map[string]any) map[string]any) *fake {
	t.Helper()
	f := &fake{reply: reply, path: filepath.Join(shortDir(t), name)}
	l, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadBytes('\n')
					if err != nil {
						return
					}
					var m map[string]any
					json.Unmarshal(line, &m)
					f.mu.Lock()
					f.reqs = append(f.reqs, m)
					f.mu.Unlock()
					b, _ := json.Marshal(f.reply(m))
					c.Write(append(b, '\n'))
				}
			}()
		}
	}()
	return f
}

// seen is the recorded requests whose key k is v.
func (f *fake) seen(k, v string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, r := range f.reqs {
		if r[k] == v {
			out = append(out, r)
		}
	}
	return out
}

func ack(map[string]any) map[string]any { return map[string]any{"ok": true} }

// gitIn runs git in dir with a fixed identity and returns its combined output.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitTry(dir, nil, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(out)
}

func gitTry(dir string, env []string, args ...string) (string, error) {
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Env = append(Env(append(Ident, "GIT_AUTHOR_DATE=1700000000 +0000", "GIT_COMMITTER_DATE=1700000000 +0000")...), env...)
	out, err := c.CombinedOutput()
	return string(out), err
}

// work is a fresh work tree with one commit of file name holding body.
func work(t *testing.T, name, body string) string {
	t.Helper()
	d := t.TempDir()
	gitIn(t, d, "init", "-q", "-b", "main")
	commit(t, d, name, body)
	return d
}

func commit(t *testing.T, d, name, body string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, d, "add", name)
	gitIn(t, d, "commit", "-q", "-m", "add "+name)
	return gitIn(t, d, "rev-parse", "HEAD")
}

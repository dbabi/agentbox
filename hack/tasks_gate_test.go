package hack

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestTasksGatePIDTakeover runs tasks-gate.sh's #125 check as root, under dash in a new PID namespace, with a setpriv
// that sleeps 0.5 s before it drops to the agent uid, as on a busy host. Until the drop, the process at the dead pause
// process's PID is root's, so the check must wait for its exec of sleep before it reads the owner (#169).
func TestTasksGatePIDTakeover(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux, for ns_last_pid, setpriv and a PID namespace")
	}
	sp, err := exec.LookPath("setpriv")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("tasks-gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)\ncheck "#125: [^"]*" '(.*?)'\n`).FindSubmatch(src)
	if m == nil {
		t.Fatal("the #125 check not found in tasks-gate.sh")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { // setpriv looks sleep up on PATH as the agent uid
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "setpriv"), []byte("#!/bin/sh\nsleep 0.5\nexec "+sp+" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	reused, pp := filepath.Join(dir, "reused"), filepath.Join(dir, "pause.pid")
	check := strings.ReplaceAll(string(m[1]), "/tmp/tg-reused", reused)
	// dash is PID 1 of the namespace, and its child sleep stands in for the pause process; all of them die with it
	script := "PATH=" + dir + ":$PATH PP=" + pp + " U=70001\nsleep 600 </dev/null >/dev/null 2>&1 & echo $! > $PP\n(eval \"$1\")"
	if out, err := exec.Command("unshare", "--pid", "--fork", "--mount-proc", "dash", "-c", script, "dash", check).CombinedOutput(); err != nil {
		t.Fatalf("the check failed: %v\n%s", err, out)
	}
	p, _ := os.ReadFile(pp)
	r, err := os.ReadFile(reused)
	if err != nil || string(r) != string(p) {
		t.Fatalf("the check wrote %q (%v), want the pause PID %q", r, err, p)
	}
}

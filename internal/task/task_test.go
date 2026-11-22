package task

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The launch is Appendix C's: one systemd-run over the agent's user bus, --cgroups=split with Delegate=yes, no network,
// the task seccomp profile, a tmpfs HOME and only the task's own dirs.
func TestArgv(t *testing.T) {
	id := "task_01JD000000000000000000000Z"
	a := Argv(Spec{Task: id, Agent: "claude", Runtime: 7200 * time.Second, Deadline: time.UnixMilli(1_800_000_000_000),
		Workspace: "/var/lib/agentbox/data/workspaces/claude", Seccomp: "/var/lib/agentbox/control/seccomp-task.json",
		Image: "localhost/agentbox-task:x", HostUsr: []string{"/usr/bin"}})
	s := strings.Join(a, " ")
	for _, want := range []string{
		"systemd-run --user -M ag-claude@ --unit=agentbox-task-" + id + ".service --collect",
		"-p Delegate=yes -p KillMode=mixed -p TimeoutStopSec=15 -p RuntimeMaxSec=7200",
		"-p ExecStopPost=-/usr/bin/podman rm -f -i -t 0 task-" + id + " /usr/bin/podman run --cgroups=split --rm --name task-" + id,
		"--network=none --userns=keep-id --security-opt=no-new-privileges --cap-drop=all --security-opt=seccomp=/var/lib/agentbox/control/seccomp-task.json",
		"--read-only --tmpfs /tmp:rw,size=2g --mount type=tmpfs,destination=/home/agent,tmpfs-size=4g,tmpfs-mode=0700,U=true --pids-limit=4096 --log-driver=none",
		"-v /var/lib/agentbox/data/workspaces/claude:/workspace",
		"-v /run/agentbox-gate/t/" + id + ":/run/agentbox/gate:ro -v /run/agentbox-proxy/t/" + id + ":/run/agentbox/egress:ro",
		"-v /run/agentbox-keys/t/" + id + ":/run/agentbox/llm:ro -v /run/agentbox-git/t/" + id + ":/run/agentbox/git:ro",
		"-v /var/lib/agentbox/control/exports/claude:/opt/agentbox/exports:ro -v /var/lib/agentbox/current/bin/agentbox:/usr/local/bin/agentbox:ro",
		"-v /usr/bin:/usr/bin:ro",
		"-e GIT_CONFIG_KEY_0=core.hooksPath -e GIT_CONFIG_VALUE_0=/opt/agentbox/exports/nohooks -e GIT_CONFIG_KEY_1=core.fsmonitor -e GIT_CONFIG_VALUE_1=false",
		"-e AGENTBOX_DEADLINE=1800000000000",
		"localhost/agentbox-task:x /usr/local/bin/agentbox taskrun",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("argv lacks %q:\n%s", want, s)
		}
	}
	for _, bad := range []string{"--privileged", "--network=host", "--cap-add", "seccomp=unconfined", "--pid=host", "session-home"} {
		if strings.Contains(s, bad) {
			t.Errorf("argv has %q", bad)
		}
	}
	if n := strings.Count(s, "systemd-run"); n != 1 {
		t.Errorf("%d systemd-run calls", n)
	}
}

// Claude ignores project settings and .mcp.json and runs with hooks off (§4.2); a planted HOME config can't matter,
// because HOME is a fresh tmpfs, but these flags hold even for a workspace that plants them.
func TestCLIArgv(t *testing.T) {
	a, _ := CLIArgv("claude")
	s := strings.Join(a, " ")
	for _, want := range []string{"--setting-sources user", "--strict-mcp-config", "--settings /opt/agentbox/exports/claude-settings.json",
		"--mcp-config /opt/agentbox/exports/mcp.json"} {
		if !strings.Contains(s, want) {
			t.Errorf("claude argv lacks %q", want)
		}
	}
	var st map[string]any
	if err := json.Unmarshal([]byte(Exports["claude-settings.json"]), &st); err != nil || st["disableAllHooks"] != true || len(st) != 1 {
		t.Errorf("claude-settings.json: %v %v", st, err)
	}
	if c, _ := CLIArgv("codex"); !slices.Contains(c, "-") {
		t.Errorf("codex must read the prompt on stdin: %v", c)
	}
	if _, err := CLIArgv("bash"); err == nil {
		t.Error("an unknown CLI must be refused")
	}
}

func TestSkeletonStable(t *testing.T) {
	if string(Skeleton()) != string(Skeleton()) || !strings.HasPrefix(Image(), "localhost/agentbox-task:") {
		t.Fatal("the skeleton tar must be the same bytes every time")
	}
}

// A gate that is down (ENOENT, ECONNREFUSED) is retried with backoff; taskrun gives up 60 s before the deadline.
func TestCallRetries(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "gate.sock")
	now := time.Unix(0, 0)
	var slept []time.Duration
	r := &Runner{Sock: sock, Deadline: now.Add(10 * time.Minute), Now: func() time.Time { return now },
		Sleep: func(d time.Duration) {
			slept = append(slept, d)
			now = now.Add(d)
			if len(slept) == 3 {
				ln, err := net.Listen("unix", sock)
				if err != nil {
					t.Fatal(err)
				}
				go func() {
					c, _ := ln.Accept()
					bufio.NewReader(c).ReadBytes('\n')
					c.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"task":"t","cli":"sh","prompt":"echo"}}` + "\n"))
					c.Close()
				}()
			}
		}}
	var j Job
	if err := r.Call("task.fetch", map[string]any{}, &j); err != nil || j.CLI != "sh" || j.Prompt != "echo" {
		t.Fatalf("%v %+v", err, j)
	}
	if !slices.Equal(slept, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Fatalf("backoff %v", slept)
	}
	r = &Runner{Sock: filepath.Join(dir, "none"), Deadline: now.Add(90 * time.Second), Now: func() time.Time { return now },
		Sleep: func(d time.Duration) { now = now.Add(d) }}
	if err := r.Call("task.fetch", nil, nil); err == nil || !strings.Contains(err.Error(), "60 s before the deadline") {
		t.Fatalf("want a give-up error, got %v", err)
	}
}

func TestSetupAndExports(t *testing.T) {
	ex, home := t.TempDir(), t.TempDir()
	if err := WriteExports(ex); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(ex, "nohooks")); err != nil || !fi.IsDir() {
		t.Fatal("no nohooks dir")
	}
	r := &Runner{Home: home, Exports: ex}
	if err := r.Setup(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if string(b) != Exports["claude-settings.json"] {
		t.Fatalf("settings %q", b)
	}
}

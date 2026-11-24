package task

import (
	"archive/tar"
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"agentbox/internal/ops"
	"agentbox/internal/taskenv"
)

// The launch is Appendix C's: one systemd-run over the agent's user bus, --cgroups=split with Delegate=yes, no network,
// the task seccomp profile, a tmpfs HOME and only the task's own dirs.
func TestArgv(t *testing.T) {
	id := "task_01JD000000000000000000000Z"
	a := Argv(Spec{Task: id, Agent: "claude", Runtime: 7200 * time.Second, Deadline: time.UnixMilli(1_800_000_000_000),
		Workspace: "/var/lib/agentbox/data/workspaces/claude", Seccomp: "/var/lib/agentbox/control/seccomp-task.json",
		Image: "localhost/agentbox-task:x", HostUsr: []string{"/usr/bin"},
		Env: []string{"-e", "GOPROXY=off"}, Witness: "/run/agentbox-witness/t/" + id})
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
		"-v /run/agentbox-witness/t/" + id + ":/run/agentbox/witness:ro -v /var/lib/agentbox/control/exports/claude:/opt/agentbox/exports:ro -v /var/lib/agentbox/current/bin/agentbox:/usr/local/bin/agentbox:ro",
		"-v /usr/bin:/usr/bin:ro",
		"-e GIT_CONFIG_COUNT=3 -e GIT_CONFIG_KEY_0=core.hooksPath -e GIT_CONFIG_VALUE_0=/opt/agentbox/exports/nohooks -e GIT_CONFIG_KEY_1=core.fsmonitor -e GIT_CONFIG_VALUE_1=false",
		"-e GIT_CONFIG_KEY_2=safe.bareRepository -e GIT_CONFIG_VALUE_2=explicit",
		"-e AGENTBOX_DEADLINE=1800000000000",
		"-e GOPROXY=off localhost/agentbox-task:x /usr/local/bin/agentbox taskrun",
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
	for _, c := range []string{"bash", "opencode"} {
		if _, err := CLIArgv(c); err == nil {
			t.Errorf("%s must be refused", c)
		}
	}
	for _, c := range []string{"claude", "codex", "sh"} {
		a, _ := CLIArgv(c)
		for _, f := range DeniedFlags {
			if slices.Contains(a, f) || slices.Contains(a, "--bare") {
				t.Errorf("%s argv has %s or --bare", c, f)
			}
		}
	}
}

// #77, #121: the image's policy files lock what user and project config can't change back; the generated Codex
// config sends the model API to the forwarder and turns the same switches off.
func TestPolicyFiles(t *testing.T) {
	files := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(Skeleton()))
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		c, _ := io.ReadAll(tr)
		files[h.Name] = string(c)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(files["etc/claude-code/managed-settings.json"]), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"allowManagedHooksOnly", "allowManagedMcpServersOnly", "allowManagedPermissionRulesOnly", "disableAllHooks"} {
		if m[k] != true {
			t.Errorf("managed %s = %v", k, m[k])
		}
	}
	if a, ok := m["allowedMcpServers"].([]any); !ok || len(a) != 0 {
		t.Errorf("allowedMcpServers %v: want an empty allowlist", m["allowedMcpServers"])
	}
	r := files["etc/codex/requirements.toml"]
	for _, want := range []string{"\nallowed_web_search_modes = []\n", "\nallow_managed_hooks_only = true\n", "\n[features]\nhooks = false\nplugins = false\n",
		"\ncheck_for_update_on_startup = false\n", "\n[feedback]\nenabled = false\n"} {
		if !strings.Contains(r, want) {
			t.Errorf("requirements.toml lacks %q", want)
		}
	}
	c := Exports["codex-config.toml"]
	for _, want := range []string{"\nmodel_provider = \"agentbox\"\nweb_search = \"disabled\"\n", "\n[analytics]\nenabled = false\n", "\nexporter = \"none\"\n",
		"\n[model_providers.agentbox]\nname = \"agentbox\"\nbase_url = \"http://127.0.0.1:8081/openai/v1\"\n"} {
		if !strings.Contains(c, want) {
			t.Errorf("codex-config.toml lacks %q", want)
		}
	}
	if i, j := strings.Index(c, "model_provider ="), strings.Index(c, "\n["); i > j {
		t.Error("codex-config.toml: a top-level key after a table belongs to that table")
	}
	s := strings.Join(Argv(Spec{Task: "task_x", Agent: "a"}), " ")
	for _, want := range []string{"-e ANTHROPIC_BASE_URL=http://127.0.0.1:8081/anthropic", "-e DISABLE_UPDATES=1", "-e CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1",
		"-e CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"} {
		if !strings.Contains(s, want) {
			t.Errorf("argv lacks %q", want)
		}
	}
}

func TestSkeletonStable(t *testing.T) {
	a, b := Skeleton(), Skeleton()
	if string(a) != string(b) || !strings.HasPrefix(Image(), "localhost/agentbox-task:") {
		t.Fatal("the skeleton tar must be the same bytes every time")
	}
	tr := tar.NewReader(bytes.NewReader(a))
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatal("no etc/resolv.conf in the skeleton:", err)
		}
		if h.Name == "etc/resolv.conf" {
			if c, _ := io.ReadAll(tr); string(c) != taskenv.ResolvConf {
				t.Fatalf("resolv.conf %q", c)
			}
			return
		}
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
	for f, dst := range map[string]string{"CLAUDE.md": ".claude/CLAUDE.md", "AGENTS.md": ".codex/AGENTS.md"} {
		if b, _ := os.ReadFile(filepath.Join(home, dst)); string(b) != string(ops.Exports()[f]) {
			t.Fatalf("%s: %q", dst, b)
		}
	}
}

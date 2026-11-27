package task

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"agentbox/internal/gate"
	"agentbox/internal/ops"
	"agentbox/internal/taskenv"
	"agentbox/internal/taskrun"
)

// The launch is Appendix C's: one systemd-run over the agent's user bus, --cgroups=split with Delegate=yes, no network,
// the task seccomp profile, a tmpfs HOME and only the task's own dirs.
func TestArgv(t *testing.T) {
	id := "task_01JD000000000000000000000Z"
	a := Argv(Spec{Task: id, Agent: "claude", UID: 70001, GID: 70001, Runtime: 7200 * time.Second, Deadline: time.UnixMilli(1_800_000_000_000),
		Workspace: "/var/lib/agentbox/data/workspaces/claude", Seccomp: "/var/lib/agentbox/control/seccomp-task.json",
		Image: "localhost/agentbox-task:x", HostUsr: []string{"/usr/bin"},
		Env: []string{"-e", "GOPROXY=off"}, Witness: "/run/agentbox-witness/t/" + id})
	s := strings.Join(a, " ")
	for _, want := range []string{
		"systemd-run --user -M ag-claude@ --unit=agentbox-task-" + id + ".service --collect",
		"-p Delegate=yes -p KillMode=mixed -p TimeoutStopSec=15 -p RuntimeMaxSec=7200",
		"-p ExecStopPost=-/usr/bin/podman rm -f -i -t 0 task-" + id + " /usr/bin/podman run --cgroups=split --rm --name task-" + id,
		"--network=none --userns=keep-id --user=70001:70001 --security-opt=no-new-privileges --cap-drop=all --security-opt=seccomp=/var/lib/agentbox/control/seccomp-task.json",
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
		"-e CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "-e CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1", "-e CLAUDE_CODE_AUTO_MODE_SERVER=0"} {
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

// #223: 16 KiB of ESC is 96 KiB as JSON. With the most denials the result can carry, the post still fits one gate
// line: only the oldest output bytes go, and a logged denial over 1 KiB is left out.
func TestResultFits(t *testing.T) {
	d := ops.Deny(ops.BrokerUnavailable, "egress", ops.Slots{By: "forwarder"})
	d.Msg += strings.Repeat("<", (ops.MaxDenial-len(d.JSON()))/6) // '<' is 6 bytes as JSON
	d.Msg += strings.Repeat("a", ops.MaxDenial-len(d.JSON()))
	big := d
	big.Msg += "a"
	if len(d.JSON()) != ops.MaxDenial || len(big.JSON()) != ops.MaxDenial+1 {
		t.Fatalf("denials of %d and %d bytes", len(d.JSON()), len(big.JSON()))
	}
	var lines []string
	for range taskrun.LogMax - 1 {
		lines = append(lines, string(d.JSON()))
	}
	log := filepath.Join(t.TempDir(), "denials.jsonl")
	if err := os.WriteFile(log, []byte(strings.Join(append(lines, string(big.JSON())), "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := strings.Repeat("x", 100) + strings.Repeat("\x1b", MaxResultOutput-100)
	res := Result{Exit: 0, Output: out, OutputLen: 1 << 30, ProbeMS: 5, Denials: denials(log)}
	if len(res.Denials) != MaxResultDenials {
		t.Fatalf("%d denials", len(res.Denials))
	}
	b := fit(res)
	if n := len(request("task.result", json.RawMessage(b))); n > gate.MaxRequest || n <= gate.MaxRequest-6 {
		t.Fatalf("a request of %d bytes", n)
	}
	var got Result
	if err := json.Unmarshal(b, &got); err != nil || !strings.HasSuffix(out, got.Output) || len(got.Output) < 5000 ||
		got.OutputLen != 1<<30 || len(got.Denials) != MaxResultDenials {
		t.Fatalf("%v: %d output bytes, %d denials", err, len(got.Output), len(got.Denials))
	}
	small := Result{Exit: 3, Output: "done\n", OutputLen: 5}
	if b, _ := json.Marshal(small); !bytes.Equal(fit(small), b) {
		t.Fatal("a result that fits must be sent as it is")
	}
}

// #223: post writes END <sha256 of the params> to the witness before the gate gets them, since the gate stops the task
// before it answers.
func TestPostWritesEND(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "post") // sun_path is 104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock, wit := filepath.Join(dir, "gate.sock"), filepath.Join(dir, "witness")
	if err := os.WriteFile(wit, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type got struct{ line, witness []byte }
	ch := make(chan got, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		line, _ := bufio.NewReader(c).ReadBytes('\n')
		w, _ := os.ReadFile(wit)
		ch <- got{line, w}
		c.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"stopped":"completed"}}` + "\n"))
		c.Close()
	}()
	rec := &taskrun.Recorder{Log: filepath.Join(dir, "denials.jsonl"), Witness: wit}
	r := &Runner{Sock: sock, Deadline: time.Now().Add(time.Hour), Now: time.Now, Sleep: time.Sleep}
	if err := r.post(rec, Result{Exit: 0, Output: "<ok>\n", OutputLen: 5}); err != nil {
		t.Fatal(err)
	}
	g := <-ch
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(g.line, &req); err != nil || req.Method != "task.result" {
		t.Fatalf("%v: %s", err, g.line)
	}
	sum := sha256.Sum256(req.Params)
	if want := "END " + hex.EncodeToString(sum[:]) + "\n"; string(g.witness) != want {
		t.Fatalf("witness %q when the post arrived, want %q", g.witness, want)
	}
	if _, err := ops.ParseWitness(strings.TrimSuffix(string(g.witness), "\n")); err != nil {
		t.Fatal(err)
	}
}

// The Go module filter's taint call is one task.taint_self{source: cache:go} on the gate socket, with no retry: a gate
// that is down fails it at once, so go falls back to CONNECT.
func TestGoFilterTaint(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "gof") // sun_path is 104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "gate.sock")
	slept := 0
	r := &Runner{Sock: sock, Deadline: time.Now().Add(time.Hour), Now: time.Now, Sleep: func(time.Duration) { slept++ }}
	t.Setenv("GOPRIVATE", "corp.example/*")
	f := r.goFilter()
	if err := f.Taint(); err == nil || slept != 0 || f.Private != "corp.example/*" {
		t.Fatalf("a missing gate: %v after %d retries; private %q", err, slept, f.Private)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		line, _ := bufio.NewReader(c).ReadBytes('\n')
		got <- line
		c.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"))
		c.Close()
	}()
	if err := f.Taint(); err != nil {
		t.Fatal(err)
	}
	if l := <-got; !strings.Contains(string(l), `"method":"task.taint_self","params":{"source":"cache:go"}`) {
		t.Fatalf("request %s", l)
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

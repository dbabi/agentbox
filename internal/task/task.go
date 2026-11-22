// Package task is the per-task container (ARCHITECTURE.md §4.2, Appendix C): the launch argv rootd runs, the task
// image, the generated CLI configs it mounts, and taskrun, the container's PID 1.
package task

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"agentbox/internal/ops"
	"agentbox/internal/taskenv"
)

// Paths on the box.
const (
	ControlDir  = "/var/lib/agentbox/control"
	ExportsDir  = ControlDir + "/exports" // <agent>/: the generated CLI configs, mounted read-only
	Binary      = "/var/lib/agentbox/current/bin/agentbox"
	Podman      = "/usr/bin/podman"
	ImageTar    = ControlDir + "/task-image.tar" // the image's root skeleton, imported per agent (stub, below)
	StopTimeout = 15 * time.Second               // TimeoutStopSec: SIGTERM to SIGKILL
)

// Svcs are the services with a per-task socket dir, and where the container sees each one (Appendix C).
var Svcs = []struct{ Name, Mount string }{
	{"gate", "/run/agentbox/gate"}, {"proxy", "/run/agentbox/egress"}, {"keys", "/run/agentbox/llm"}, {"git", "/run/agentbox/git"},
}

// SvcUser is the service user that owns each per-task dir and binds its socket (§2.1).
var SvcUser = map[string]string{"gate": "agentbox", "proxy": "agentbox-proxy", "keys": "agentbox-keys", "git": "agentbox-git"}

// SockDir is /run/agentbox-<svc>/t/<task>, which rootd creates and the service binds <svc>.sock in.
func SockDir(svc, task string) string { return "/run/agentbox-" + svc + "/t/" + task }

// Unit is the transient user unit, and Container the container, of task.
func Unit(task string) string      { return "agentbox-task-" + task + ".service" }
func Container(task string) string { return "task-" + task }

// CgroupDir is the unit's cgroup under the agent's user manager, relative to the cgroup2 root.
func CgroupDir(uid uint32, task string) string {
	u := strconv.FormatUint(uint64(uid), 10)
	return "user.slice/user-" + u + ".slice/user@" + u + ".service/app.slice/" + Unit(task)
}

// Spec is everything the launch argv is built from: typed values only, nothing interpolated from agent input.
type Spec struct {
	Task, Agent string // already validated: ids.Is("task", Task), an existing account
	Runtime     time.Duration
	Deadline    time.Time
	Workspace   string
	Seccomp     string
	Image       string
	HostUsr     []string // the host dirs the stub image mounts read-only (HostUsr)
	Env         []string // the task env's podman args (taskenv.ForAgent)
	Witness     string   // the task's witness dir, mounted read-only at /run/agentbox/witness
}

// Argv is rootd's one launch per task (Appendix C): one systemd-run over the agent's user bus, which opens the task's
// one login session. --cgroups=split with Delegate=yes keeps conmon and the payload inside the unit, so unit stop,
// RuntimeMaxSec and cgroup.kill reach every process of the task.
func Argv(s Spec) []string {
	sec := int64(s.Runtime / time.Second)
	if sec < 1 {
		sec = 1
	}
	a := []string{"systemd-run", "--user", "-M", "ag-" + s.Agent + "@", "--unit=" + Unit(s.Task), "--collect", "--quiet",
		"-p", "Delegate=yes", "-p", "KillMode=mixed", "-p", "TimeoutStopSec=" + strconv.Itoa(int(StopTimeout/time.Second)),
		"-p", "RuntimeMaxSec=" + strconv.FormatInt(sec, 10),
		"-p", "ExecStopPost=-" + Podman + " rm -f -i -t 0 " + Container(s.Task),
		Podman, "run", "--cgroups=split", "--rm", "--name", Container(s.Task), "--network=none", "--userns=keep-id",
		"--security-opt=no-new-privileges", "--cap-drop=all", "--security-opt=seccomp=" + s.Seccomp,
		"--read-only", "--tmpfs", "/tmp:rw,size=2g", "--mount", "type=tmpfs,destination=/home/agent,tmpfs-size=4g,tmpfs-mode=0700,U=true",
		"--pids-limit=4096", "--log-driver=none",
		"-v", s.Workspace + ":/workspace"}
	for _, v := range Svcs {
		a = append(a, "-v", SockDir(v.Name, s.Task)+":"+v.Mount+":ro")
	}
	a = append(a, "-v", s.Witness+":/run/agentbox/witness:ro",
		"-v", filepath.Join(ExportsDir, s.Agent)+":/opt/agentbox/exports:ro", "-v", Binary+":/usr/local/bin/agentbox:ro")
	for _, m := range s.HostUsr {
		a = append(a, "-v", m+":"+m+":ro")
	}
	a = append(a, "-e", "HOME=/home/agent", "-e", "CODEX_HOME=/home/agent/.codex", "-e", "ANTHROPIC_BASE_URL="+LLM+"/anthropic",
		"-e", "ANTHROPIC_API_KEY="+LLMKey)
	for _, e := range ClaudeQuiet {
		a = append(a, "-e", e)
	}
	a = append(a, "-e", "AGENTBOX_DEADLINE="+strconv.FormatInt(s.Deadline.UnixMilli(), 10),
		"-e", "GIT_CONFIG_COUNT=2", "-e", "GIT_CONFIG_KEY_0=core.hooksPath", "-e", "GIT_CONFIG_VALUE_0=/opt/agentbox/exports/nohooks",
		"-e", "GIT_CONFIG_KEY_1=core.fsmonitor", "-e", "GIT_CONFIG_VALUE_1=false")
	return append(append(a, s.Env...), s.Image, "/usr/local/bin/agentbox", "taskrun")
}

// LLM is the in-task LLM forwarder (taskrun.Channels), and LLMKey the placeholder key the CLIs send it: the keys
// broker swaps in the real one (§4.3).
const (
	LLM    = "http://127.0.0.1:8081"
	LLMKey = "agentbox-placeholder"
)

// ClaudeQuiet turns off Claude Code's update, telemetry and marketplace traffic (#121; code.claude.com/docs/en/env-vars):
// the first var doesn't cover the official marketplace auto-install, and DISABLE_UPDATES also blocks `claude update`.
var ClaudeQuiet = []string{"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "DISABLE_UPDATES=1", "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1"}

// ClaudeManaged is Claude Code's managed settings, /etc/claude-code/managed-settings.json in the task image (attach
// binds a superset there). Nothing in user, project or --settings files overrides a managed key
// (code.claude.com/docs/en/settings), so a claude run without the task flags still loads no hook, MCP server,
// permission rule or marketplace from the workspace. No managed-mcp.json: with one, Claude exits on --strict-mcp-config
// and --mcp-config (code.claude.com/docs/en/managed-mcp); the empty managed allowlist admits no server instead.
// WebSearch runs on the model provider's side, outside the proxy, like Codex's web_search.
var ClaudeManaged = map[string]any{
	"allowManagedHooksOnly":           true,
	"allowManagedMcpServersOnly":      true,
	"allowManagedPermissionRulesOnly": true,
	"allowedMcpServers":               []string{},
	"disableAllHooks":                 true,
	"permissions":                     map[string]any{"deny": []string{"WebSearch"}},
	"strictKnownMarketplaces":         []string{},
}

// ClaudeManagedJSON is ClaudeManaged as the file holds it.
func ClaudeManagedJSON() string {
	b, _ := json.MarshalIndent(ClaudeManaged, "", "  ")
	return string(b) + "\n"
}

// CodexRequirements is /etc/codex/requirements.toml in the task image, which user, project and -c config can't
// override (learn.chatgpt.com/docs/config-file/config-reference.md): only web_search "disabled", no hooks even with
// --dangerously-bypass-hook-trust (learn.chatgpt.com/docs/hooks), no plugins (their startup sync fetches github.com and
// chatgpt.com), no update check and no /feedback.
const CodexRequirements = `# agentbox task image (ARCHITECTURE.md §4.2): admin-enforced, above every Codex config layer
allowed_web_search_modes = []
allow_managed_hooks_only = true
check_for_update_on_startup = false

[features]
hooks = false
plugins = false

[feedback]
enabled = false
`

// CodexQuiet is the top of every generated Codex config, task and attach: the same switches, plus no analytics and
// no OpenTelemetry export (#121).
const CodexQuiet = `web_search = "disabled"
check_for_update_on_startup = false

[features]
hooks = false
plugins = false

[analytics]
enabled = false

[feedback]
enabled = false

[otel]
exporter = "none"
metrics_exporter = "none"
trace_exporter = "none"
`

// Exports are the generated CLI configs (§4.2 "Inside the container"), by file name under ExportsDir/<agent>.
// disableAllHooks stops project, local and skill frontmatter hooks; the CLI flags in CLIArgv ignore project settings
// and .mcp.json. Codex sends the model API to the LLM forwarder.
var Exports = map[string]string{
	"claude-settings.json": "{\n  \"disableAllHooks\": true\n}\n",
	"mcp.json":             "{\n  \"mcpServers\": {}\n}\n",
	"codex-config.toml": "# generated by agentbox: no [projects] trust entries, no MCP servers\nmodel_provider = \"agentbox\"\n" + CodexQuiet +
		"\n[model_providers.agentbox]\nname = \"agentbox\"\nbase_url = \"" + LLM + "/openai/v1\"\n",
}

// WriteExports makes ExportsDir/<agent> hold exactly Exports, the generated CLAUDE.md and AGENTS.md (ops.Exports, §8)
// and the empty nohooks dir, root-owned and world-readable.
func WriteExports(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, "nohooks"), 0o755); err != nil {
		return err
	}
	for _, d := range []string{filepath.Dir(dir), dir, filepath.Join(dir, "nohooks")} {
		if err := os.Chmod(d, 0o755); err != nil { // rootd runs with umask 0077, and the agent uid must read these
			return err
		}
	}
	all := maps.Clone(Exports)
	for n, b := range ops.Exports() {
		all[n] = string(b)
	}
	for n, c := range all {
		if b, err := os.ReadFile(filepath.Join(dir, n)); err == nil && string(b) == c {
			continue
		}
		t := filepath.Join(dir, "."+n+".new")
		if err := os.WriteFile(t, []byte(c), 0o644); err != nil {
			return err
		}
		if err := os.Chmod(t, 0o644); err != nil {
			return err
		}
		if err := os.Rename(t, filepath.Join(dir, n)); err != nil {
			return err
		}
	}
	return nil
}

// usrDirs are the host /usr dirs the stub image mounts read-only, when the host has them.
var usrDirs = []string{"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/share", "/etc/alternatives", "/etc/ld.so.cache"}

// HostUsr is the part of usrDirs that exists on this host.
//
// shortcut: the task image is a root skeleton plus the host's /usr, read-only; weeks 11-12's osbuild-image@ builds the
// pinned ubuntu:26.04 image with the CLIs baked in, and these mounts go.
func HostUsr() []string {
	var out []string
	for _, d := range usrDirs {
		if _, err := os.Stat(d); err == nil {
			out = append(out, d)
		}
	}
	return out
}

// Skeleton is the stub image's root file system as a tar, the same bytes on every box.
func Skeleton() []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	mt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := func(n string, mode int64) {
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: n + "/", Mode: mode, ModTime: mt})
	}
	link := func(n, to string) {
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: n, Linkname: to, Mode: 0o777, ModTime: mt})
	}
	file := func(n, c string) {
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(c)), ModTime: mt})
		tw.Write([]byte(c))
	}
	for _, d := range []string{"dev", "etc", "etc/alternatives", "etc/claude-code", "etc/codex", "home", "home/agent", "opt", "opt/agentbox", "opt/agentbox/exports",
		"proc", "root", "run", "sys", "usr", "usr/bin", "usr/lib", "usr/lib64", "usr/libexec", "usr/local", "usr/local/bin", "usr/sbin",
		"usr/share", "var", "workspace"} {
		dir(d, 0o755)
	}
	dir("tmp", 0o1777)
	dir("var/tmp", 0o1777)
	link("bin", "usr/bin")
	link("sbin", "usr/sbin")
	link("lib", "usr/lib")
	link("lib64", "usr/lib64")
	file("etc/ld.so.cache", "")
	file("usr/local/bin/agentbox", "")
	file("etc/passwd", "root:x:0:0:root:/root:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
	file("etc/group", "root:x:0:\nnogroup:x:65534:\n")
	file("etc/nsswitch.conf", "passwd: files\ngroup: files\nhosts: files\n")
	file("etc/resolv.conf", taskenv.ResolvConf) // podman leaves it as it is under --network=none
	file("etc/claude-code/managed-settings.json", ClaudeManagedJSON())
	file("etc/codex/requirements.toml", CodexRequirements)

	tw.Close()
	return b.Bytes()
}

// Image is the stub image's name: its tag is the skeleton's hash, so a box imports it once per skeleton change.
func Image() string {
	h := sha256.Sum256(Skeleton())
	return "localhost/agentbox-task:" + hex.EncodeToString(h[:6])
}

// DeniedFlags are CLI flags no task or attach argv may carry: each makes Codex run hooks or project config the policy
// files turn off.
var DeniedFlags = []string{"--dangerously-bypass-hook-trust", "--trust"}

// CLIArgv is the agent CLI taskrun runs, with the prompt on its stdin (§4.2). "sh" runs the prompt as a POSIX sh
// script; agentboxd hands it out only to test boxes (AGENTBOX_TEST_CLI=sh).
//
// Claude runs without --bare: bare mode skips CLAUDE.md, so INSTRUCTIONS.md would not reach the model, and limits the
// tools to Bash, Read and Edit, which --tools can't widen. hack/cli-gate.sh checks the instructions canary and the tool
// list against each pinned Claude Code, in case a release makes bare the -p default (#120). No opencode: 1.19.6 has no
// managed policy for plugins or MCP servers, and runs a workspace opencode.json plugin even with
// OPENCODE_DISABLE_PROJECT_CONFIG=1 (#77).
func CLIArgv(cli string) ([]string, error) {
	switch cli {
	case "claude":
		return []string{"claude", "-p", "--output-format", "json", "--dangerously-skip-permissions", "--setting-sources", "user",
			"--strict-mcp-config", "--settings", "/opt/agentbox/exports/claude-settings.json", "--mcp-config", "/opt/agentbox/exports/mcp.json"}, nil
	case "codex":
		return []string{"codex", "exec", "--json", "--dangerously-bypass-approvals-and-sandbox", "-C", "/workspace", "-"}, nil
	case "sh":
		return []string{"/bin/sh", "-s"}, nil
	}
	return nil, fmt.Errorf("unknown CLI %q", cli)
}

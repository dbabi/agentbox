// Package taskenv is the environment rootd gives every task container and taskrun cleans before the CLI starts
// (ARCHITECTURE.md §4.2 "No DNS, fast failure", "One cache: Go modules", "Quiet package managers"; Appendix C):
// the proxy env, the Go env from the agent's allowlist and go.private patterns, and quiet npm and pip.
//
// No --dns=none: podman 5.7 (and 6.2) refuse it with --network=none ("conflicting options: dns and the network mode:
// none"), and with --network=none they already leave the image's /etc/resolv.conf in place, which is what --dns=none
// was for (Appendix C, R26). hack/taskenv-gate.sh checks the file inside a task.
package taskenv

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"agentbox/internal/rootd/gens"
	"agentbox/internal/rootd/resolve"
)

// The in-container endpoints (§4.2 Inside the container, step 2).
const (
	ProxyURL   = "http://127.0.0.1:8080"
	NoProxy    = "127.0.0.1,localhost,::1"
	GoFilter   = "http://127.0.0.1:8083"
	MaxPrivate = 1024
)

// ResolvConf is the task image's /etc/resolv.conf: nothing listens on 127.0.0.1:53, so a direct lookup fails in under
// 1 s instead of hanging on a resolver timeout (§4.2).
const ResolvConf = "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n"

// GoProxyEntry is the allowlist entry that turns on the Go module cache path.
var GoProxyEntry = resolve.Entry{Host: "proxy.golang.org", Port: 443}

// Unset is what taskrun removes before the CLI starts, in case the image sets them: only the admin scopes private
// paths (GOPRIVATE), and the egress path is HTTPS_PROXY alone.
var Unset = []string{"GOFLAGS", "GONOSUMDB", "GONOPROXY", "GOINSECURE", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"}

// Env is the task env for an agent: goProxy says whether its allowlist holds proxy.golang.org:443, goPrivate is its
// validated go.private patterns ("" for none).
func Env(goProxy bool, goPrivate string) []string {
	env := []string{"HTTPS_PROXY=" + ProxyURL, "https_proxy=" + ProxyURL, "NO_PROXY=" + NoProxy, "no_proxy=" + NoProxy}
	if goProxy {
		env = append(env, "GOPROXY="+GoFilter+",https://proxy.golang.org,direct", "GOSUMDB=sum.golang.org")
	} else {
		env = append(env, "GOPROXY=off") // go fails at once with its own error and opens no CONNECT
	}
	env = append(env, "GOTOOLCHAIN=local")
	if goPrivate != "" {
		env = append(env, "GOPRIVATE="+goPrivate)
	}
	return append(env, "npm_config_audit=false", "npm_config_fund=false", "npm_config_update_notifier=false",
		"NO_UPDATE_NOTIFIER=1", "PIP_DISABLE_PIP_VERSION_CHECK=1")
}

// PodmanArgs is the part of the podman run argv this package owns: one -e per Env entry.
func PodmanArgs(goProxy bool, goPrivate string) []string {
	var args []string
	for _, e := range Env(goProxy, goPrivate) {
		args = append(args, "-e", e)
	}
	return args
}

// ForAgent reads the agent's allowlist and go.private patterns from the egress dir and returns PodmanArgs for them.
func ForAgent(egressDir, agent string) ([]string, error) {
	if !reAgent.MatchString(agent) {
		return nil, fmt.Errorf("bad agent name %q", agent)
	}
	l, err := resolve.LoadLists(egressDir)
	if err != nil {
		return nil, err
	}
	gp, err := ReadGoPrivate(egressDir, agent)
	if err != nil {
		return nil, err
	}
	return PodmanArgs(l.Allowed("proxy", agent, GoProxyEntry), gp), nil
}

// Clean is taskrun's env step: it drops every Unset name.
func Clean() {
	for _, k := range Unset {
		os.Unsetenv(k)
	}
}

var (
	reAgent   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	rePattern = regexp.MustCompile(`^[A-Za-z0-9._~/*?\[\]-]+$`)
)

// ValidGoPrivate checks go.private.set's patterns (§5.3): comma-separated path.Match globs of module path prefixes,
// printable ASCII, at most 1 KiB. "" clears them.
func ValidGoPrivate(s string) error {
	if len(s) > MaxPrivate {
		return fmt.Errorf("patterns: longer than %d bytes", MaxPrivate)
	}
	if s == "" {
		return nil
	}
	for _, p := range strings.Split(s, ",") {
		if !rePattern.MatchString(p) {
			return fmt.Errorf("patterns: %q is not a module path glob", p)
		}
		if _, err := path.Match(p, "x"); err != nil {
			return fmt.Errorf("patterns: %q: %v", p, err)
		}
	}
	return nil
}

func goPrivateFile(dir, agent string) string { return filepath.Join(dir, agent+".goprivate") }

// ReadGoPrivate returns the agent's patterns, "" if it has none. A file that fails ValidGoPrivate is an error, so a
// hand-edited file never reaches the env unchecked.
func ReadGoPrivate(dir, agent string) (string, error) {
	b, err := os.ReadFile(goPrivateFile(dir, agent))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	s := strings.TrimSuffix(string(b), "\n")
	if err := ValidGoPrivate(s); err != nil {
		return "", fmt.Errorf("%s: %v", goPrivateFile(dir, agent), err)
	}
	return s, nil
}

// WriteGoPrivate is go.private.set's effect: control/egress/<agent>.goprivate, written atomically; "" removes it.
// It reports whether anything changed.
func WriteGoPrivate(dir, agent, patterns string) (bool, error) {
	if !reAgent.MatchString(agent) {
		return false, fmt.Errorf("bad agent name %q", agent)
	}
	if err := ValidGoPrivate(patterns); err != nil {
		return false, err
	}
	old, err := ReadGoPrivate(dir, agent)
	if err != nil {
		old = "\x00" // an invalid file is always replaced
	}
	if old == patterns {
		return false, nil
	}
	if patterns == "" {
		return true, os.Remove(goPrivateFile(dir, agent))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	return true, gens.WriteAtomic(goPrivateFile(dir, agent), []byte(patterns+"\n"), 0o644)
}

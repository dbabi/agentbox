// Package git is agentbox-git (ARCHITECTURE.md §2, §5.3, §6.3): the git service. It serves each task's local bare
// repos over smart HTTP on the task's own git.sock, with a root-owned pre-receive hook that keeps pushes inside
// refs/heads/agent/<name>/, under the daily byte cap, and free of the task's canary (#105). It applies read taint to a
// task that fetches a tainted ref. It holds the GitHub token and runs the remote writes of the registry ops
// (repo.push, gh.pr.create, gh.*.comment) and repo.merge, each only when rootd sends it an approved op on
// svc-git.sock, and finds an effect again after a rootd restart (reconcile). It never resolves a name: rootd does,
// on resolve-git.sock, and the service dials only rootd's answers (§6.3 pinned dialing).
package git

import (
	"errors"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Paths and limits on the box.
const (
	Root        = "/var/lib/agentbox/git" // git/: <agent>/<project>.git and the service's .state.db (a subvolume under 2/0)
	TaskDir     = "/run/agentbox-git"     // rootd makes t/<task>/; the service binds git.sock there
	SvcSock     = "/run/agentbox-rootd/svc-git.sock"
	ResolveSock = "/run/agentbox-rootd/resolve-git.sock"
	AuditSock   = "/run/agentbox-audit/git.sock"
	// HooksDir is the release's root-owned hooks dir, core.hooksPath for every local push: only pre-receive is in it.
	HooksDir = "/var/lib/agentbox/current/git-hooks"
	// MaxPushBytes is receive.maxInputSize, git's own cap on one push (§6.3), and DayPushBytes the default cap on
	// each agent's pushed bytes per UTC day (budgets.toml push_bytes_day). shortcut: budgets.toml isn't read yet;
	// `agentbox git --push-day-bytes` sets it until the budget ops land.
	MaxPushBytes = 512 << 20
	DayPushBytes = 4 << 30
	// WebHost serves git over https and APIHost GitHub REST; service.list must name both, port 443.
	WebHost = "github.com"
	APIHost = "api.github.com"
)

var (
	reAgent   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	reProject = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	reOID     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	// a GitHub owner or repo name: what GitHub itself allows, minus a leading dot
	reGHName = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}$`)
)

// ValidProject reports whether p names a local repo: one lowercase label, so a path element is all it can be.
func ValidProject(p string) bool { return reProject.MatchString(p) }

// ValidOID reports whether o is a full sha1 or sha256 object id in lower-case hex.
func ValidOID(o string) bool { return reOID.MatchString(o) }

// Repo is agent's local bare repo project under root.
func Repo(root, agent, project string) string { return filepath.Join(root, agent, project+".git") }

// RepoName is the repo part of a ref subject: <agent>/<project>.
func RepoName(agent, project string) string { return agent + "/" + project }

// RefSubject is a ref's taint subject (§5.2): ref:<agent>/<project>:<ref>.
func RefSubject(agent, project, ref string) string {
	return "ref:" + RepoName(agent, project) + ":" + ref
}

// Namespace is the one ref prefix an agent may push to (§6.3): refs/heads/agent/<name>/.
func Namespace(agent string) string { return "refs/heads/agent/" + agent + "/" }

var reRefTail = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}$`)

// InNamespace reports whether ref is a branch under agent's namespace with a name git and the denial grammar both
// accept: no "..", "//", "@{", trailing "/", ".lock" or ".".
func InNamespace(agent, ref string) bool {
	tail, ok := strings.CutPrefix(ref, Namespace(agent))
	return ok && reRefTail.MatchString(tail) && !strings.Contains(tail, "..") && !strings.Contains(tail, "//") &&
		!strings.Contains(tail, "@{") && !strings.HasSuffix(tail, "/") && !strings.HasSuffix(tail, ".lock") && !strings.HasSuffix(tail, ".")
}

// Branch is a base branch name for a pull request: main, or any branch name with the same grammar.
func Branch(b string) (string, bool) {
	b = strings.TrimPrefix(b, "refs/heads/")
	return b, reRefTail.MatchString(b) && !strings.Contains(b, "..") && !strings.Contains(b, "//") && !strings.Contains(b, "@{") &&
		!strings.HasSuffix(b, "/") && !strings.HasSuffix(b, ".lock") && !strings.HasSuffix(b, ".")
}

// ParseRemoteURL checks a remote URL and returns its owner and repo: https on github.com only, with no user info,
// port, query or fragment. The token is scoped to exactly the remotes rows, so a stray host or path is never stored.
func ParseRemoteURL(raw string) (owner, repo string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	if u.Scheme != "https" || u.Host != WebHost || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return "", "", errors.New("a remote URL is https://github.com/<owner>/<repo>")
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), ".git"), "/")
	if len(parts) != 2 || !reGHName.MatchString(parts[0]) || !reGHName.MatchString(parts[1]) || strings.HasSuffix(parts[1], ".") {
		return "", "", errors.New("a remote URL's path is /<owner>/<repo>")
	}
	return parts[0], parts[1], nil
}

// CanonURL is the stored form of a remote URL: https://github.com/<owner>/<repo>.
func CanonURL(owner, repo string) string { return "https://" + WebHost + "/" + owner + "/" + repo }

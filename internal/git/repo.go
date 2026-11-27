package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Env is the environment every git command of the service runs with: no system or global config and no prompt, so
// only the repo's own config and the -c and GIT_CONFIG_* settings the service passes apply.
func Env(extra ...string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=/nonexistent", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0"}
	return append(env, extra...)
}

// run runs git with args in repo and returns stdout. A non-zero exit is an error that carries git's stderr, for the
// service's own log only.
func run(ctx context.Context, repo string, env []string, args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	c := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...)
	c.Env, c.Stderr = Env(env...), &stderr
	out, err := c.Output()
	if err != nil {
		return out, fmt.Errorf("git %s: %w: %s", args[0], err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

func git(repo string, args ...string) ([]byte, error) {
	return run(context.Background(), repo, nil, args...)
}

// CreateRepo makes agent's bare repo project under root, idempotently. Its branch is main; every push and fetch
// setting comes from the service at serve time, not from this repo's config.
func CreateRepo(root, agent, project string) error {
	if !reAgent.MatchString(agent) || !ValidProject(project) {
		return errors.New("bad agent or project name")
	}
	repo := Repo(root, agent, project)
	if fi, err := os.Stat(filepath.Join(repo, "HEAD")); err == nil && fi.Mode().IsRegular() {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(repo), 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(repo), "."+project+".new-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if _, err := git(tmp, "init", "-q", "--bare", "-b", "main", tmp); err != nil {
		return err
	}
	// a repo appears only complete: a crash leaves a temp dir, never a half-made repo under its name
	if err := os.Rename(tmp, repo); err != nil && !Exists(root, agent, project) {
		return err
	}
	return nil
}

// Exists reports whether agent's repo project is a bare repo under root.
func Exists(root, agent, project string) bool {
	if !reAgent.MatchString(agent) || !ValidProject(project) {
		return false
	}
	fi, err := os.Stat(filepath.Join(Repo(root, agent, project), "HEAD"))
	return err == nil && fi.Mode().IsRegular()
}

// Contains reports whether some branch of repo contains oid (`git for-each-ref --contains`, §5.3): the commit came
// in through a push the hook accepted, so it is the agent's own.
func Contains(repo, oid string) (bool, error) {
	if !ValidOID(oid) {
		return false, nil
	}
	if _, err := git(repo, "cat-file", "-e", oid+"^{commit}"); err != nil {
		return false, nil // no such commit
	}
	out, err := git(repo, "for-each-ref", "--contains", oid, "--format=%(refname)", "refs/heads/")
	if err != nil {
		return false, err
	}
	return len(bytes.TrimSpace(out)) > 0, nil
}

// Tip is ref's commit in repo, or "" if the ref doesn't exist.
func Tip(repo, ref string) (string, error) {
	out, err := git(repo, "for-each-ref", "--format=%(objectname)", ref)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(out), "\n") {
		if ValidOID(l) {
			return l, nil
		}
	}
	return "", nil
}

// Tips is every branch of repo and its commit.
func Tips(repo string) (map[string]string, error) {
	out, err := git(repo, "for-each-ref", "--format=%(objectname) %(refname)", "refs/")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		oid, ref, ok := strings.Cut(sc.Text(), " ")
		if ok && ValidOID(oid) {
			m[ref] = oid
		}
	}
	return m, sc.Err()
}

// Between is the commits reachable from src and not from dst (all of src's history when dst is "").
func Between(repo, src, dst string) ([]string, error) {
	args := []string{"rev-list", src}
	if dst != "" {
		args = append(args, "--not", dst)
	}
	out, err := git(repo, args...)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// Ident is who a merge commit names.
var Ident = []string{"GIT_AUTHOR_NAME=agentbox", "GIT_AUTHOR_EMAIL=agentbox@localhost", "GIT_COMMITTER_NAME=agentbox",
	"GIT_COMMITTER_EMAIL=agentbox@localhost"}

// ErrConflict is a merge whose trees conflict: nothing changed.
var ErrConflict = errors.New("the branches conflict")

// MergeCommit makes the commit that merging src into dst gives, without moving any ref: src itself when dst is ""
// (main doesn't exist yet) or an ancestor of src (a fast-forward), else a two-parent commit of `git merge-tree`'s tree.
func MergeCommit(repo, src, dst, msg string, when time.Time) (string, error) {
	if dst == "" {
		return src, nil
	}
	if _, err := git(repo, "merge-base", "--is-ancestor", dst, src); err == nil {
		return src, nil
	}
	out, err := git(repo, "merge-tree", "--write-tree", "--no-messages", dst, src)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return "", ErrConflict
		}
		return "", err
	}
	tree := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if !ValidOID(tree) {
		return "", fmt.Errorf("merge-tree gave %q", tree)
	}
	date := fmt.Sprintf("%d +0000", when.Unix())
	out, err = run(context.Background(), repo, append(Ident, "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date), "commit-tree", tree, "-p", dst, "-p", src, "-m", msg)
	if err != nil {
		return "", err
	}
	c := strings.TrimSpace(string(out))
	if !ValidOID(c) {
		return "", fmt.Errorf("commit-tree gave %q", c)
	}
	return c, nil
}

// MoveRef sets ref to oid only if it is still old ("" for a ref that must not exist yet): a compare-and-swap.
func MoveRef(repo, ref, oid, old string) error {
	if old == "" {
		old = strings.Repeat("0", len(oid))
	}
	_, err := git(repo, "update-ref", ref, oid, old)
	return err
}

// Merged reports whether main already holds the merge of src into dst: main is src (a fast-forward or main created
// from it), or a commit whose parents are dst and src. Reconcile uses it after a restart, so a merge never runs twice.
func Merged(repo, src, dst string) (string, bool, error) {
	main, err := Tip(repo, "refs/heads/main")
	if err != nil || main == "" {
		return "", false, err
	}
	if main == src {
		return main, true, nil
	}
	out, err := git(repo, "rev-list", "--parents", "-n", "1", main)
	if err != nil {
		return "", false, err
	}
	f := strings.Fields(string(out))
	return main, len(f) == 3 && f[1] == dst && f[2] == src, nil
}

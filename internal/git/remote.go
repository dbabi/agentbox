package git

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"agentbox/internal/dial"
)

// Pusher runs git against a remote over https only, with pinned dialing (§6.3 step 4): rootd resolves github.com on
// Sock (dial.Resolve), and http.curloptResolve hands libcurl those addresses, so libcurl does no lookup of its own.
// The token reaches git only through the credential helper, never argv or the environment.
type Pusher struct {
	Sock   string   // resolve-git.sock
	Helper string   // the credential helper: "!<agentbox> git-credential"
	Env    []string // passed on to git and the helper (CREDENTIALS_DIRECTORY)
}

// env is the git config for one remote call, as GIT_CONFIG_* (command-line precedence): the resolved addresses, IPv6
// in brackets, no redirect, only https, only the service's credential helper.
func (p Pusher) env(ctx context.Context) ([]string, error) {
	addrs, err := dial.Resolve(ctx, p.Sock, "", WebHost, 443)
	if err != nil {
		return nil, &APIError{"unreachable", "resolve " + WebHost + ": " + err.Error()}
	}
	var l []string
	for _, a := range addrs {
		if a.Is6() {
			l = append(l, "["+a.String()+"]")
		} else {
			l = append(l, a.String())
		}
	}
	kv := [][2]string{
		{"http.curloptResolve", WebHost + ":443:" + strings.Join(l, ",")},
		{"http.followRedirects", "false"},
		{"protocol.allow", "never"},
		{"protocol.https.allow", "always"},
		{"credential.helper", ""}, // an empty value clears any helper set before it
		{"credential.helper", p.Helper},
		{"core.hooksPath", "/dev/null"},
	}
	env := append([]string{"GIT_CONFIG_COUNT=" + strconv.Itoa(len(kv))}, p.Env...)
	for i, x := range kv {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, x[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, x[1]))
	}
	return env, nil
}

// pushError maps git's push failure to a REMOTE_REJECTED what; git's text stays in Detail.
func pushError(err error, stderr []byte) *APIError {
	s := string(stderr)
	d := trunc(fmt.Sprintf("%v: %s", err, bytes.TrimSpace(stderr)), 800)
	low := strings.ToLower(s)
	switch {
	case strings.Contains(s, "GH013") || strings.Contains(low, "rule violation") || strings.Contains(low, "protected branch"):
		return &APIError{"ruleset", d}
	case strings.Contains(low, "could not resolve") || strings.Contains(low, "failed to connect") || strings.Contains(low, "timed out") ||
		strings.Contains(low, "connection refused") || strings.Contains(low, "unreachable"):
		return &APIError{"unreachable", d}
	case strings.Contains(low, "not found") || strings.Contains(low, "404"):
		return &APIError{"not_found", d}
	}
	return &APIError{"other", d}
}

// Push pushes oid from repo to ref of the remote at url (`git push --porcelain <url> <oid>:<ref>`), never forced: a
// ref that moved on the remote refuses it.
func (p Pusher) Push(ctx context.Context, repo, url, oid, ref string) error {
	env, err := p.env(ctx)
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	c := exec.CommandContext(ctx, "git", "-C", repo, "push", "--porcelain", "--no-verify", url+".git", oid+":"+ref)
	c.Env, c.Stderr = Env(env...), &stderr
	out, err := c.Output()
	if err != nil {
		return pushError(err, append(out, stderr.Bytes()...))
	}
	// porcelain: "!" flags a rejected ref even when git exits 0 for others
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "!") {
			return pushError(fmt.Errorf("rejected"), out)
		}
	}
	return nil
}

// RemoteRef is ref's commit on the remote at url (`git ls-remote`), or "" if the remote has no such ref. Reconcile
// compares it with the bound OID (§5.3: repo.push needs no marker).
func (p Pusher) RemoteRef(ctx context.Context, repo, url, ref string) (string, error) {
	env, err := p.env(ctx)
	if err != nil {
		return "", err
	}
	var stderr bytes.Buffer
	c := exec.CommandContext(ctx, "git", "-C", repo, "ls-remote", "--refs", url+".git", ref)
	c.Env, c.Stderr = Env(env...), &stderr
	out, err := c.Output()
	if err != nil {
		return "", pushError(err, stderr.Bytes())
	}
	for _, l := range strings.Split(string(out), "\n") {
		oid, r, ok := strings.Cut(l, "\t")
		if ok && r == ref && ValidOID(oid) {
			return oid, nil
		}
	}
	return "", nil
}

// Credential is the git credential helper (`agentbox git-credential get`): for https://github.com only, it answers
// the service's token as x-access-token's password. It reads git's request on stdin and writes the answer to w.
func Credential(op string, in []byte, w *bytes.Buffer) error {
	if op != "get" {
		return nil // store and erase: the token is not git's to keep
	}
	attrs := map[string]string{}
	for _, l := range strings.Split(string(in), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			attrs[k] = v
		}
	}
	if attrs["protocol"] != "https" || attrs["host"] != WebHost {
		return nil
	}
	tok, err := Token()
	if err != nil {
		return err
	}
	w.WriteString("username=x-access-token\npassword=" + tok + "\n")
	return nil
}

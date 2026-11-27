package git

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resolver returns rootd's checked addresses for host:port (§6.3 pinned dialing step 1).
type Resolver func(ctx context.Context, host string, port int) ([]netip.Addr, error)

// Resolve asks rootd on resolve-git.sock. rootd re-checks service.list, resolves through resolved, adds the answers
// to git_dst and returns them; a refusal names one reason.
func (r Rootd) Resolve(ctx context.Context, host string, port int) ([]netip.Addr, error) {
	rep, err := r.Call(map[string]any{"op": "resolve", "host": host, "port": port}, 20*time.Second)
	if err != nil {
		return nil, err
	}
	l, _ := rep["addrs"].([]any)
	var out []netip.Addr
	for _, x := range l {
		s, _ := x.(string)
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("rootd answered %q", s)
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("rootd answered no address")
	}
	return out, nil
}

// DialBudget is the one budget a connection's addresses share (§6.3).
const DialBudget = 10 * time.Second

// Dialer is pinned dialing for an http.Transport: it ignores the address's host lookup and dials only what rootd
// resolved, in order, each with an even share of what is left of DialBudget. TLS SNI, the certificate check and the
// Host header keep the URL's host name.
// shortcut: internal/dial (#20) replaces this when it lands.
type Dialer struct{ Resolve Resolver }

// DialContext dials host:port through rootd's answers; network must be tcp.
func (d Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil || network != "tcp" {
		return nil, fmt.Errorf("dial %s %s: tcp host:port only", network, addr)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}
	addrs, err := d.Resolve(ctx, host, port)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, DialBudget)
	defer cancel()
	end, _ := ctx.Deadline()
	var first error
	for i, a := range addrs {
		actx, acancel := context.WithDeadline(ctx, time.Now().Add(time.Until(end)/time.Duration(len(addrs)-i)))
		c, err := new(net.Dialer).DialContext(actx, "tcp", netip.AddrPortFrom(a, uint16(port)).String())
		acancel()
		if err == nil {
			return c, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
}

// Client is an HTTP client on pinned dialing: no environment proxy, no redirect followed (its target would need its
// own allowlist entry), no cookies.
func (d Dialer) Client() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy, t.DialContext = nil, d.DialContext
	return &http.Client{Transport: t, Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect not followed") }}
}

// TokenName is the GitHub token's credential: agentbox-git.service loads the root-only control/secrets/git dir as
// credential "git", so the file github-token there is $CREDENTIALS_DIRECTORY/git_github-token.
const TokenName = "git_github-token"

// errNoToken is a box with no GitHub token installed.
var errNoToken = errors.New("no GitHub token: put one in /var/lib/agentbox/control/secrets/git/github-token and restart agentbox-git")

// Token reads the service's GitHub token from its systemd credentials. It is never logged, audited or put in argv.
func Token() (string, error) {
	d := os.Getenv("CREDENTIALS_DIRECTORY")
	if d == "" {
		return "", errNoToken
	}
	b, err := os.ReadFile(filepath.Join(d, TokenName))
	if err != nil {
		return "", errNoToken
	}
	t := strings.TrimSpace(string(b))
	if t == "" || strings.ContainsAny(t, " \t\r\n") {
		return "", errNoToken
	}
	return t, nil
}

// APIError is a remote write GitHub refused, or one that never reached it. What is the REMOTE_REJECTED what a task
// sees; Detail (GitHub's status and text) goes only to the DENY record and the journal.
type APIError struct {
	What   string
	Detail string
}

func (e *APIError) Error() string { return e.What + ": " + e.Detail }

// GitHub is the REST client of the service's token (§6.3), on pinned dialing.
type GitHub struct {
	API   string // https://api.github.com
	HTTP  *http.Client
	Token func() (string, error)

	mu    sync.Mutex
	login string
}

const maxAPIBody = 8 << 20

// do sends one request and decodes a 2xx JSON reply into out. Any other outcome is an *APIError.
func (g *GitHub) do(ctx context.Context, method, path string, in, out any) error {
	tok, err := g.Token()
	if err != nil {
		return &APIError{"other", err.Error()}
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.API+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "agentbox-git")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return &APIError{"unreachable", method + " " + path + ": " + err.Error()}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return &APIError{"unreachable", method + " " + path + ": " + err.Error()}
	}
	if resp.StatusCode/100 == 2 {
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(b, out); err != nil {
			return &APIError{"other", method + " " + path + ": a 2xx reply that is not JSON"}
		}
		return nil
	}
	return apiError(method+" "+path, resp, b)
}

// apiError maps a GitHub refusal to its REMOTE_REJECTED what (§5.6): GitHub's text stays in Detail.
func apiError(what string, resp *http.Response, b []byte) *APIError {
	msg := string(b)
	d := fmt.Sprintf("%s: %d %s", what, resp.StatusCode, trunc(msg, 600))
	switch {
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode == http.StatusForbidden && (resp.Header.Get("X-Ratelimit-Remaining") == "0" ||
		strings.Contains(strings.ToLower(msg), "rate limit")):
		return &APIError{"rate_limited", d}
	case resp.StatusCode == http.StatusNotFound:
		return &APIError{"not_found", d}
	case resp.StatusCode == http.StatusUnprocessableEntity && strings.Contains(msg, "pull request already exists"):
		return &APIError{"pr_exists", d}
	case resp.StatusCode == http.StatusUnprocessableEntity && strings.Contains(msg, "No commits between"):
		return &APIError{"no_commits", d}
	case resp.StatusCode == http.StatusConflict && strings.Contains(strings.ToLower(msg), "rule"):
		return &APIError{"ruleset", d}
	case resp.StatusCode >= 500:
		return &APIError{"unreachable", d}
	}
	return &APIError{"other", d}
}

// RepoInfo is what remote.set stores and execution re-checks (§5.3 Remote re-check).
type RepoInfo struct {
	NodeID     string `json:"node_id"`
	Visibility string `json:"visibility"`
}

// Repo reads owner/repo (GET /repos/{o}/{r}).
func (g *GitHub) Repo(ctx context.Context, owner, repo string) (RepoInfo, error) {
	var r RepoInfo
	if err := g.do(ctx, http.MethodGet, "/repos/"+owner+"/"+repo, nil, &r); err != nil {
		return r, err
	}
	switch r.Visibility {
	case "private", "internal", "public":
	default:
		return r, &APIError{"other", "GET /repos: no visibility in the reply"}
	}
	if r.NodeID == "" || len(r.NodeID) > 128 {
		return r, &APIError{"other", "GET /repos: no node_id in the reply"}
	}
	return r, nil
}

// Login is the token's own user (GET /user), cached: reconcile matches only items it wrote (§5.3 step 3).
func (g *GitHub) Login(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.login != "" {
		return g.login, nil
	}
	var u struct {
		Login string `json:"login"`
	}
	if err := g.do(ctx, http.MethodGet, "/user", nil, &u); err != nil {
		return "", err
	}
	if u.Login == "" {
		return "", &APIError{"other", "GET /user: no login"}
	}
	g.login = u.Login
	return u.Login, nil
}

// Item is one created PR or comment: its number (a PR) or id (a comment), and its URL. GitHub generates both.
type Item struct {
	Number int64  `json:"number,omitempty"`
	ID     int64  `json:"id,omitempty"`
	URL    string `json:"html_url"`
	Body   string `json:"body"`
	User   struct {
		Login string `json:"login"`
	} `json:"user"`
}

// CreatePR opens a pull request (POST /repos/{o}/{r}/pulls).
func (g *GitHub) CreatePR(ctx context.Context, owner, repo, title, head, base, body string) (Item, error) {
	var it Item
	err := g.do(ctx, http.MethodPost, "/repos/"+owner+"/"+repo+"/pulls", map[string]string{"title": title, "head": head, "base": base, "body": body}, &it)
	return it, err
}

// Comment comments on an issue or a pull request's conversation (POST /repos/{o}/{r}/issues/{n}/comments).
func (g *GitHub) Comment(ctx context.Context, owner, repo string, n int64, body string) (Item, error) {
	var it Item
	err := g.do(ctx, http.MethodPost, "/repos/"+owner+"/"+repo+"/issues/"+strconv.FormatInt(n, 10)+"/comments", map[string]string{"body": body}, &it)
	return it, err
}

// Marker is the op marker rootd appends to every gh.* body (§5.3 step 1).
func Marker(id string) string { return "\n<!-- agentbox-op:" + id + " -->" }

// mine reports whether it is the token user's and ends with id's marker (§5.3 step 3).
func mine(it Item, login, id string) bool {
	return it.User.Login == login && strings.HasSuffix(strings.TrimRight(it.Body, " \t\r\n"), strings.TrimPrefix(Marker(id), "\n"))
}

const maxPages = 50

// FindComment lists issue n's comments since since, every page (§5.3 step 2), and returns the token user's comment
// that ends with id's marker.
func (g *GitHub) FindComment(ctx context.Context, owner, repo string, n int64, since time.Time, id string) (Item, bool, error) {
	login, err := g.Login(ctx)
	if err != nil {
		return Item{}, false, err
	}
	q := url.Values{"since": {since.UTC().Format(time.RFC3339)}, "per_page": {"100"}}
	for page := 1; page <= maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		var l []Item
		if err := g.do(ctx, http.MethodGet, "/repos/"+owner+"/"+repo+"/issues/"+strconv.FormatInt(n, 10)+"/comments?"+q.Encode(), nil, &l); err != nil {
			return Item{}, false, err
		}
		for _, it := range l {
			if mine(it, login, id) {
				return it, true, nil
			}
		}
		if len(l) < 100 {
			break
		}
	}
	return Item{}, false, nil
}

// FindPR lists the pull requests from head to base in every state (§5.3 step 2) and returns the token user's that
// ends with id's marker.
func (g *GitHub) FindPR(ctx context.Context, owner, repo, head, base, id string) (Item, bool, error) {
	login, err := g.Login(ctx)
	if err != nil {
		return Item{}, false, err
	}
	q := url.Values{"head": {owner + ":" + head}, "base": {base}, "state": {"all"}, "per_page": {"100"}}
	for page := 1; page <= maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		var l []Item
		if err := g.do(ctx, http.MethodGet, "/repos/"+owner+"/"+repo+"/pulls?"+q.Encode(), nil, &l); err != nil {
			return Item{}, false, err
		}
		for _, it := range l {
			if mine(it, login, id) {
				return it, true, nil
			}
		}
		if len(l) < 100 {
			break
		}
	}
	return Item{}, false, nil
}

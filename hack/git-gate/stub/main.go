// Command stub is a stand-in for GitHub for hack/git-gate.sh, run on the host on 127.0.0.1 only. The VM reaches it
// through vmnet's forward of one port (AGENTBOX_VM_FWD), and the gate DNATs agentbox-git's https connections to it.
// It serves TLS for github.com and api.github.com from a throwaway CA it writes to -dir, so agentbox-git checks
// names and certificates as it would against GitHub. github.com is git smart HTTP over bare repos (git http-backend),
// behind Basic auth with -token; api.github.com is the REST subset agentbox-git uses, behind Bearer -token. /_gate/
// is the gate's own control: the state, a comment POST held after it is stored (so the gate can kill rootd between
// the POST and its RESULT), and a forced 422 for the next pull request. Test fixture: never shipped.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type item struct {
	Number int64  `json:"number,omitempty"`
	ID     int64  `json:"id,omitempty"`
	URL    string `json:"html_url"`
	Body   string `json:"body"`
	Title  string `json:"title,omitempty"`
	Issue  int64  `json:"issue,omitempty"`
	Head   *struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head,omitempty"`
	Base *struct {
		Ref string `json:"ref"`
	} `json:"base,omitempty"`
	User    struct{ Login string } `json:"user"`
	Created string                 `json:"created_at"`
}

type stub struct {
	dir, token, login, backend string
	mu                         sync.Mutex
	prs                        map[string][]item // owner/repo
	comments                   map[string][]item // owner/repo#n
	posts                      int
	hold                       bool          // hold the next comment POST's reply after storing it
	held                       chan struct{} // closed by /_gate/release
	heldNow                    bool
	fail422                    string // the body of a forced 422 for the next pull request
	nextID                     int64
}

var repos = map[string]string{"acme/app": "R_kgDOGateApp", "acme/other": "R_kgDOGateOther"}

func main() {
	listen := flag.String("listen", "127.0.0.1:7900", "loopback address:port")
	dir := flag.String("dir", "", "state dir: ca.pem and the bare repos")
	token := flag.String("token", "", "the token agentbox-git must send")
	login := flag.String("login", "agentbox-gate-bot", "the token's user")
	flag.Parse()
	if err := loopback(*listen); err != nil || *dir == "" || *token == "" {
		log.Fatal("usage: stub -listen 127.0.0.1:PORT -dir DIR -token T")
	}
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		log.Fatal(err)
	}
	s := &stub{dir: *dir, token: *token, login: *login, backend: filepath.Join(strings.TrimSpace(string(out)), "git-http-backend"),
		prs: map[string][]item{}, comments: map[string][]item{}, nextID: 9000}
	if err := s.repos(); err != nil {
		log.Fatal(err)
	}
	cert, err := s.certs()
	if err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("stub GitHub on https://%s (github.com, api.github.com); CA in %s", l.Addr(), filepath.Join(*dir, "ca.pem"))
	srv := &http.Server{Handler: s, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, ErrorLog: log.New(os.Stderr, "http: ", 0)}
	log.Fatal(srv.ServeTLS(l, "", ""))
}

// loopback accepts only a loopback listen address: the stub is never on another interface.
func loopback(a string) error {
	h, _, err := net.SplitHostPort(a)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s is not loopback", h)
	}
	return nil
}

// repos makes acme/app.git (with a main branch) and acme/other.git, once.
func (s *stub) repos() error {
	for name := range repos {
		p := filepath.Join(s.dir, "repos", name+".git")
		if _, err := os.Stat(p); err == nil {
			continue
		}
		w := filepath.Join(s.dir, "seed-"+strings.ReplaceAll(name, "/", "-"))
		for _, c := range [][]string{{"init", "-q", "-b", "main", w}, {"-C", w, "commit", "-q", "--allow-empty", "-m", "init"},
			{"clone", "-q", "--bare", w, p}} {
			cmd := exec.Command("git", c...)
			cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=stub", "GIT_AUTHOR_EMAIL=stub@gate", "GIT_COMMITTER_NAME=stub", "GIT_COMMITTER_EMAIL=stub@gate")
			if b, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("git %v: %v: %s", c, err, b)
			}
		}
		os.RemoveAll(w)
		exec.Command("git", "-C", p, "config", "http.receivepack", "true").Run()
	}
	return nil
}

// certs writes a throwaway CA to dir/ca.pem and returns a leaf for github.com and api.github.com it signed.
func (s *stub) certs() (tls.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agentbox git-gate stub CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "github.com"}, DNSNames: []string{"github.com", "api.github.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(filepath.Join(s.dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &status{ResponseWriter: w, code: 200}
	defer func() { log.Printf("%s %s %s %d", r.Host, r.Method, r.URL.Path, rec.code) }()
	switch {
	case strings.HasPrefix(r.URL.Path, "/_gate/"):
		s.control(rec, r)
	case r.Host == "github.com" || strings.HasPrefix(r.Host, "github.com:"):
		s.git(rec, r)
	default:
		s.api(rec, r)
	}
}

type status struct {
	http.ResponseWriter
	code int
}

func (s *status) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }
func (s *status) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

var reGit = regexp.MustCompile(`^/(acme/[a-z]+)\.git/(info/refs|git-upload-pack|git-receive-pack)$`)

// git is smart HTTP behind Basic auth: the password must be the token, as GitHub takes an installation token.
func (s *stub) git(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || p != s.token {
		w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	if !reGit.MatchString(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	(&cgi.Handler{Path: s.backend, Root: "/", Env: []string{"GIT_PROJECT_ROOT=" + filepath.Join(s.dir, "repos"), "GIT_HTTP_EXPORT_ALL=1",
		"REMOTE_USER=" + u}}).ServeHTTP(w, r)
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	e := json.NewEncoder(w)
	e.SetEscapeHTML(false) // as GitHub: a body's <!-- marker --> stays readable in /_gate/state
	e.Encode(v)
}

var (
	rePulls    = regexp.MustCompile(`^/repos/(acme/[a-z]+)/pulls$`)
	reComments = regexp.MustCompile(`^/repos/(acme/[a-z]+)/issues/([0-9]+)/comments$`)
	reRepo     = regexp.MustCompile(`^/repos/(acme/[a-z]+)$`)
)

func (s *stub) api(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		reply(w, 401, map[string]string{"message": "Bad credentials"})
		return
	}
	p := r.URL.Path
	switch {
	case p == "/user" && r.Method == "GET":
		reply(w, 200, map[string]string{"login": s.login})
	case reRepo.MatchString(p) && r.Method == "GET":
		name := reRepo.FindStringSubmatch(p)[1]
		if id, ok := repos[name]; ok {
			reply(w, 200, map[string]any{"node_id": id, "visibility": "private", "private": true, "full_name": name})
			return
		}
		reply(w, 404, map[string]string{"message": "Not Found"})
	case rePulls.MatchString(p) && r.Method == "POST":
		s.createPR(w, r, rePulls.FindStringSubmatch(p)[1])
	case rePulls.MatchString(p) && r.Method == "GET":
		name := rePulls.FindStringSubmatch(p)[1]
		head, base := r.URL.Query().Get("head"), r.URL.Query().Get("base")
		s.mu.Lock()
		out := []item{}
		for _, it := range s.prs[name] {
			if (head == "" || strings.SplitN(name, "/", 2)[0]+":"+it.Head.Ref == head) && (base == "" || it.Base.Ref == base) {
				out = append(out, it)
			}
		}
		s.mu.Unlock()
		reply(w, 200, out)
	case reComments.MatchString(p) && r.Method == "POST":
		m := reComments.FindStringSubmatch(p)
		s.comment(w, r, m[1], m[2])
	case reComments.MatchString(p) && r.Method == "GET":
		m := reComments.FindStringSubmatch(p)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if page < 1 {
			page = 1
		}
		if per < 1 || per > 100 {
			per = 30
		}
		s.mu.Lock()
		l := s.comments[m[1]+"#"+m[2]]
		from, to := min((page-1)*per, len(l)), min(page*per, len(l))
		out := append([]item{}, l[from:to]...)
		s.mu.Unlock()
		reply(w, 200, out)
	default:
		reply(w, 404, map[string]string{"message": "Not Found"})
	}
}

func (s *stub) createPR(w http.ResponseWriter, r *http.Request, name string) {
	var in struct{ Title, Head, Base, Body string }
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		reply(w, 400, map[string]string{"message": "Problems parsing JSON"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.posts++
	if s.fail422 != "" {
		body := s.fail422
		s.fail422 = ""
		reply(w, 422, map[string]any{"message": "Validation Failed", "errors": []map[string]string{{"message": body}}})
		return
	}
	sha, err := exec.Command("git", "-C", filepath.Join(s.dir, "repos", name+".git"), "rev-parse", "--verify", "-q", "refs/heads/"+in.Head).Output()
	if err != nil {
		reply(w, 422, map[string]any{"message": "Validation Failed", "errors": []map[string]string{{"message": "No commits between " + in.Base + " and " + in.Head}}})
		return
	}
	for _, it := range s.prs[name] {
		if it.Head.Ref == in.Head && it.Base.Ref == in.Base {
			reply(w, 422, map[string]any{"message": "Validation Failed", "errors": []map[string]string{{"message": "A pull request already exists for " + in.Head + "."}}})
			return
		}
	}
	n := int64(len(s.prs[name]) + 1)
	it := item{Number: n, URL: fmt.Sprintf("https://github.com/%s/pull/%d", name, n), Title: in.Title, Body: in.Body, Created: time.Now().UTC().Format(time.RFC3339)}
	it.Head = &struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}{in.Head, strings.TrimSpace(string(sha))}
	it.Base = &struct {
		Ref string `json:"ref"`
	}{in.Base}
	it.User.Login = s.login
	s.prs[name] = append(s.prs[name], it)
	reply(w, 201, it)
}

// comment stores the comment first; with hold set, its reply then waits for /_gate/release (at most 90 s).
func (s *stub) comment(w http.ResponseWriter, r *http.Request, name, n string) {
	var in struct{ Body string }
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		reply(w, 400, map[string]string{"message": "Problems parsing JSON"})
		return
	}
	s.mu.Lock()
	s.posts++
	s.nextID++
	num, _ := strconv.ParseInt(n, 10, 64)
	it := item{ID: s.nextID, Issue: num, URL: fmt.Sprintf("https://github.com/%s/issues/%s#issuecomment-%d", name, n, s.nextID), Body: in.Body,
		Created: time.Now().UTC().Format(time.RFC3339)}
	it.User.Login = s.login
	s.comments[name+"#"+n] = append(s.comments[name+"#"+n], it)
	hold := s.hold
	ch := s.held
	if hold {
		s.hold, s.heldNow = false, true
	}
	s.mu.Unlock()
	if hold {
		log.Printf("comment %d stored; holding its reply", it.ID)
		select {
		case <-ch:
		case <-time.After(90 * time.Second):
		}
		s.mu.Lock()
		s.heldNow = false
		s.mu.Unlock()
	}
	reply(w, 201, it)
}

func (s *stub) control(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/_gate/state":
		refs := map[string]string{}
		for name := range repos {
			out, _ := exec.Command("git", "-C", filepath.Join(s.dir, "repos", name+".git"), "for-each-ref", "--format=%(objectname) %(refname)").Output()
			for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if oid, ref, ok := strings.Cut(l, " "); ok {
					refs[name+" "+ref] = oid
				}
			}
		}
		reply(w, 200, map[string]any{"prs": s.prs, "comments": s.comments, "posts": s.posts, "refs": refs, "held": s.heldNow})
	case "/_gate/hold":
		s.hold, s.held = true, make(chan struct{})
		reply(w, 200, map[string]bool{"ok": true})
	case "/_gate/release":
		if s.held != nil {
			close(s.held)
			s.held = nil
		}
		reply(w, 200, map[string]bool{"ok": true})
	case "/_gate/fail422":
		b, _ := base64.StdEncoding.DecodeString(r.URL.Query().Get("b64"))
		s.fail422 = string(b)
		reply(w, 200, map[string]bool{"ok": true})
	default:
		http.NotFound(w, r)
	}
}

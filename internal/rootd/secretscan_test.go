package rootd

import (
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/ids"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/resolve"
	"agentbox/internal/secrets"
)

// #104: a planted credential blocks the next task, naming the file and type; --ack-secrets with the count lets it
// start; a grant for the credential's host names it and makes the next task scan again; a fixed file unblocks.
func TestSecretGate(t *testing.T) {
	r := newRig(t)
	var hits []secrets.Hit
	var scanErr error
	scans := 0
	r.t.cfg.SecretScan = func(Account) ([]secrets.Hit, error) { scans++; return hits, scanErr }
	acct, _ := r.t.cfg.Accounts.Lookup("claude")
	start := func() reply {
		req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
		return r.t.start(ids.New(ids.Task), "claude", "admin:"+req)
	}
	gh := secrets.Hit{Path: "notes/token.txt", Rule: "github-pat", Line: 3}
	hits = []secrets.Hit{gh}
	rep := start()
	if rep["ok"] != false || rep["reason"] != SecretsInWorkspace || !strings.Contains(rep["error"].(string), "notes/token.txt:3 (github-pat)") || len(r.launch) != 0 {
		t.Fatalf("planted token: %v, launches %d", rep, len(r.launch))
	}
	for _, ack := range []int{2, -1} { // #273: no count but the hit count passes, a negative one included
		if rep := r.t.secretGate(acct, ack); rep["reason"] != SecretsAckMismatch {
			t.Fatalf("--ack-secrets %d for 1 hit: %v", ack, rep)
		}
	}
	if rep := r.t.secretGate(acct, 1); rep != nil {
		t.Fatalf("--ack-secrets 1: %v", rep)
	}
	n := scans
	if rep := start(); rep["ok"] != true || scans != n {
		t.Fatalf("after the ack: %v, scans %d -> %d (want no new scan)", rep, n, scans)
	}
	found, failed := r.t.grantScan([]string{"claude"}, "api.github.com")
	if len(failed) != 0 || len(found) != 1 || found[0]["type"] != "github-pat" || found[0]["path"] != gh.Path {
		t.Fatalf("grant scan: %v %v", found, failed)
	}
	// #222 R52: the ack came while github was not allowed, so a github grant drops it and the next task blocks, as the
	// grant's warning says, until a new --ack-secrets
	if err := r.t.dropAcks([]string{"claude"}, "api.github.com"); err != nil {
		t.Fatal(err)
	}
	if rep := start(); rep["reason"] != SecretsInWorkspace {
		t.Fatalf("a task after the grant, on the ack from before it: %v", rep)
	}
	if rep := r.t.secretGate(acct, 1); rep != nil {
		t.Fatalf("--ack-secrets 1 after the grant: %v", rep)
	}
	if found, _ := r.t.grantScan([]string{"claude"}, "pypi.org"); len(found) != 0 {
		t.Fatalf("a grant for another host named it: %v", found)
	}
	if err := r.t.dropAcks([]string{"claude"}, "pypi.org"); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := r.t.loadScan(accounts.WorkspaceSubject("claude", int(acct.UID))); !slices.Equal(st.acked, []secrets.Hit{gh}) {
		t.Fatalf("a grant for another host changed the acks: %v", st.acked)
	}
	hits = append(hits, secrets.Hit{Path: ".env", Rule: "aws-access-token", Line: 1})
	if rep := start(); rep["reason"] != SecretsInWorkspace || !strings.Contains(rep["error"].(string), ".env:1 (aws-access-token)") {
		t.Fatalf("a new unacknowledged hit: %v", rep)
	}
	hits = nil
	if rep := start(); rep["ok"] != true {
		t.Fatalf("fixed: %v", rep)
	}
	// #208: a scan that fails at a grant leaves the workspace unchecked, so the next task scans again, and a failed
	// scan blocks it
	scanErr = errors.New("boom")
	if _, failed := r.t.grantScan([]string{"claude"}, "api.github.com"); !slices.Equal(failed, []string{"claude"}) {
		t.Fatalf("a failed grant scan: %v", failed)
	}
	n = scans
	if rep := start(); rep["reason"] != SecretScanFailed || scans != n+1 {
		t.Fatalf("after a failed grant scan: %v, scans %d -> %d (want a new scan)", rep, n, scans)
	}
	// a scan cut off at MaxHits read only part of the workspace: tasks stay blocked, and no --ack-secrets passes it
	hits, scanErr = []secrets.Hit{gh}, errTooManyHits
	for _, ack := range []int{0, 1} {
		if rep := r.t.secretGate(acct, ack); rep["reason"] != SecretsTooMany || !strings.Contains(rep["error"].(string), "stopped at") {
			t.Fatalf("a truncated scan, --ack-secrets %d: %v", ack, rep)
		}
	}
	if found, failed := r.t.grantScan([]string{"claude"}, "api.github.com"); !slices.Equal(failed, []string{"claude"}) || len(found) != 1 {
		t.Fatalf("a truncated scan at a grant: %v %v", found, failed)
	}
	scanErr = nil
	if rep := r.t.secretGate(acct, 1); rep != nil {
		t.Fatalf("a whole scan again, acknowledged: %v", rep)
	}
}

// lookups is an Accounts whose Lookup fails with a read error, from call fail on (0: never).
type lookups struct {
	Accounts
	n, fail int
}

func (l *lookups) Lookup(a string) (Account, error) {
	if l.n++; l.fail > 0 && l.n >= l.fail {
		return Account{}, errors.New("disk I/O error")
	}
	return l.Accounts.Lookup(a)
}

// #222: an egress grant that would let a task use a workspace credential against the new host is refused, with nothing
// sent to auditd and the lists and acks as they were, until --ack-secrets gives the count; the acked grant drops the
// matching acks. A failed scan refuses any grant. #273: so do a negative count, a grant with no agent list and one
// whose agent lookup fails; a grant auditd refuses keeps the acks, and one whose acks can't be dropped after the
// INTENT changes no list and says so in a failed RESULT.
func TestEgressGrantRefused(t *testing.T) {
	r := newRig(t)
	if _, err := accounts.Add(r.db, "claude", time.Now()); err != nil {
		t.Fatal(err)
	}
	gh := secrets.Hit{Path: "notes/token.txt", Rule: "github-pat", Line: 3}
	var scanErr error
	r.t.cfg.SecretScan = func(Account) ([]secrets.Hit, error) { return []secrets.Hit{gh}, scanErr }
	acct, _ := r.t.cfg.Accounts.Lookup("claude")
	if rep := r.t.secretGate(acct, 1); rep != nil {
		t.Fatal(rep)
	}
	dir := r.t.cfg.EgressDir
	os.MkdirAll(dir, 0o700)
	s := &server{db: r.db, tasks: r.t, cfg: Config{EgressDir: dir}, svc: &resolve.Service{DB: r.db, Dir: dir}, audit: r.t.audit}
	start := func() reply {
		req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
		return r.t.start(ids.New(ids.Task), "claude", "admin:"+req)
	}
	listed := func(host string) bool {
		l, err := resolve.LoadLists(dir)
		return err == nil && l.AllowedAny("proxy", resolve.Entry{Host: host, Port: 443})
	}
	grant := func(host string, ack int) reply {
		return s.admin(request{Op: "egress.allow", Svc: "proxy", Entry: host + ":443", AckSecrets: ack}, peer{})
	}
	r.reset()
	for ack, want := range map[int]string{0: SecretsInWorkspace, 2: SecretsAckMismatch, -1: SecretsAckMismatch} {
		rep := grant("api.github.com", ack)
		if rep["ok"] != false || rep["reason"] != want || listed("api.github.com") || len(r.recs()) != 0 {
			t.Fatalf("--ack-secrets %d: %v, listed %v, records %v", ack, rep, listed("api.github.com"), r.recs())
		}
		if ack == 0 && !strings.Contains(rep["error"].(string), "a github-pat in claude's workspace (notes/token.txt:3)") {
			t.Fatalf("the refusal does not name the token: %v", rep)
		}
	}
	r.auditUp = false
	if rep := grant("api.github.com", 1); rep["ok"] != false || !strings.Contains(rep["error"].(string), "nothing changed") || listed("api.github.com") {
		t.Fatalf("auditd down: %v, listed %v", rep, listed("api.github.com"))
	}
	r.auditUp = true
	if rep := start(); rep["ok"] != true {
		t.Fatalf("a refused grant dropped the ack: %v", rep)
	}
	r.reset()
	rep := grant("api.github.com", 1)
	if rep["changed"] != true || !listed("api.github.com") || !strings.Contains(rep["warning"].(string), "Tasks running now can use it") ||
		!slices.Equal(r.types(), []string{"INTENT", "RESULT"}) {
		t.Fatalf("--ack-secrets 1: %v, records %v", rep, r.recs())
	}
	if rep := start(); rep["reason"] != SecretsInWorkspace {
		t.Fatalf("a task after the acked grant, on the ack from before it: %v", rep)
	}
	scanErr = errors.New("boom")
	r.reset()
	if rep := grant("pypi.org", 1); rep["reason"] != SecretScanFailed || !slices.Equal(rep["secretScanFailed"].([]string), []string{"claude"}) ||
		listed("pypi.org") || len(r.recs()) != 0 {
		t.Fatalf("a grant whose scan failed: %v, records %v", rep, r.recs())
	}
	scanErr = nil
	acc := &lookups{Accounts: r.t.cfg.Accounts, fail: 1}
	r.t.cfg.Accounts = acc
	if rep := grant("pypi.org", 0); rep["reason"] != SecretScanFailed || !slices.Equal(rep["secretScanFailed"].([]string), []string{"claude"}) ||
		listed("pypi.org") || len(r.recs()) != 0 {
		t.Fatalf("a grant whose agent lookup failed: %v, records %v", rep, r.recs())
	}
	if err := r.t.dropAcks([]string{"claude"}, "pypi.org"); err == nil {
		t.Fatal("dropAcks went on past a failed lookup")
	}
	acc.n, acc.fail = 0, 2 // the grant's scan looks claude up; dropAcks, after the INTENT, can't
	rep = grant("pypi.org", 0)
	if msg, _ := rep["error"].(string); rep["ok"] != false || !strings.Contains(msg, "the list did not change") || !strings.Contains(msg, "may be dropped") ||
		listed("pypi.org") || !slices.Equal(r.types(), []string{"INTENT", "RESULT"}) || r.recs()[1]["status"] != "failed" {
		t.Fatalf("a grant whose acks can't be dropped: %v, records %v", rep, r.recs())
	}
	r.t.cfg.Accounts = acc.Accounts
	r.reset()
	if _, err := r.db.Exec(`ALTER TABLE ids RENAME TO ids_gone`); err != nil {
		t.Fatal(err)
	}
	if rep := grant("pypi.org", 0); rep["reason"] != SecretScanFailed || !strings.Contains(rep["error"].(string), "no agent list") ||
		listed("pypi.org") || len(r.recs()) != 0 {
		t.Fatalf("a grant with no agent list: %v, records %v", rep, r.recs())
	}
}

// #224: scans of one workspace run one at a time, so an older, slower scan can't save its result over a newer one's.
func TestSecretScanSerial(t *testing.T) {
	r := newRig(t)
	acct, _ := r.t.cfg.Accounts.Lookup("claude")
	key := secrets.Hit{Path: ".env", Rule: "aws-access-token", Line: 1}
	began, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	calls := 0
	r.t.cfg.SecretScan = func(Account) ([]secrets.Hit, error) {
		mu.Lock()
		calls++
		c := calls
		mu.Unlock()
		if c == 1 { // a task's scan, slow, that read the workspace before .env was written
			close(began)
			<-release
			return nil, nil
		}
		return []secrets.Hit{key}, nil // the grant's, after it
	}
	task := make(chan reply)
	go func() { task <- r.t.secretGate(acct, 0) }()
	<-began
	grant := make(chan struct{})
	go func() { r.t.grantScan([]string{"claude"}, "sts.amazonaws.com"); close(grant) }()
	time.Sleep(50 * time.Millisecond) // time for the grant's scan to finish first, if nothing makes it wait
	close(release)
	<-task
	<-grant
	st, _, err := r.t.loadScan("workspace:claude#1")
	if err != nil || st.checked || !slices.Equal(st.hits, []secrets.Hit{key}) {
		t.Fatalf("after both: %+v %v, want the grant's hit and the workspace unchecked", st, err)
	}
}

func TestCheckReport(t *testing.T) {
	ok := secrets.Report{Netdevs: []string{"lo"}, Hits: []secrets.Hit{{Path: "a/b", Rule: "github-pat", Line: 1}}}
	if err := checkReport(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []secrets.Report{
		{Netdevs: []string{"lo", "eth0"}}, {Netdevs: nil},
		{Netdevs: []string{"lo"}, Hits: []secrets.Hit{{Path: "/etc/x", Rule: "github-pat", Line: 1}}},
		{Netdevs: []string{"lo"}, Hits: []secrets.Hit{{Path: "../x", Rule: "github-pat", Line: 1}}},
		{Netdevs: []string{"lo"}, Hits: []secrets.Hit{{Path: "a\x1b[2J", Rule: "github-pat", Line: 1}}},
		{Netdevs: []string{"lo"}, Hits: []secrets.Hit{{Path: "a", Rule: "made-up", Line: 1}}},
	} {
		if checkReport(bad) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// The unit is built like agentbox-depcheck@: no network, a dynamic uid with only CAP_DAC_READ_SEARCH, read-only binds.
func TestScanArgv(t *testing.T) {
	a := strings.Join(scanArgv("/r", "/bin/agentbox", "/w"), " ")
	for _, p := range []string{"-p DynamicUser=yes", "-p PrivateNetwork=yes", "-p CapabilityBoundingSet=CAP_DAC_READ_SEARCH", "-p NoNewPrivileges=yes",
		"-p RootDirectory=/r", "-p BindReadOnlyPaths=/w:/ws", "-p BindReadOnlyPaths=/bin/agentbox:/agentbox", " /agentbox secretscan --dir /ws"} {
		if !strings.Contains(a, p) {
			t.Errorf("argv lacks %q: %s", p, a)
		}
	}
	if slices.Contains(strings.Fields(a), "BindPaths") {
		t.Error("a writable bind")
	}
}

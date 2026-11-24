package rootd

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"agentbox/internal/ids"
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
	if rep := r.t.secretGate(acct, 2); rep["reason"] != SecretsAckMismatch {
		t.Fatalf("--ack-secrets 2 for 1 hit: %v", rep)
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
	if found, _ := r.t.grantScan([]string{"claude"}, "pypi.org"); len(found) != 0 {
		t.Fatalf("a grant for another host named it: %v", found)
	}
	hits = append(hits, secrets.Hit{Path: ".env", Rule: "aws-access-token", Line: 1})
	if rep := start(); rep["reason"] != SecretsInWorkspace || !strings.Contains(rep["error"].(string), ".env:1 (aws-access-token)") {
		t.Fatalf("a new unacknowledged hit: %v", rep)
	}
	hits = nil
	if rep := start(); rep["ok"] != true {
		t.Fatalf("fixed: %v", rep)
	}
	r.db.Exec(`UPDATE secret_scan SET checked=0`)
	scanErr = errors.New("boom")
	if rep := start(); rep["reason"] != SecretScanFailed {
		t.Fatalf("a failed scan must block: %v", rep)
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

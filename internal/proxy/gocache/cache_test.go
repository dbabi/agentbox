package gocache

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/proxy/gocache/goproxytest"
)

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: Upstream}, DNSNames: []string{Upstream},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}

type fixture struct {
	c       *Cache
	up      *goproxytest.Server
	root    string
	mu      sync.Mutex
	recs    []map[string]any
	alerts  []string
	nack    map[string]bool // record types auditd refuses
	allowed map[string]bool
	live    map[string]bool
}

// mods are two modules at two versions, each zip about 100 KiB of incompressible data, so blobs dwarf the index.
func mods() []goproxytest.Module {
	r := mrand.New(mrand.NewPCG(1, 2))
	var m []goproxytest.Module
	for _, p := range []string{"example.com/a", "example.com/b"} {
		for _, v := range []string{"v1.0.0", "v1.1.0"} {
			b := make([]byte, 100<<10)
			for i := range b {
				b[i] = byte(r.Uint32())
			}
			m = append(m, goproxytest.Module{Path: p, Version: v, Files: map[string]string{
				"go.mod": "module " + p + "\n\ngo 1.21\n", "a.go": "package a\n\n// " + v + "\nconst V = \"" + v + "\"\n",
				"data.bin": string(b)}})
		}
	}
	return m
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	up, err := goproxytest.New("sum.golang.org", mods())
	if err != nil {
		t.Fatal(err)
	}
	cert, pool := testCert(t)
	srv := httptest.NewUnstartedServer(up)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	x := &fixture{up: up, root: t.TempDir(), nack: map[string]bool{}, allowed: map[string]bool{"ga": true, "gb": true},
		live: map[string]bool{"T1": true, "T2": true, "T3": true}}
	for _, a := range []string{"ga", "gb", "gc"} {
		os.Mkdir(filepath.Join(x.root, a), 0o700)
	}
	lim := DefaultLimits()
	lim.SlotWait = time.Second
	x.c = New(Config{Root: x.root, Key: up.VKey, Roots: pool, Limits: lim,
		Upstream: func(ctx context.Context, task string) (net.Conn, error) {
			if !x.isLive(task) {
				return nil, errors.New("no live task")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
		Audit: func(rec map[string]any) error {
			x.mu.Lock()
			defer x.mu.Unlock()
			if x.nack[rec["type"].(string)] {
				return errors.New("NACK UNAVAILABLE")
			}
			x.recs = append(x.recs, rec)
			return nil
		},
		Alert:   func(agent, reason string) { x.mu.Lock(); x.alerts = append(x.alerts, agent+" "+reason); x.mu.Unlock() },
		Allowed: func(agent string) bool { x.mu.Lock(); defer x.mu.Unlock(); return x.allowed[agent] },
		Private: func(agent string) string { return "corp.example/*" },
		Live:    x.isLive,
		Free:    func(string) (int64, error) { return 100 << 30, nil },
	})
	t.Cleanup(x.c.Close)
	return x
}

func (x *fixture) isLive(task string) bool { x.mu.Lock(); defer x.mu.Unlock(); return x.live[task] }

// do sends one request line as the proxy hands it over and returns the status and body.
func (x *fixture) do(t *testing.T, task, agent, line string) (int, []byte) {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(line + " HTTP/1.1\r\nHost: proxy\r\n\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	x.c.Serve(&out, task, agent, req)
	resp, err := http.ReadResponse(bufio.NewReader(&out), req)
	if err != nil {
		t.Fatalf("%s: reply %q: %v", line, out.String(), err)
	}
	if resp.Header.Get("Agentbox-Denial") != "" {
		t.Errorf("%s: a cache reply with a denial header", line)
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (x *fixture) records(typ, event string) []map[string]any {
	x.mu.Lock()
	defer x.mu.Unlock()
	var r []map[string]any
	for _, rec := range x.recs {
		if rec["type"] == typ && (event == "" || rec["event"] == event) {
			r = append(r, rec)
		}
	}
	return r
}

func (x *fixture) moduleGets() int {
	n := 0
	for _, l := range x.up.Log() {
		if strings.HasPrefix(l, "GET /example.com/") {
			n++
		}
	}
	return n
}

func (x *fixture) stats(t *testing.T, agent string) (int, int) {
	t.Helper()
	s, err := x.c.store(agent)
	if err != nil {
		t.Fatal(err)
	}
	var rows int
	s.db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&rows)
	blobs, _ := os.ReadDir(filepath.Join(x.root, agent, blobsDir))
	return rows, len(blobs)
}

const (
	modA  = "GET /_cache/go/example.com/a/@v/v1.0.0.mod"
	zipA  = "GET /_cache/go/example.com/a/@v/v1.0.0.zip"
	zipA1 = "GET /_cache/go/example.com/a/@v/v1.1.0.zip"
)

// A miss fills from upstream after the task's taint record, checked against the signed checksum database, with one
// ACKed fill record per file; the next request is a hit that asks upstream nothing.
func TestFillAndHit(t *testing.T) {
	x := newFixture(t)
	if st, b := x.do(t, "T1", "ga", modA); st != 200 || !bytes.Equal(b, x.up.Mod("example.com/a", "v1.0.0")) {
		t.Fatalf("mod: %d %q", st, b)
	}
	if st, b := x.do(t, "T1", "ga", zipA); st != 200 || !bytes.Equal(b, x.up.Zip("example.com/a", "v1.0.0")) {
		t.Fatalf("zip: %d (%d bytes)", st, len(b))
	}
	if n := len(x.records("TAINT", "")); n != 1 {
		t.Fatalf("%d taint records, want 1", n)
	}
	if r := x.records("TAINT", ""); r[0]["subject"] != "task:T1" || r[0]["source"] != "cache:go" {
		t.Fatalf("taint record %v", r[0])
	}
	fills := x.records("CACHE", "fill")
	if len(fills) != 2 || fills[0]["key"] != "go:example.com/a@v1.0.0.mod" || fills[1]["agent"] != "ga" || fills[1]["task"] != "T1" {
		t.Fatalf("fill records %v", fills)
	}
	x.up.Log()
	for range 3 {
		if st, _ := x.do(t, "T2", "ga", zipA); st != 200 {
			t.Fatalf("hit: %d", st)
		}
	}
	if n := x.moduleGets(); n != 0 {
		t.Errorf("a hit asked upstream %d times", n)
	}
	if rows, blobs := x.stats(t, "ga"); rows != 2 || blobs != 2 {
		t.Errorf("%d rows, %d blobs", rows, blobs)
	}
	if fi, err := os.Stat(filepath.Join(x.root, "ga", blobsDir, fills[1]["sha256"].(string))); err != nil || fi.Mode().Perm() != 0o444 {
		t.Errorf("blob: %v %v", fi, err)
	}
}

// A-G5's proxy half: everything but GET of an exact .mod or .zip gets 404, or 405 for another method, with no taint,
// no lookup and no upstream request; so does an agent without proxy.golang.org (A-G7).
func TestCacheGrammar(t *testing.T) {
	x := newFixture(t)
	for line, want := range map[string]int{
		"POST /_cache/go/example.com/a/@v/v1.0.0.mod":            405,
		"PUT /_cache/go/example.com/a/@v/v1.0.0.zip":             405,
		"GET /_cache/go/example.com/a/@v/v1.0.0.info":            404,
		"GET /_cache/go/example.com/a/@latest":                   404,
		"GET /_cache/go/example.com/a/@v/list":                   404,
		"GET /_cache/go/example.com/a/@v/v1.0.mod":               404,
		"GET /_cache/go/example.com/a/@v/v1.0.0.zip?x":           404,
		"GET /_cache/go/Example.com/a/@v/v1.0.0.zip":             404,
		"GET /_cache/go/example.com/../a/@v/v1.0.0.zip":          404,
		"GET /_cache/go/example.com/%2e%2e/@v/v1.0.0.zip":        404,
		"GET /_cache/go/corp.example/x/@v/v1.0.0.zip":            404,
		"GET /_cache/npm/left-pad":                               404,
		"GET http://proxy/_cache/go/example.com/a/@v/v1.0.0.zip": 404,
	} {
		if st, _ := x.do(t, "T1", "ga", line); st != want {
			t.Errorf("%s: %d, want %d", line, st, want)
		}
	}
	if st, _ := x.do(t, "T3", "gc", zipA); st != 404 { // gc has no proxy.golang.org
		t.Errorf("off the allowlist: %d", st)
	}
	if len(x.recs) != 0 || x.moduleGets() != 0 {
		t.Fatalf("refusals wrote %v or asked upstream", x.recs)
	}
}

// A-G6: the taint record comes first and is ACKed before any lookup; while auditd refuses it every request gets a
// bare 503; concurrent first requests share one record.
func TestTaintFirst(t *testing.T) {
	x := newFixture(t)
	x.nack["TAINT"] = true
	for range 2 {
		if st, b := x.do(t, "T1", "ga", zipA); st != 503 || len(b) != 0 {
			t.Fatalf("auditd down: %d %q", st, b)
		}
	}
	if x.moduleGets() != 0 {
		t.Fatal("a lookup before the taint record")
	}
	x.nack["TAINT"] = false
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			line := zipA
			if i%2 == 1 {
				line = modA
			}
			if st, _ := x.do(t, "T1", "ga", line); st != 200 {
				t.Errorf("parallel: %d", st)
			}
		}()
	}
	wg.Wait()
	if n := len(x.records("TAINT", "")); n != 1 {
		t.Errorf("%d taint records for 20 parallel first requests, want 1", n)
	}
	if n := len(x.records("CACHE", "fill")); n != 2 {
		t.Errorf("%d fills for 2 keys asked 10 times each, want 2", n)
	}
}

// A-G8 (a): upstream bytes that differ from the signed record are refused: sum_mismatch, an alert, no row, no blob;
// (c) a blob changed on disk is deleted and filled again.
func TestMismatchAndCorrupt(t *testing.T) {
	x := newFixture(t)
	x.up.Alter("example.com/a", "v1.0.0", "zip", true)
	if st, _ := x.do(t, "T1", "ga", zipA); st != 404 {
		t.Fatalf("an altered zip: %d", st)
	}
	if len(x.records("CACHE", "sum_mismatch")) != 1 || len(x.records("CACHE", "fill")) != 0 {
		t.Fatalf("records %v", x.recs)
	}
	if rows, blobs := x.stats(t, "ga"); rows != 0 || blobs != 0 {
		t.Fatalf("%d rows, %d blobs after a mismatch", rows, blobs)
	}
	if tmp, _ := os.ReadDir(filepath.Join(x.root, "ga", tmpDir)); len(tmp) != 0 {
		t.Fatalf("temp files left: %v", tmp)
	}
	x.up.Alter("example.com/a", "v1.0.0", "zip", false)
	if st, _ := x.do(t, "T1", "ga", zipA); st != 200 {
		t.Fatal(st)
	}
	d := x.records("CACHE", "fill")[0]["sha256"].(string)
	p := filepath.Join(x.root, "ga", blobsDir, d)
	b, _ := os.ReadFile(p)
	b[10] ^= 1
	os.Chmod(p, 0o644)
	os.WriteFile(p, b, 0o444)
	if st, got := x.do(t, "T2", "ga", zipA); st != 200 || !bytes.Equal(got, x.up.Zip("example.com/a", "v1.0.0")) {
		t.Fatalf("after a flipped byte: %d", st)
	}
	if len(x.records("CACHE", "blob_corrupt")) != 1 || len(x.records("CACHE", "fill")) != 2 {
		t.Fatalf("records %v", x.recs)
	}
	time.Sleep(10 * time.Millisecond) // alerts go out on their own goroutine
	x.mu.Lock()
	defer x.mu.Unlock()
	if strings.Join(x.alerts, ",") != "ga sum_mismatch,ga blob_corrupt" {
		t.Errorf("alerts %q", x.alerts)
	}
}

// A version the checksum database doesn't hold is a plain 404, not an alert. An inconsistent log is sumdb_security:
// the agent's fills stop until cache.purge, and another agent's don't.
func TestChecksumDatabase(t *testing.T) {
	x := newFixture(t)
	if st, _ := x.do(t, "T1", "ga", "GET /_cache/go/example.com/a/@v/v9.0.0.zip"); st != 404 || len(x.alerts) != 0 {
		t.Fatalf("unknown version: %d, alerts %v", st, x.alerts)
	}
	if st, _ := x.do(t, "T1", "ga", zipA); st != 200 {
		t.Fatal(st)
	}
	x.up.Fork()
	if st, _ := x.do(t, "T1", "ga", zipA1); st != 404 || len(x.records("CACHE", "sumdb_security")) != 1 {
		t.Fatalf("a forked log: %d, records %v", st, x.recs)
	}
	if st, _ := x.do(t, "T1", "ga", "GET /_cache/go/example.com/b/@v/v1.0.0.mod"); st != 404 {
		t.Fatalf("fills after sumdb_security: %d", st)
	}
	if st, _ := x.do(t, "T2", "gb", zipA1); st != 200 { // gb's own tree state never saw the old log
		t.Fatalf("another agent: %d", st)
	}
	if err := x.c.Purge("ga"); err != nil {
		t.Fatal(err)
	}
	if st, _ := x.do(t, "T1", "ga", zipA1); st != 200 {
		t.Fatalf("after cache.purge: %d", st)
	}
}

// A-G10: past a task's file or byte cap, or the agent's day cap, or below the disk reserve, a miss gets 404; hits still
// work. Eviction keeps the store under its limit and the newest entries.
func TestCapsAndEviction(t *testing.T) {
	x := newFixture(t)
	x.c.cfg.Limits.TaskFillMaxFiles = 1
	x.do(t, "T1", "ga", modA)
	if st, _ := x.do(t, "T1", "ga", zipA); st != 404 {
		t.Errorf("past the task's file cap: %d", st)
	}
	if st, _ := x.do(t, "T1", "ga", modA); st != 200 {
		t.Errorf("a hit past the cap: %d", st)
	}
	x.c.cfg.Limits.TaskFillMaxFiles = 100
	x.c.cfg.Limits.AgentFillDayBytes = 1
	if st, _ := x.do(t, "T2", "ga", zipA); st != 404 {
		t.Errorf("past the day cap: %d", st)
	}
	x.c.cfg.Limits.AgentFillDayBytes = 1 << 30
	x.c.cfg.Free = func(string) (int64, error) { return x.c.cfg.Limits.ReserveBytes, nil }
	if st, _ := x.do(t, "T2", "ga", zipA); st != 404 {
		t.Errorf("at the reserve: %d", st)
	}
	x.c.cfg.Free = nil // statfs
	x.c.cfg.Limits.ReserveBytes = 0
	z := int64(len(x.up.Zip("example.com/a", "v1.0.0")))
	s0, _ := x.c.store("ga")
	x.c.cfg.Limits.AgentMaxBytes = 3*z + s0.overhead() + z/2 // three zips and the index pass 90%
	for _, l := range []string{zipA, zipA1, "GET /_cache/go/example.com/b/@v/v1.0.0.zip", "GET /_cache/go/example.com/b/@v/v1.1.0.zip"} {
		if st, _ := x.do(t, "T2", "ga", l); st != 200 {
			t.Fatalf("%s: %d", l, st)
		}
		time.Sleep(2 * time.Millisecond) // filled_at orders them
	}
	s, _ := x.c.store("ga")
	if u, _ := s.usage(); u+s.overhead() > x.c.cfg.Limits.AgentMaxBytes {
		t.Errorf("usage %d and overhead %d over the limit %d", u, s.overhead(), x.c.cfg.Limits.AgentMaxBytes)
	}
	if _, ok := s.row("go:example.com/b@v1.1.0.zip"); !ok {
		t.Error("eviction dropped the newest entry")
	}
	if _, ok := s.row("go:example.com/a@v1.0.0.zip"); ok {
		t.Error("eviction kept the oldest entry")
	}
}

// A-G9, A-G12: cache.purge empties one agent's store (rows, blobs, checksum state) while another keeps its hits; a
// revoked task's fill in flight inserts no row; the start sweep removes temp files, orphan blobs and rows without blobs.
func TestPurgeRevokeSweep(t *testing.T) {
	x := newFixture(t)
	x.do(t, "T1", "ga", zipA)
	x.do(t, "T2", "gb", zipA)
	if err := x.c.Purge("ga"); err != nil {
		t.Fatal(err)
	}
	if rows, blobs := x.stats(t, "ga"); rows != 0 || blobs != 0 {
		t.Fatalf("after purge: %d rows, %d blobs", rows, blobs)
	}
	if ents, _ := os.ReadDir(filepath.Join(x.root, "ga", sumdbDir)); len(ents) != 0 {
		t.Fatalf("checksum state after purge: %v", ents)
	}
	x.up.Log()
	if st, _ := x.do(t, "T2", "gb", zipA); st != 200 || x.moduleGets() != 0 {
		t.Fatal("gb lost its hit")
	}
	if len(x.records("CACHE", "purge")) != 1 {
		t.Fatal("no purge record")
	}
	// a slow upstream: the task is revoked mid-download
	x.up.Slow(time.Second, 0)
	done := make(chan int)
	go func() { st, _ := x.do(t, "T1", "ga", zipA1); done <- st }()
	time.Sleep(300 * time.Millisecond)
	x.mu.Lock()
	x.live["T1"] = false
	x.mu.Unlock()
	x.c.Revoke("T1")
	if st := <-done; st != 404 {
		t.Fatalf("a revoked fill: %d", st)
	}
	if rows, _ := x.stats(t, "ga"); rows != 0 {
		t.Fatal("a revoked task's fill inserted a row")
	}
	x.up.Slow(0, 0)
	// a crash's leftovers
	x.do(t, "T2", "ga", zipA)
	s, _ := x.c.store("ga")
	os.WriteFile(filepath.Join(x.root, "ga", tmpDir, "left"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(x.root, "ga", blobsDir, strings.Repeat("0", 64)), []byte("orphan"), 0o444)
	s.db.Exec(`INSERT INTO entries VALUES('go:example.com/z@v1.0.0.zip', ?, 1, 'h1:x', 'proxy.golang.org', 'T9', 0, 0)`, strings.Repeat("1", 64))
	x.c.Close()
	if err := x.c.Open("ga", "gb", "gz"); err != nil { // the proxy's start; gz has no store
		t.Fatal(err)
	}
	if rows, blobs := x.stats(t, "ga"); rows != 1 || blobs != 1 {
		t.Errorf("after the start sweep: %d rows, %d blobs, want the one good entry", rows, blobs)
	}
	if tmp, _ := os.ReadDir(filepath.Join(x.root, "ga", tmpDir)); len(tmp) != 0 {
		t.Errorf("temp files after the start sweep: %v", tmp)
	}
}

// A fill's blob is safe from the rename to its row: another fill that fails, and the nightly eviction, delete only the
// blobs no row names and no fill holds.
func TestFillsKeepEachOthersBlobs(t *testing.T) {
	x := newFixture(t)
	held, hold := make(chan struct{}), make(chan struct{})
	audit := x.c.cfg.Audit
	x.c.cfg.Audit = func(rec map[string]any) error {
		if rec["type"] == "CACHE" && rec["event"] == "fill" {
			switch rec["key"] {
			case "go:example.com/a@v1.0.0.zip":
				close(held)
				<-hold // the blob is in blobs/, its row not yet
			case "go:example.com/a@v1.1.0.zip":
				return errors.New("NACK UNAVAILABLE")
			}
		}
		return audit(rec)
	}
	done := make(chan int)
	go func() { st, _ := x.do(t, "T1", "ga", zipA); done <- st }()
	<-held
	if st, _ := x.do(t, "T1", "ga", zipA1); st != 404 {
		t.Errorf("a fill whose record was refused: %d", st)
	}
	if err := x.c.Nightly("ga"); err != nil {
		t.Fatal(err)
	}
	close(hold)
	if st := <-done; st != 200 {
		t.Fatalf("the held fill: %d", st)
	}
	if rows, blobs := x.stats(t, "ga"); rows != 1 || blobs != 1 {
		t.Fatalf("%d rows, %d blobs, want the held fill's one", rows, blobs)
	}
	x.up.Log()
	if st, b := x.do(t, "T2", "ga", zipA); st != 200 || !bytes.Equal(b, x.up.Zip("example.com/a", "v1.0.0")) || x.moduleGets() != 0 {
		t.Fatalf("the held fill's hit: %d", st)
	}
}

// A store rootd deleted and made again (agent.remove, a purge with the proxy stopped) is opened afresh: the cache never
// serves or writes the old one.
func TestStoreRemade(t *testing.T) {
	x := newFixture(t)
	x.do(t, "T1", "ga", zipA)
	os.RemoveAll(filepath.Join(x.root, "ga"))
	if st, _ := x.do(t, "T1", "ga", zipA); st != 404 {
		t.Fatalf("a deleted store: %d", st)
	}
	os.Mkdir(filepath.Join(x.root, "ga"), 0o700)
	x.up.Log()
	if st, _ := x.do(t, "T1", "ga", zipA); st != 200 || x.moduleGets() != 1 {
		t.Fatalf("a new store: %d, it must miss", st)
	}
}

// The nightly eviction drops rows idle past MaxIdleDays, with no network.
func TestNightly(t *testing.T) {
	x := newFixture(t)
	x.do(t, "T1", "ga", zipA)
	now := time.Now().Add(31 * 24 * time.Hour)
	x.c.cfg.Now = func() time.Time { return now }
	x.up.Log()
	if err := x.c.Nightly("ga"); err != nil {
		t.Fatal(err)
	}
	if rows, blobs := x.stats(t, "ga"); rows != 0 || blobs != 0 || len(x.up.Log()) != 0 {
		t.Fatalf("after 31 idle days: %d rows, %d blobs", rows, blobs)
	}
}

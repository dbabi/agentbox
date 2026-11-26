// Package gocache is the proxy's read-only Go module cache (ARCHITECTURE.md §6.2 "Go module cache"): one store per
// agent in data/cache/<agent>, filled only by the proxy and only with .mod and .zip files whose hash matches the record
// the checksum database signed, and served only on a task's own proxy socket, after the task's taint record.
//
// The proxy hands Serve every origin-form request under /_cache/ on a task's proxy socket; attach and app egress
// sockets answer 404 for /_cache/ themselves. Purge is cache.purge{agent} on svc-proxy.sock, Revoke a task's revoke.
package gocache

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"

	"agentbox/internal/taskrun/gomodfilter"
)

// Upstream is the cache's one upstream, and the allowlist entry that turns it on (proxy.golang.org:443).
const Upstream = gomodfilter.Upstream

// Prefix is the cache path on a task's proxy socket.
const Prefix = gomodfilter.CachePrefix

// TaintSource is the source of both the proxy's taint record and the filter's (task.taint_self).
const TaintSource = "cache:go"

// Limits are the budgets.toml cache keys (App. E) and the fixed fill limits of §6.2.
type Limits struct {
	AgentMaxBytes     int64         // cache.agent_max_bytes: eviction works below it; the kernel qgroup enforces it
	TaskFillMaxBytes  int64         // cache.task_fill_max_bytes
	TaskFillMaxFiles  int           // cache.task_fill_max_files
	AgentFillDayBytes int64         // cache.agent_fill_day_bytes, per UTC day
	MaxIdleDays       int           // cache.max_idle_days
	ReserveBytes      int64         // disk.reserve_bytes: no fill below it
	Slots             int           // fills per agent at once
	SlotWait          time.Duration // how long a fill waits for a slot before it gives up (404)
}

// DefaultLimits are App. E's defaults.
func DefaultLimits() Limits {
	return Limits{AgentMaxBytes: 8 << 30, TaskFillMaxBytes: 2 << 30, TaskFillMaxFiles: 20000, AgentFillDayBytes: 4 << 30,
		MaxIdleDays: 30, ReserveBytes: 2 << 30, Slots: 8, SlotWait: 30 * time.Second}
}

// Config is what the proxy gives the cache. Every func is required.
type Config struct {
	Root string // data/cache
	Key  string // the checksum database's verifier key: SumKey
	// Upstream is a pinned TCP connection to proxy.golang.org:443 for task: rootd's answers only (§6.3). The cache adds
	// TLS with SNI proxy.golang.org.
	Upstream func(ctx context.Context, task string) (net.Conn, error)
	Roots    *x509.CertPool // the TLS roots; nil: the system's
	// Audit sends one record on the proxy's auditd producer socket and returns nil only on its ACK: the task's TAINT
	// before any lookup or byte, and the CACHE records of fills, mismatches, corrupt blobs and purges.
	Audit   func(rec map[string]any) error
	Alert   func(agent, reason string)      // cache.alert{agent, reason} on resolve-proxy.sock
	Allowed func(agent string) bool         // proxy.golang.org:443 is on the agent's allowlist (CONNECT step 1)
	Private func(agent string) string       // the agent's go.private patterns, "" for none
	Live    func(task string) bool          // the task is still registered: a revoked task's fill inserts no row
	Free    func(dir string) (int64, error) // free pool bytes; nil: statfs
	Limits  Limits
	Now     func() time.Time // nil: time.Now
}

// Cache is the proxy's cache: per-agent stores and per-task state.
type Cache struct {
	cfg    Config
	mu     sync.Mutex
	stores map[string]*store
	tasks  map[string]*taskState
}

// taskState is one task's: its one taint record, its fill counters and its upstream client, which a revoke closes.
type taskState struct {
	agent  string
	ctx    context.Context
	cancel context.CancelFunc

	taintMu sync.Mutex
	tainted bool

	mu     sync.Mutex
	bytes  int64
	files  int
	client *http.Client
}

// New returns a cache over cfg.
func New(cfg Config) *Cache {
	return &Cache{cfg: cfg, stores: map[string]*store{}, tasks: map[string]*taskState{}}
}

func (c *Cache) now() time.Time {
	if c.cfg.Now != nil {
		return c.cfg.Now()
	}
	return time.Now()
}

var reAgent = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// bare is a cache reply with no denial header: go falls back to the next GOPROXY entry only on a plain 404 (§6.2).
func bare(w io.Writer, status int) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status))
}

// Serve answers one origin-form request under /_cache/ on task's own proxy socket, in §6.2's order: grammar,
// allowlist, the taint record, then hit or fill. Steps 1 and 2 read only the request and the policy; everything that
// depends on the cache's state comes after the task's taint is ACKed.
func (c *Cache) Serve(w io.Writer, task, agent string, req *http.Request) {
	if !reAgent.MatchString(agent) {
		bare(w, http.StatusNotFound)
		return
	}
	f, st := gomodfilter.Request(req, Prefix, []string{"mod", "zip"}, c.cfg.Private(agent))
	if st != 0 {
		bare(w, st)
		return
	}
	if !c.cfg.Allowed(agent) {
		bare(w, http.StatusNotFound)
		return
	}
	ts := c.task(task, agent)
	if err := c.taint(ts, task); err != nil {
		log.Printf("gocache: task %s: taint not ACKed: %v", task, err)
		bare(w, http.StatusServiceUnavailable)
		return
	}
	s, err := c.store(agent)
	if err != nil {
		log.Printf("gocache: agent %s: store: %v", agent, err)
		bare(w, http.StatusNotFound)
		return
	}
	if c.serveHit(w, s, f) {
		return
	}
	if err := c.fill(ts, task, s, f); err != nil {
		log.Printf("gocache: task %s: %s: %v", task, f.Key(), err)
		bare(w, http.StatusNotFound)
		return
	}
	if !c.serveHit(w, s, f) {
		bare(w, http.StatusNotFound)
	}
}

func (c *Cache) task(task, agent string) *taskState {
	c.mu.Lock()
	defer c.mu.Unlock()
	ts := c.tasks[task]
	if ts == nil || ts.agent != agent {
		ts = &taskState{agent: agent}
		ts.ctx, ts.cancel = context.WithCancel(context.Background())
		c.tasks[task] = ts
	}
	return ts
}

// taint is §6.2 step 3: the record a CONNECT to proxy.golang.org:443 would write for the task, ACKed, before any lookup
// or response byte. One per task: concurrent first requests share it; a NACK is tried again on the next request.
func (c *Cache) taint(ts *taskState, task string) error {
	ts.taintMu.Lock()
	defer ts.taintMu.Unlock()
	if ts.tainted {
		return nil
	}
	if err := c.cfg.Audit(map[string]any{"type": "TAINT", "subject": "task:" + task, "source": TaintSource}); err != nil {
		return err
	}
	ts.tainted = true
	return nil
}

func (c *Cache) store(agent string) (*store, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s := c.stores[agent]; s != nil {
		if s.current() {
			return s, nil
		}
		s.close() // rootd deleted the store, and maybe made a new one: never write into the old one
		delete(c.stores, agent)
	}
	s, err := openStore(c.cfg.Root, agent, c.cfg.Limits.Slots)
	if err != nil {
		return nil, err
	}
	c.stores[agent] = s
	return s, nil
}

// serveHit streams a stored file whose blob matches its row; a mismatch deletes them, counts blob_corrupt and is a miss.
func (c *Cache) serveHit(w io.Writer, s *store, f gomodfilter.File) bool {
	r, ok := s.row(f.Key())
	if !ok {
		return false
	}
	b, err := s.openBlob(r)
	if err != nil {
		s.dropDigest(r.sha256)
		if errors.Is(err, errCorrupt) {
			c.record(s.agent, map[string]any{"event": "blob_corrupt", "key": r.key, "sha256": r.sha256})
			c.alert(s.agent, "blob_corrupt")
		}
		return false
	}
	defer b.Close()
	s.touch(r, c.now())
	fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", r.size)
	io.Copy(w, b)
	return true
}

// fill makes one key's fill happen once per agent at a time: a concurrent miss of the same key waits for it.
func (c *Cache) fill(ts *taskState, task string, s *store, f gomodfilter.File) error {
	key := f.Key()
	s.mu.Lock()
	if s.stopped || s.purging {
		s.mu.Unlock()
		return errStopped
	}
	if fl := s.fills[key]; fl != nil {
		s.mu.Unlock()
		<-fl.done
		return fl.err
	}
	fl := &fill{done: make(chan struct{})}
	s.fills[key] = fl
	gen, sctx := s.gen, s.ctx
	s.wg.Add(1)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.fills, key)
		s.mu.Unlock()
		close(fl.done)
		s.wg.Done()
	}()
	ctx, cancel := context.WithCancel(ts.ctx)
	defer cancel()
	stop := context.AfterFunc(sctx, cancel) // a purge cancels it too
	defer stop()
	fl.err = c.doFill(ctx, ts, task, s, gen, f)
	return fl.err
}

var (
	errStopped = errors.New("fills stopped for this agent (sumdb_security) or a purge is running")
	errCap     = errors.New("over a fill cap")
	errReserve = errors.New("pool free space at or below disk.reserve_bytes")
	errBusy    = errors.New("no fill slot within the wait")
	errGone    = errors.New("the task or the store changed during the fill")
)

// doFill is §6.2 Fill: preconditions, the download into tmp/, the checksum database check, then the blob, its audit
// record's ACK, and the row, but only while the filling task is registered and no purge ran.
func (c *Cache) doFill(ctx context.Context, ts *taskState, task string, s *store, gen uint64, f gomodfilter.File) error {
	lim := c.cfg.Limits
	ts.mu.Lock()
	over := ts.bytes >= lim.TaskFillMaxBytes || ts.files >= lim.TaskFillMaxFiles
	ts.mu.Unlock()
	if over || s.dayBytes(c.now()) >= lim.AgentFillDayBytes {
		return errCap
	}
	if free, err := c.free(s.dir); err != nil || free <= lim.ReserveBytes {
		return errReserve
	}
	t := time.NewTimer(lim.SlotWait)
	defer t.Stop()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-t.C:
		return errBusy
	case <-ctx.Done():
		return ctx.Err()
	}
	max := int64(modzip.MaxZipFile)
	if f.Ext == "mod" {
		max = modzip.MaxGoMod
	}
	tmp, name, err := s.newTemp()
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		tmp.Close()
		if !keep {
			os.Remove(tmp.Name())
		}
	}()
	client := c.client(ts, task)
	n, digest, err := download(ctx, client, "https://"+Upstream+f.Escaped(), tmp, max)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	h1, err := c.lookup(ctx, s, client, f)
	if err != nil {
		return err
	}
	if got, err := hash(f, tmp.Name()); err != nil || got != h1 {
		c.record(s.agent, map[string]any{"event": "sum_mismatch", "task": task, "key": f.Key(), "sha256": digest, "h1": h1, "bytes": n})
		c.alert(s.agent, "sum_mismatch")
		return fmt.Errorf("sum_mismatch: %s, want %s: %v", got, h1, err)
	}
	if err := s.makeRoom(n, lim.AgentMaxBytes); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Chmod(0o444); err != nil {
		return err
	}
	if err := renameNoReplace(s.tmp, name, s.blobs, digest); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	} else if err == nil {
		keep = true
	}
	if err := s.blobs.Sync(); err != nil {
		return err
	}
	r := row{key: f.Key(), sha256: digest, size: n, h1: h1}
	if err := c.cfg.Audit(map[string]any{"type": "CACHE", "event": "fill", "agent": s.agent, "task": task, "key": r.key,
		"sha256": digest, "h1": h1, "bytes": n, "result": "stored"}); err != nil {
		s.mu.Lock()
		s.dropUnnamed(nil) // the blob, unless a row already names the same bytes
		s.mu.Unlock()
		return fmt.Errorf("fill record not ACKed: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen || ctx.Err() != nil || !c.cfg.Live(task) {
		s.dropUnnamed(nil)
		return errGone
	}
	if err := s.insert(r, task, c.now()); err != nil {
		return err
	}
	ts.mu.Lock()
	ts.bytes += n
	ts.files++
	ts.mu.Unlock()
	return nil
}

func (c *Cache) free(dir string) (int64, error) {
	if c.cfg.Free != nil {
		return c.cfg.Free(dir)
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// client is the task's upstream client: TLS with SNI proxy.golang.org over the pinned dial, GET only, no redirects,
// no cookies, no credentials, the bytes as sent (no transparent gunzip). One per task, so its connections live only as
// long as the task; a revoke closes them.
func (c *Cache) client(ts *taskState, task string) *http.Client {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.client == nil {
		tr := &http.Transport{
			Proxy:              nil,
			ForceAttemptHTTP2:  true,
			DisableCompression: true,
			MaxConnsPerHost:    4,
			IdleConnTimeout:    90 * time.Second,
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				conn, err := c.cfg.Upstream(ctx, task)
				if err != nil {
					return nil, err
				}
				tc := tls.Client(conn, &tls.Config{ServerName: Upstream, RootCAs: c.cfg.Roots, NextProtos: []string{"h2", "http/1.1"},
					MinVersion: tls.VersionTLS12})
				if err := tc.HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}
				return tc, nil
			},
			ResponseHeaderTimeout: 30 * time.Second,
		}
		ts.client = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
	}
	return ts.client
}

var errRedirect = errors.New("redirect refused")

// download GETs url into w, at most max bytes, and returns the size and SHA-256 of what it wrote.
func download(ctx context.Context, client *http.Client, url string, w io.Writer, max int64) (int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("%s", resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, max+1))
	if err != nil {
		return 0, "", err
	}
	if n > max {
		return 0, "", fmt.Errorf("over %d bytes", max)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// lookup is the checksum database's h1 for f: the module zip's line, or the go.mod's.
func (c *Cache) lookup(ctx context.Context, s *store, client *http.Client, f gomodfilter.File) (string, error) {
	vers := f.Version
	if f.Ext == "mod" {
		vers += "/go.mod"
	}
	ops := &sumOps{s: s, key: c.cfg.Key, ctx: ctx, client: client}
	lines, err := sumdb.NewClient(ops).Lookup(f.Path, vers)
	if msg := ops.security.Load(); msg != nil || errors.Is(err, sumdb.ErrSecurity) {
		s.mu.Lock()
		s.stopped = true
		s.mu.Unlock()
		detail := "inconsistent checksum log"
		if msg != nil {
			detail, _, _ = strings.Cut(*msg, "\n") // the proof goes to audit as the record's event, not to the log
		}
		log.Printf("gocache: agent %s: sumdb_security: %s; fills stop until cache.purge", s.agent, detail)
		c.record(s.agent, map[string]any{"event": "sumdb_security", "key": f.Key()})
		c.alert(s.agent, "sumdb_security")
		return "", errStopped
	}
	if err != nil {
		return "", fmt.Errorf("checksum database: %w", err) // a version the log doesn't hold: a plain 404
	}
	for _, l := range lines {
		if fs := strings.Fields(l); len(fs) == 3 && fs[0] == f.Path && fs[1] == vers && strings.HasPrefix(fs[2], "h1:") {
			return fs[2], nil
		}
	}
	return "", fmt.Errorf("checksum database: no h1 line for %s %s", f.Path, vers)
}

// hash is the go command's own hash of a downloaded file: a .zip must pass zip.CheckZip and HashZip; a .mod is hashed
// as the one file go.mod (goModSum).
func hash(f gomodfilter.File, path string) (string, error) {
	if f.Ext == "mod" {
		return dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) { return os.Open(path) })
	}
	if _, err := modzip.CheckZip(module.Version{Path: f.Path, Version: f.Version}, path); err != nil {
		return "", err
	}
	return dirhash.HashZip(path, dirhash.Hash1)
}

// record is a best-effort CACHE record: it never holds up a reply.
func (c *Cache) record(agent string, rec map[string]any) {
	rec["type"], rec["agent"] = "CACHE", agent
	if err := c.cfg.Audit(rec); err != nil {
		log.Printf("gocache: agent %s: %v record not ACKed: %v", agent, rec["event"], err)
	}
}

func (c *Cache) alert(agent, reason string) { go c.cfg.Alert(agent, reason) }

// Revoke ends task's state: its fills in flight are cancelled (they insert no row) and its upstream connections close.
func (c *Cache) Revoke(task string) {
	c.mu.Lock()
	ts := c.tasks[task]
	delete(c.tasks, task)
	c.mu.Unlock()
	if ts == nil {
		return
	}
	ts.cancel()
	ts.mu.Lock()
	if ts.client != nil {
		ts.client.CloseIdleConnections()
	}
	ts.mu.Unlock()
}

// Purge is cache.purge{agent} (§6.2): it cancels the agent's fills in flight, waits for them to stop, then deletes the
// rows, blobs, temp files and checksum database state, and lifts a sumdb_security stop.
func (c *Cache) Purge(agent string) error {
	if !reAgent.MatchString(agent) {
		return fmt.Errorf("gocache: bad agent name %q", agent)
	}
	s, err := c.store(agent)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.purging = true
	s.gen++
	s.cancel()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.wipe()
	s.purging, s.stopped = false, false
	c.record(agent, map[string]any{"event": "purge", "bytes": rows})
	return err
}

// Nightly is the idle eviction of every store under Root: rows unused for more than MaxIdleDays, then the blobs no row
// names. It makes no network request.
func (c *Cache) Nightly() error {
	ents, err := os.ReadDir(c.cfg.Root)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		if !e.IsDir() || !reAgent.MatchString(e.Name()) {
			continue
		}
		s, err := c.store(e.Name())
		if err == nil {
			err = s.evictIdle(c.now(), c.cfg.Limits.MaxIdleDays)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Close closes every store.
func (c *Cache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for a, s := range c.stores {
		s.close()
		delete(c.stores, a)
	}
}

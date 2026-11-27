package gocache

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// An agent's store, data/cache/<agent> (§6.2, App. E): rootd makes it, a subvolume owned by agentbox-proxy, mode 0700.
const (
	indexDB  = "index.db"
	blobsDir = "blobs"
	sumdbDir = "sumdb"
	tmpDir   = "tmp"
)

// schema is App. E's index. sha256, size and h1 never change after insert; used_at moves at most once an hour.
const schema = `
CREATE TABLE IF NOT EXISTS entries(key TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL, h1 TEXT NOT NULL,
  upstream TEXT NOT NULL, filled_by_task TEXT NOT NULL, filled_at INTEGER NOT NULL, used_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS fill_days(day_start INTEGER PRIMARY KEY, bytes INTEGER NOT NULL) STRICT;
`

var reDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type row struct {
	key, sha256, h1 string
	size            int64
	usedAt          int64
}

// store is one agent's: its index, its blobs, its fills in flight and their slots, and its checksum database state.
type store struct {
	agent, dir string
	id         string // the store's id file: rootd may delete the store and make a new one (agent.remove, a purge)
	db         *sql.DB
	blobs, tmp *os.File // dir handles: blobs open beneath blobs
	slots      chan struct{}

	mu      sync.Mutex
	gen     uint64 // a purge moves it: a fill from before inserts no row
	ctx     context.Context
	cancel  context.CancelFunc // purge cancels every fill in flight
	wg      sync.WaitGroup     // the fills in flight
	fills   map[string]*fill   // coalesced by key
	pending map[string]int     // blobs a fill renamed in and has no row for yet: no cleanup deletes them
	purging bool
	stopped bool // sumdb_security: no fills until cache.purge

	cfgMu sync.Mutex // the checksum database's latest-tree file, compare and swap
}

// fill is one in-flight fill; waiters for the same key read err once done is closed.
type fill struct {
	done chan struct{}
	err  error
}

// openStore opens the agent's store under root, makes its dirs, and sweeps it as at proxy start: no temp file, no blob
// without a row, no row without a blob. A missing store is an error: only rootd makes one.
func openStore(root, agent string, slots int) (*store, error) {
	dir := filepath.Join(root, agent)
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("gocache: %s is not a directory", dir)
	}
	for _, d := range []string{blobsDir, tmpDir, sumdbDir} {
		p := filepath.Join(dir, d)
		if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		// the unit's UMask=0117, for its 0660 task sockets, makes a Mkdir 0600: a dir no one can make a file in
		if err := os.Chmod(p, 0o700); err != nil {
			return nil, err
		}
	}
	// journal_size_limit: a checkpoint truncates the WAL, which the store's kernel limit counts
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, indexDB)+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(10000)&_pragma=journal_size_limit(1048576)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	id, err := storeID(dir, true)
	if err != nil {
		db.Close()
		return nil, err
	}
	s := &store{agent: agent, dir: dir, id: id, db: db, slots: make(chan struct{}, slots), fills: map[string]*fill{},
		pending: map[string]int{}}
	if s.blobs, err = os.Open(filepath.Join(dir, blobsDir)); err == nil {
		s.tmp, err = os.Open(filepath.Join(dir, tmpDir))
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, s.sweep()
}

// storeID is the random id in the store's id file, made if create is set and there is none. A subvolume made again
// has a new id even where it has the same inode and device numbers.
func storeID(dir string, create bool) (string, error) {
	p := filepath.Join(dir, "id")
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) && create {
		r := newID()
		if err = writeFile(p, []byte(r)); err == nil {
			return r, nil
		}
	}
	return string(b), err
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// current reports whether the store on disk is still the one s opened.
func (s *store) current() bool {
	id, err := storeID(s.dir, false)
	return err == nil && id == s.id
}

func (s *store) close() {
	s.cancel()
	s.db.Close()
	s.blobs.Close()
	s.tmp.Close()
}

// sweep is the start sweep (§6.2 Store): it deletes tmp/, blobs no row names and rows with no blob.
func (s *store) sweep() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := emptyDir(filepath.Join(s.dir, tmpDir)); err != nil {
		return err
	}
	have := map[string]bool{}
	rows, err := s.db.Query(`SELECT key, sha256 FROM entries`)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var k, d string
		if err := rows.Scan(&k, &d); err != nil {
			rows.Close()
			return err
		}
		if _, err := os.Lstat(filepath.Join(s.dir, blobsDir, d)); err != nil {
			gone = append(gone, k)
			continue
		}
		have[d] = true
	}
	rows.Close()
	for _, k := range gone {
		if _, err := s.db.Exec(`DELETE FROM entries WHERE key=?`, k); err != nil {
			return err
		}
	}
	return s.dropUnnamed(have)
}

// dropUnnamed deletes each blob that isn't in named and that no fill holds; call it with s.mu held.
func (s *store) dropUnnamed(named map[string]bool) error {
	if named == nil {
		named = map[string]bool{}
		rows, err := s.db.Query(`SELECT DISTINCT sha256 FROM entries`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var d string
			rows.Scan(&d)
			named[d] = true
		}
		rows.Close()
	}
	ents, err := os.ReadDir(filepath.Join(s.dir, blobsDir))
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !named[e.Name()] && s.pending[e.Name()] == 0 {
			if err := os.Remove(filepath.Join(s.dir, blobsDir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// dropBlob deletes blobs/<digest> unless a row names it or a fill holds it; call it with s.mu held.
func (s *store) dropBlob(digest string) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM entries WHERE sha256=?`, digest).Scan(&n); err == nil && n == 0 &&
		s.pending[digest] == 0 && reDigest.MatchString(digest) {
		os.Remove(filepath.Join(s.dir, blobsDir, digest))
	}
}

func emptyDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (s *store) row(key string) (row, bool) {
	r := row{key: key}
	err := s.db.QueryRow(`SELECT sha256, size, h1, used_at FROM entries WHERE key=?`, key).Scan(&r.sha256, &r.size, &r.h1, &r.usedAt)
	return r, err == nil && reDigest.MatchString(r.sha256)
}

// touch moves used_at, at most once an hour (App. E).
func (s *store) touch(r row, now time.Time) {
	if now.UnixMilli()-r.usedAt >= time.Hour.Milliseconds() {
		s.db.Exec(`UPDATE entries SET used_at=? WHERE key=?`, now.UnixMilli(), r.key)
	}
}

// openBlob opens blobs/<digest> beneath the store's blobs dir and checks it against digest and size before the first
// byte goes out (§6.2 Hit). The file comes back at offset 0.
func (s *store) openBlob(r row) (*os.File, error) {
	f, err := openBeneath(s.blobs, r.sha256)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err == nil && (hex.EncodeToString(h.Sum(nil)) != r.sha256 || n != r.size) {
		err = errCorrupt
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

var errCorrupt = errors.New("blob does not match its row")

// dropDigest deletes every row that names digest, and the blob.
func (s *store) dropDigest(digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec(`DELETE FROM entries WHERE sha256=?`, digest)
	if reDigest.MatchString(digest) {
		os.Remove(filepath.Join(s.dir, blobsDir, digest))
	}
}

// newTemp is tmp/<random>, made with O_EXCL and mode 0600 in the proxy's own 0700 store: no other writer can change it
// between the hash and the rename.
func (s *store) newTemp() (*os.File, string, error) {
	b := make([]byte, 16)
	rand.Read(b)
	name := hex.EncodeToString(b)
	f, err := os.OpenFile(filepath.Join(s.dir, tmpDir, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	return f, name, err
}

// usage is the bytes the store's blobs hold, each counted once.
func (s *store) usage() (int64, error) {
	var n sql.NullInt64
	err := s.db.QueryRow(`SELECT SUM(size) FROM (SELECT MAX(size) AS size FROM entries GROUP BY sha256)`).Scan(&n)
	return n.Int64, err
}

// overhead is what the store holds besides its blobs: the index and its WAL, the checksum database state and temp
// files. The kernel limit counts them too.
func (s *store) overhead() int64 {
	var n int64
	for _, d := range []string{"", sumdbDir, tmpDir} {
		ents, _ := os.ReadDir(filepath.Join(s.dir, d))
		for _, e := range ents {
			if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() {
				n += fi.Size()
			}
		}
	}
	return n
}

// makeRoom is §6.2's eviction: before a fill of n bytes would pass 90% of max, it deletes least-recently-used rows
// until usage is under 80%, then each blob no row names. Usage is the blobs plus the overhead, so the kernel limit,
// which counts every byte of the store, is never what stops a fill. An open stream keeps its file.
func (s *store) makeRoom(n, max int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.usage()
	o := s.overhead()
	if err != nil || u+o+n <= max*9/10 {
		return err
	}
	for u+o+n > max*8/10 {
		var k string
		if err := s.db.QueryRow(`SELECT key FROM entries ORDER BY used_at, filled_at LIMIT 1`).Scan(&k); err != nil {
			break // no rows left
		}
		if _, err := s.db.Exec(`DELETE FROM entries WHERE key=?`, k); err != nil {
			return err
		}
		if u, err = s.usage(); err != nil {
			return err
		}
	}
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`) // the WAL counts against the limit too
	return s.dropUnnamed(nil)
}

// evictIdle is the nightly eviction: rows idle for more than days, then the blobs no row names. Local work only.
func (s *store) evictIdle(now time.Time, days int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM entries WHERE used_at < ?`, now.Add(-time.Duration(days)*24*time.Hour).UnixMilli()); err != nil {
		return err
	}
	return s.dropUnnamed(nil)
}

// dayStart is 00:00 UTC of now's day, in Unix ms.
func dayStart(now time.Time) int64 {
	return now.UTC().Truncate(24 * time.Hour).UnixMilli()
}

func (s *store) dayBytes(now time.Time) int64 {
	var n int64
	s.db.QueryRow(`SELECT bytes FROM fill_days WHERE day_start=?`, dayStart(now)).Scan(&n)
	return n
}

// insert is a fill's last step: the row, and the day's fill bytes, in one transaction.
func (s *store) insert(r row, task string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ms := now.UnixMilli()
	if _, err := tx.Exec(`INSERT INTO entries VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(key) DO NOTHING`, r.key, r.sha256, r.size, r.h1,
		Upstream, task, ms, ms); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO fill_days VALUES(?,?) ON CONFLICT(day_start) DO UPDATE SET bytes=bytes+excluded.bytes`,
		dayStart(now), r.size); err != nil {
		return err
	}
	return tx.Commit()
}

// wipe is a purge's delete: every row, blob, temp file and the checksum database state. The day's fill bytes stay.
func (s *store) wipe() (rows int64, err error) {
	res, err := s.db.Exec(`DELETE FROM entries`)
	if err != nil {
		return 0, err
	}
	rows, _ = res.RowsAffected()
	for _, d := range []string{blobsDir, tmpDir, sumdbDir} {
		if err := emptyDir(filepath.Join(s.dir, d)); err != nil {
			return rows, err
		}
	}
	return rows, nil
}

package gocache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/mod/sumdb"
)

// SumKey is the checksum database key the go command pins (cmd/go/internal/modfetch/key.go). Only a test stand-in
// for the proxy passes another one.
const SumKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"

// maxSumdb caps one checksum database reply (a lookup record, a tile or the latest tree).
const maxSumdb = 1 << 20

// sumOps is sumdb.ClientOps for one lookup in one agent's store (§6.2 Fill step 3): the remote is
// https://proxy.golang.org/sumdb/<name>/ through the filling task's pinned client, and the tree state and tiles live
// in the agent's sumdb/, never shared with another agent. A cache file name is the SHA-256 of the client's name for
// it, so no module path becomes a file name.
type sumOps struct {
	s        *store
	key      string
	ctx      context.Context
	client   *http.Client
	security atomic.Pointer[string]
}

func (o *sumOps) name() string { n, _, _ := strings.Cut(o.key, "+"); return n }

func (o *sumOps) ReadRemote(path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(o.ctx, http.MethodGet, "https://"+Upstream+"/sumdb/"+o.name()+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", path, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSumdb+1))
	if err == nil && len(b) > maxSumdb {
		err = fmt.Errorf("%s: reply over %d bytes", path, maxSumdb)
	}
	return b, err
}

func (o *sumOps) latest() string { return filepath.Join(o.s.dir, sumdbDir, "latest") }

func (o *sumOps) ReadConfig(file string) ([]byte, error) {
	switch file {
	case "key":
		return []byte(o.key), nil
	case o.name() + "/latest":
		b, err := os.ReadFile(o.latest())
		if os.IsNotExist(err) {
			return nil, nil // an empty tree: the client starts over
		}
		return b, err
	}
	return nil, fmt.Errorf("no config file %q", file)
}

func (o *sumOps) WriteConfig(file string, old, new []byte) error {
	if file != o.name()+"/latest" {
		return fmt.Errorf("no config file %q", file)
	}
	o.s.cfgMu.Lock()
	defer o.s.cfgMu.Unlock()
	cur, err := os.ReadFile(o.latest())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if !bytes.Equal(cur, old) {
		return sumdb.ErrWriteConflict
	}
	return writeFile(o.latest(), new)
}

func (o *sumOps) cacheFile(file string) string {
	h := sha256.Sum256([]byte(file))
	return filepath.Join(o.s.dir, sumdbDir, "c-"+hex.EncodeToString(h[:]))
}

func (o *sumOps) ReadCache(file string) ([]byte, error) { return os.ReadFile(o.cacheFile(file)) }

func (o *sumOps) WriteCache(file string, data []byte) { writeFile(o.cacheFile(file), data) }

func (o *sumOps) Log(msg string) { log.Printf("gocache %s: sumdb: %s", o.s.agent, msg) }

// SecurityError is an inconsistent checksum log: the lookup fails with ErrSecurity, and the agent's fills stop until
// cache.purge.
func (o *sumOps) SecurityError(msg string) { o.security.Store(&msg) }

// writeFile replaces p with b: a temp file in the same dir, fsynced, renamed over p, and the dir fsynced.
func writeFile(p string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), ".w-")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), p)
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

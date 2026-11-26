package gomodfilter

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The filter's fixed values (§6.2 Task-side filter).
const (
	Addr         = "127.0.0.1:8083" // inside the container only (Network=none)
	Upstream     = "proxy.golang.org"
	InfoMax      = 64 << 10         // the live check reads at most this much of a .info reply
	CheckTimeout = 10 * time.Second // per live check
	RetryAfter   = 60 * time.Second // a failed live check is asked again after this, never cached longer
	CachePrefix  = "/_cache/go"     // the proxy's cache path on the task's proxy socket
)

// Filter serves one task. Taint and Dial are required.
type Filter struct {
	Private string                                      // the agent's go.private patterns (GOPRIVATE)
	Taint   func() error                                // task.taint_self{source: cache:go} on the task's gate socket
	Dial    func(ctx context.Context) (net.Conn, error) // a new connection to the task's proxy socket
	Roots   *x509.CertPool                              // the live check's roots; nil: the image's
	Now     func() time.Time                            // nil: time.Now

	taintOnce sync.Once
	taintErr  error

	mu     sync.Mutex
	checks map[string]*check // module@version: the live check's outcome
	h2     atomic.Bool       // a tunnel negotiated HTTP/2
	h1     atomic.Bool       // HTTP/2 over the tunnel failed once: HTTP/1.1 keep-alive for the rest of the task
	client *http.Client
}

// check is one version's live check; done is closed when it has an outcome.
type check struct {
	done chan struct{}
	ok   bool
	info []byte
	at   time.Time
}

// Start serves f on Addr until ctx ends. A listen failure is returned at once.
func Start(ctx context.Context, f *Filter) error {
	ln, err := net.Listen("tcp", Addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: 30 * time.Second}
	go srv.Serve(ln)
	go func() { <-ctx.Done(); srv.Close() }()
	return nil
}

func (f *Filter) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// notFound is the filter's own reply to everything it doesn't serve: go moves to the next GOPROXY entry only on 404
// or 410.
func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNotFound)
}

// ServeHTTP is §6.2 Task-side filter steps 1 to 4.
func (f *Filter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	file, st := Request(r, "", []string{"info", "mod", "zip"}, f.Private)
	if st != 0 || !f.tainted() {
		notFound(w)
		return
	}
	info, ok := f.live(file)
	if !ok {
		notFound(w)
		return
	}
	if file.Ext == "info" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(info)))
		w.Write(info)
		return
	}
	f.serveCache(w, r.Context(), file)
}

// tainted is step 2: the task's taint record, once, before the filter's first request to the proxy. If it fails, the
// filter answers 404 to everything for the rest of the task, and go uses CONNECT.
func (f *Filter) tainted() bool {
	f.taintOnce.Do(func() { f.taintErr = f.Taint() })
	return f.taintErr == nil
}

// live is step 3: once per version per task, proxy.golang.org's .info over TLS through a CONNECT on the task's proxy
// socket. Only a 200 whose JSON Version is the request's makes the version available; anything else makes every file
// of it 404, and is asked again only after RetryAfter. Concurrent asks for one version share one check.
func (f *Filter) live(file File) ([]byte, bool) {
	key := file.Path + "@" + file.Version
	f.mu.Lock()
	if f.checks == nil {
		f.checks = map[string]*check{}
	}
	c := f.checks[key]
	if c != nil {
		select {
		case <-c.done:
			if !c.ok && f.now().Sub(c.at) >= RetryAfter {
				c = nil
			}
		default:
		}
	}
	if c == nil {
		c = &check{done: make(chan struct{})}
		f.checks[key] = c
		f.mu.Unlock()
		c.info, c.ok = f.fetchInfo(file)
		c.at = f.now()
		close(c.done)
	} else {
		f.mu.Unlock()
		<-c.done
	}
	return c.info, c.ok
}

func (f *Filter) fetchInfo(file File) ([]byte, bool) {
	info := File{file.Path, file.Version, "info"}
	b, err := f.get(info)
	if err != nil && errors.Is(err, errTransport) && f.h2.Load() && !f.h1.Load() {
		// HTTP/2 over the tunnel failed: HTTP/1.1 keep-alive from now on, and this check once more
		f.h1.Store(true)
		f.mu.Lock()
		if f.client != nil {
			f.client.CloseIdleConnections()
			f.client = nil
		}
		f.mu.Unlock()
		b, err = f.get(info)
	}
	if err != nil || !InfoOK(b, file.Version) {
		return nil, false
	}
	return b, true
}

// InfoOK is the .info reply check: JSON whose Version is the one asked for, in at most InfoMax bytes.
func InfoOK(b []byte, version string) bool {
	var v struct{ Version string }
	return version != "" && len(b) <= InfoMax && json.Unmarshal(b, &v) == nil && v.Version == version
}

var errTransport = errors.New("live check transport")

// get fetches one file from proxy.golang.org: 200 or an error, at most InfoMax bytes, no redirects.
func (f *Filter) get(file File) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), CheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+Upstream+file.Escaped(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.liveClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errTransport, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", file.Key(), resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, InfoMax+1))
	if err != nil || len(b) > InfoMax {
		return nil, fmt.Errorf("%s: reply over %d bytes or cut: %v", file.Key(), InfoMax, err)
	}
	return b, nil
}

// liveClient is the task's one live-check client: TLS with SNI proxy.golang.org through one CONNECT tunnel, kept for
// every check, HTTP/2 unless it failed. No proxy from the environment, no cookies, no redirects.
func (f *Filter) liveClient() *http.Client {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.client == nil {
		protos := []string{"h2", "http/1.1"}
		if f.h1.Load() {
			protos = protos[1:]
		}
		tr := &http.Transport{
			Proxy:             nil,
			ForceAttemptHTTP2: !f.h1.Load(),
			MaxConnsPerHost:   1, // one tunnel: HTTP/2 multiplexes every check on it
			IdleConnTimeout:   5 * time.Minute,
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return f.tunnel(ctx, protos)
			},
		}
		f.client = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return f.client
}

// tunnel opens CONNECT proxy.golang.org:443 on the task's proxy socket and TLS over it.
func (f *Filter) tunnel(ctx context.Context, protos []string) (net.Conn, error) {
	c, err := f.Dial(ctx)
	if err != nil {
		return nil, err
	}
	dl, _ := ctx.Deadline()
	c.SetDeadline(dl)
	target := Upstream + ":443"
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("CONNECT %s: %s", target, resp.Status)
	}
	c.SetDeadline(time.Time{})
	tc := tls.Client(&bufConn{c, br}, &tls.Config{ServerName: Upstream, RootCAs: f.Roots, NextProtos: protos, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, err
	}
	if tc.ConnectionState().NegotiatedProtocol == "h2" {
		f.h2.Store(true)
	}
	return tc, nil
}

// bufConn reads what the CONNECT reply's reader already buffered first.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// serveCache is step 4 for .mod and .zip: GET /_cache/go/... on the task's proxy socket, built from the checked file.
// A 200 body streams through unchanged; any other reply becomes 404, and go falls back.
func (f *Filter) serveCache(w http.ResponseWriter, ctx context.Context, file File) {
	c, err := f.Dial(ctx)
	if err != nil {
		notFound(w)
		return
	}
	defer c.Close()
	if _, err := fmt.Fprintf(c, "GET %s%s HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n\r\n", CachePrefix, file.Escaped()); err != nil {
		notFound(w)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodGet})
	if err != nil {
		notFound(w)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength < 0 {
		notFound(w)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, resp.Body)
}

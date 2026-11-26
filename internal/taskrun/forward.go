package taskrun

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"syscall"
	"time"

	"agentbox/internal/ops"
)

// Channel is one forwarder: a loopback listener inside the container relaying to a broker's per-task socket.
type Channel struct {
	Name   string // the BROKER_UNAVAILABLE what: egress, llm or git
	Addr   string // the listener, inside the container only (Network=none)
	Socket string // the broker's socket, in a dir mounted read-only (Appendix C)
	By     string // the enforcer a broker denial on this channel comes from
}

// Channels are the three forwarders (§4.2 Inside the container, step 2): egress is a CONNECT relay, llm and git are
// reverse proxies.
var Channels = []Channel{
	{"egress", "127.0.0.1:8080", "/run/agentbox/egress/proxy.sock", "proxy"},
	{"llm", "127.0.0.1:8081", "/run/agentbox/llm/keys.sock", "keys"},
	{"git", "127.0.0.1:8082", "/run/agentbox/git/git.sock", "git"},
}

// BrokerRetry is how long a forwarder retries a missing or refusing broker socket before it answers 503
// BROKER_UNAVAILABLE: long enough for a broker restart, short enough to answer within pip's 15 s timeout.
const BrokerRetry = 5 * time.Second

const maxDenialBody = 64 << 10

// Forwarder serves one Channel.
type Forwarder struct {
	Ch    Channel
	Rec   *Recorder
	Retry time.Duration // BrokerRetry; shorter only in tests
	rp    *httputil.ReverseProxy
}

// Start listens on every channel and serves until ctx ends. A listen failure is returned at once.
func Start(ctx context.Context, chans []Channel, rec *Recorder) error {
	var lns []net.Listener
	for _, ch := range chans {
		ln, err := net.Listen("tcp", ch.Addr)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return err
		}
		lns = append(lns, ln)
		srv := &http.Server{Handler: (&Forwarder{Ch: ch, Rec: rec, Retry: BrokerRetry}).Handler(), ReadHeaderTimeout: 30 * time.Second}
		go srv.Serve(ln)
		go func() { <-ctx.Done(); srv.Close() }()
	}
	return nil
}

// dial connects to the broker, retrying ENOENT and ECONNREFUSED (a broker restarting) until f.Retry passes.
func (f *Forwarder) dial(ctx context.Context) (net.Conn, error) {
	end := time.Now().Add(f.Retry)
	for {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", f.Ch.Socket)
		if err == nil || !(errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)) || time.Now().After(end) {
			return c, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Handler is the forwarder: CONNECT on egress is a tunnel; every other request goes through a reverse proxy.
// shortcut: a non-CONNECT request on egress reaches the proxy in origin form, so the proxy can't yet tell an
// absolute-form plain-http request (EGRESS_WRONG_ROUTE{plain_http}) from /_cache/; the proxy and that check are weeks 7-8.
func (f *Forwarder) Handler() http.Handler {
	f.rp = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host = "http", "broker"
			r.Out.Host = r.In.Host
		},
		Transport: &http.Transport{
			DialContext:        func(ctx context.Context, _, _ string) (net.Conn, error) { return f.dial(ctx) },
			DisableCompression: true,
			// -1 keeps no idle conn, so each request dials afresh: a kept-alive conn to a broker that restarted fails the
			// next POST at once (the transport won't replay a body), and only dial retries ENOENT and ECONNREFUSED inside
			// f.Retry. Not DisableKeepAlives: its Connection: close makes a Go broker that answers before it reads the
			// whole body hang up at once, and the body write's EPIPE can then beat the answer out of RoundTrip (#168)
			MaxIdleConnsPerHost: -1,
		},
		FlushInterval: -1, // streamed LLM replies and git packs pass through as they arrive
		ModifyResponse: func(resp *http.Response) error {
			f.saw(resp.Header, ops.Subject{})
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { f.unavailable(w) },
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && f.Ch.Name == "egress" {
			f.tunnel(w, r)
			return
		}
		f.rp.ServeHTTP(w, r)
	})
}

// saw logs a broker denial from its response head only: code, next and id from the header, and the subject from the
// forwarder's own request. Msg and remedy come from this binary's registry, so no broker byte reaches the log.
func (f *Forwarder) saw(h http.Header, sub ops.Subject) {
	c, next, id, ok := ops.ParseDenialHeader(h.Get(ops.DenialHeaderName))
	if !ok {
		return
	}
	d := ops.Deny(c, "", ops.Slots{By: f.Ch.By, Subject: sub})
	d.ID, d.Next = id, next
	f.Rec.Record(d)
}

// unavailable is the forwarder's own 503 BROKER_UNAVAILABLE{<channel>}, in that channel's format.
func (f *Forwarder) unavailable(w http.ResponseWriter) {
	d := ops.Deny(ops.BrokerUnavailable, f.Ch.Name, ops.Slots{By: "forwarder"})
	f.Rec.Record(d)
	h := w.Header()
	h.Set(ops.DenialHeaderName, ops.DenialHeader(d))
	var body []byte
	switch f.Ch.Name {
	case "llm":
		body = ops.KeysBody(d)
		h.Set("Content-Type", "application/json")
		h.Set("x-should-retry", "true")
	case "git":
		body = ops.GitBody(d)
		h.Set("Content-Type", "text/plain; charset=utf-8")
	default:
		body = ops.ConnectBody(d)
		h.Set("Content-Type", "application/json")
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write(body)
}

// tunnel relays one CONNECT. The reply head is written raw, so the client sees the broker's reason phrase
// (`agentbox <CODE> (run: agentbox why)`); http.ResponseWriter can't set one.
func (f *Forwarder) tunnel(w http.ResponseWriter, r *http.Request) {
	host, port, _ := net.SplitHostPort(r.Host)
	p, _ := strconv.ParseInt(port, 10, 32)
	sub := ops.Subject{Host: host, Port: p}
	cc, cbuf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer cc.Close()
	uc, err := f.dial(r.Context())
	if err != nil {
		d := ops.Deny(ops.BrokerUnavailable, f.Ch.Name, ops.Slots{By: "forwarder"})
		f.Rec.Record(d)
		body := ops.ConnectBody(d)
		fmt.Fprintf(cc, "HTTP/1.1 503 %s\r\n%s: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			ops.ConnectReason(d), ops.DenialHeaderName, ops.DenialHeader(d), len(body), body)
		return
	}
	defer uc.Close()
	fmt.Fprintf(uc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", r.Host, r.Host)
	ubuf := bufio.NewReader(uc)
	resp, err := http.ReadResponse(ubuf, r)
	if err != nil {
		return
	}
	f.saw(resp.Header, sub)
	head := resp.Proto + " " + resp.Status + "\r\n"
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDenialBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		resp.Header.Set("Connection", "close")
		io.WriteString(cc, head)
		resp.Header.Write(cc)
		io.WriteString(cc, "\r\n")
		cc.Write(body)
		return
	}
	io.WriteString(cc, head)
	resp.Header.Write(cc)
	io.WriteString(cc, "\r\n")
	done := make(chan struct{}, 2)
	go func() { io.Copy(uc, cbuf); closeWrite(uc); done <- struct{}{} }() // cbuf: bytes the client sent after its head
	go func() { io.Copy(cc, ubuf); closeWrite(cc); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

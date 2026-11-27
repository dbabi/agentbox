// Package dial is the brokers' pinned dialing (ARCHITECTURE.md §6.2 step 3, §6.3). A broker never resolves a name
// itself: it asks rootd on its resolve-<svc>.sock, which checks the name (Appendix B), adds the answers to <svc>_dst
// and returns them. The broker then dials exactly those addresses, in order, within one 10 s budget. TLS SNI, the
// certificate check and the Host header keep the original host name.
package dial

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"agentbox/internal/rootd/resolve"
)

// Budget is the one dial budget a connection's addresses share (§6.2 step 3; keys: §6.3).
const Budget = 10 * time.Second

// What a failed dial was (EGRESS_DIAL_FAILED's what, §5.6). An nft drop is a timeout: the kernel keeps resending the
// SYN it dropped.
const (
	Timeout = "timeout" // the budget ran out
	Refused = "refused" // the upstream, or a reject on the way, reset the connection
	Blocked = "blocked" // any other failure: no route, unreachable, not permitted
)

// Error is a dial that reached none of rootd's addresses. Err is the last address's failure, the one the rest of the
// budget went to.
type Error struct {
	What string
	Err  error
}

func (e *Error) Error() string { return "dial " + e.What + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Resolve asks rootd on sock for host:port and returns its checked addresses in order. The proxy names the task it
// resolves for; keys and git pass "". Any failure is a *resolve.Refused with one of the four reasons a broker maps to
// its denial (§6.2 step 2): rootd's own, or unavailable when rootd can't be asked.
func Resolve(ctx context.Context, sock, task, host string, port uint16) ([]netip.Addr, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, unavailable(err)
	}
	defer c.Close()
	dl := time.Now().Add(Budget + 5*time.Second) // rootd gives up on resolved after 10 s
	if t, ok := ctx.Deadline(); ok && t.Before(dl) {
		dl = t
	}
	c.SetDeadline(dl)
	req, _ := json.Marshal(map[string]any{"op": "resolve", "host": host, "port": port, "task": task})
	if _, err := c.Write(append(req, '\n')); err != nil {
		return nil, unavailable(err)
	}
	line, err := bufio.NewReader(io.LimitReader(c, 64<<10)).ReadBytes('\n')
	if err != nil {
		return nil, unavailable(err)
	}
	return parseReply(line)
}

func unavailable(err error) error {
	return &resolve.Refused{Reason: resolve.Unavailable, Detail: err.Error()}
}

// parseReply reads rootd's resolve reply line.
func parseReply(line []byte) ([]netip.Addr, error) {
	var rep struct {
		OK     bool     `json:"ok"`
		Reason string   `json:"reason"`
		Addrs  []string `json:"addrs"`
	}
	if err := json.Unmarshal(line, &rep); err != nil {
		return nil, unavailable(err)
	}
	if !rep.OK {
		switch rep.Reason {
		case resolve.NotAllowlisted, resolve.NonPublic, resolve.NoSuchName:
			return nil, &resolve.Refused{Reason: rep.Reason}
		}
		return nil, &resolve.Refused{Reason: resolve.Unavailable, Detail: "rootd: " + rep.Reason}
	}
	if len(rep.Addrs) == 0 {
		return nil, unavailable(errors.New("rootd answered no address"))
	}
	out := make([]netip.Addr, len(rep.Addrs))
	for i, s := range rep.Addrs {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" || a.Is4In6() {
			return nil, unavailable(fmt.Errorf("rootd answered %q", s))
		}
		out[i] = a
	}
	return out, nil
}

// Dialer is pinned dialing on one resolve socket. Task is the task the proxy dials for; keys and git leave it empty.
type Dialer struct {
	Sock, Task string
	dial       func(ctx context.Context, network, addr string) (net.Conn, error) // tests; nil is a net.Dialer
}

// DialContext is the DialContext of an http.Transport: it never looks addr's host up. It asks rootd and dials only
// rootd's addresses, in order, each with an even share of what is left of Budget. It returns a *resolve.Refused when
// rootd refuses the name, and an *Error when no address answers.
func (d Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("dial %s %s: tcp only", network, addr)
	}
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("dial %s: bad port", addr)
	}
	addrs, err := Resolve(ctx, d.Sock, d.Task, host, uint16(port))
	if err != nil {
		return nil, err
	}
	dial := d.dial
	if dial == nil {
		dial = new(net.Dialer).DialContext
	}
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	end, _ := ctx.Deadline()
	var last error
	for i, a := range addrs {
		actx, acancel := context.WithDeadline(ctx, time.Now().Add(time.Until(end)/time.Duration(len(addrs)-i)))
		c, err := dial(actx, "tcp", netip.AddrPortFrom(a, uint16(port)).String()) // an IP literal: no lookup
		acancel()
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, &Error{What: what(last), Err: last}
}

func what(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return Refused
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return Timeout
	}
	return Blocked
}

// Transport is an http.Transport whose every connection is a pinned dial: never the environment's proxy, and TLS that
// checks the original host name, which also goes in SNI and the Host header.
func (d Dialer) Transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = d.DialContext
	return t
}

// ErrRedirect is what Client returns for any redirect: its target would need its own allowlist entry (§6.3).
var ErrRedirect = errors.New("dial: redirect not followed")

// Client is an http.Client on Transport that follows no redirect and keeps no cookies (§6.3).
func (d Dialer) Client() *http.Client {
	return &http.Client{Transport: d.Transport(), CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect }}
}

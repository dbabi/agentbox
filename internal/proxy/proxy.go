// Package proxy is agentbox-proxy (ARCHITECTURE.md §6.2): the egress path of every task. It holds no secrets. Each
// connection on a task's proxy.sock (bound through internal/gate) carries one HTTP request. A CONNECT to a host:port on
// the agent's allowlist is resolved by rootd, dialed only at rootd's answers, recorded as taint on the task with an
// auditd ACK before any byte flows, and then tunneled as bytes: no TLS interception, no redirects. Anything else gets a
// §5.6 refusal in the CONNECT format.
//
// shortcut: no Go module cache yet (#21): every origin-form /_cache/ request is a cache miss, a bare 404 (405 for
// another method), so go falls back to CONNECT as it would.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/dial"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/resolve"
)

// Dialer is the pinned dialer (§6.3): it asks rootd for e on behalf of task and connects only to rootd's answers, as
// IP literals. A refusal is a *resolve.Refused with one of rootd's four reasons; a dial that reached none of the answers
// is a *dial.Error, whose What is EGRESS_DIAL_FAILED's what.
type Dialer interface {
	Dial(ctx context.Context, task string, e resolve.Entry) (net.Conn, error)
}

// Server is the proxy. Every field is required.
type Server struct {
	Egress string // the allowlists (resolve.EgressDir), read at every CONNECT
	Dial   Dialer
	// Taint sends one record on auditd's proxy.sock and returns nil only on its ACK (Audit).
	Taint func(rec map[string]any) error
}

// MaxConns is how many connections, so tunnels, one task's proxy.sock serves at once. §2.1's 8 for a per-task socket
// would hang npm for good: it keeps up to 15 keep-alive tunnels open per registry, so its fetches on the sockets past
// the cap wait on tunnels that never close (#285).
const MaxConns = 64

const (
	maxHead = 16 << 10
	maxBody = 1 << 20 // read off a refused request first, so the refusal is what the client reads (#168)
	// a request head must arrive within headTimeout; rootd's resolution (at most 10 s, plus the socket's slack) and
	// dial.Budget fit in connectTimeout
	headTimeout    = 30 * time.Second
	connectTimeout = 30 * time.Second
)

// Serve answers one connection on task's proxy.sock: one request, then a tunnel or a refusal.
func (s *Server) Serve(task, agent string, c net.Conn) {
	defer c.Close()
	lr := &io.LimitedReader{R: c, N: maxHead}
	br := bufio.NewReader(lr)
	c.SetReadDeadline(time.Now().Add(headTimeout))
	req, err := http.ReadRequest(br)
	if err != nil {
		return // no request: nothing to answer
	}
	if req.Method != http.MethodConnect {
		lr.N = maxBody
		io.Copy(io.Discard, req.Body)
		c.SetReadDeadline(time.Time{})
		s.notConnect(c, task, req)
		return
	}
	c.SetReadDeadline(time.Time{})
	e, ok := s.check(c, task, agent, req.RequestURI)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	sub := ops.Subject{Host: e.Host, Port: int64(e.Port)}
	up, err := s.Dial.Dial(ctx, task, e)
	if err != nil {
		var rf *resolve.Refused
		switch {
		case !errors.As(err, &rf):
			refuse(c, task, ops.EgressDialFailed, dialWhat(err), sub, "")
		case rf.Reason == resolve.NotAllowlisted: // removed from the list since step 1, or the task ended
			refuse(c, task, ops.EgressNotAllowlisted, deputy(e), sub, "")
		case rf.Reason == resolve.NonPublic:
			refuse(c, task, ops.EgressNameRejected, "non_public", sub, "")
		case rf.Reason == resolve.NoSuchName:
			refuse(c, task, ops.EgressResolveFailed, "no_such_name", sub, "")
		default: // unavailable, or a reason this proxy doesn't know
			refuse(c, task, ops.EgressResolveFailed, "unavailable", sub, "")
		}
		return
	}
	defer up.Close()
	// §6.2 step 4: the taint before any byte flows. Every proxy CONNECT taints: LLM vendors, the one class that
	// doesn't, never reach it.
	if err := s.Taint(map[string]any{"type": "TAINT", "subject": "task:" + task, "source": "proxy:" + e.String()}); err != nil {
		log.Printf("task %s CONNECT %s: taint not ACKed: %v", task, e, err)
		refuse(c, task, ops.AuditUnavailable, "", sub, "")
		return
	}
	log.Printf("task %s CONNECT %s: tunnel to %s", task, e, up.RemoteAddr())
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	lr.N = 1<<63 - 1 // the head limit is lifted: from here on these are tunnel bytes
	tunnel(c, br, up)
}

// check is §6.2 step 1, before any rootd call: the CONNECT target canonicalized, the LLM vendor list, the agent's
// allowlist. A miss is refused here and names no other entry.
func (s *Server) check(c net.Conn, task, agent, target string) (resolve.Entry, bool) {
	host, _, _ := net.SplitHostPort(target)
	sub := ops.Subject{Host: strings.ToLower(host)} // Deny drops a host that is no A-label, an IP literal among them
	e, err := resolve.ParseEntry(target)            // no IP literal, wildcard or U-label: a list holds none
	if err == nil {
		sub.Port = int64(e.Port) // a port only from a target that parsed, so a remedy never names another spelling
	}
	if slices.Contains(resolve.VendorHosts, strings.TrimSuffix(sub.Host, ".")) {
		refuse(c, task, ops.EgressWrongRoute, "llm_vendor", sub, "use :8081")
		return resolve.Entry{}, false
	}
	if err != nil {
		refuse(c, task, ops.EgressNotAllowlisted, "", sub, "")
		return resolve.Entry{}, false
	}
	l, err := resolve.LoadLists(s.Egress)
	if err != nil {
		log.Printf("task %s CONNECT %s: allowlists: %v", task, e, err)
		refuse(c, task, ops.EgressResolveFailed, "unavailable", sub, "")
		return resolve.Entry{}, false
	}
	if !l.Allowed("proxy", agent, e) {
		refuse(c, task, ops.EgressNotAllowlisted, deputy(e), sub, "")
		return resolve.Entry{}, false
	}
	return e, true
}

// deputy is EGRESS_NOT_ALLOWLISTED's what: a deputy host gets next human, since only a human adds one (§6.2).
func deputy(e resolve.Entry) string {
	if slices.Contains(resolve.DeputyHosts, e.Host) {
		return "deputy_host"
	}
	return ""
}

// notConnect answers a request that is not a CONNECT. An origin-form /_cache/ request is the Go module cache's; any
// other one is plain HTTP, which never leaves the box.
func (s *Server) notConnect(c net.Conn, task string, req *http.Request) {
	if !strings.HasPrefix(req.RequestURI, "/_cache/") {
		refuse(c, task, ops.EgressWrongRoute, "plain_http", ops.Subject{}, "use CONNECT")
		return
	}
	// a bare reply with no denial header: go falls back to the next GOPROXY entry only on a plain 404 (§6.2)
	status := "404 Not Found"
	if req.Method != http.MethodGet {
		status = "405 Method Not Allowed"
	}
	io.WriteString(c, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

// refuse writes the §5.6 CONNECT refusal: the code's status (502 for a dial refused or blocked, §6.2 step 3), the
// reason phrase, the Agentbox-Denial header and the {error, agentbox} body, then the connection closes. Only the
// requested host:port is named, and only if it passes the A-label grammar.
//
// shortcut: #21's ops.ConnectReply writes the same bytes; use it once that lands.
func refuse(c net.Conn, task string, code ops.Code, what string, sub ops.Subject, expect string) {
	d := ops.Deny(code, what, ops.Slots{By: "proxy", Subject: sub, Expect: expect})
	status := ops.HTTPStatus(code)
	if code == ops.EgressDialFailed && d.What != "timeout" {
		status = http.StatusBadGateway
	}
	body := ops.ConnectBody(d)
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n%s: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, ops.ConnectReason(d), ops.DenialHeaderName, ops.DenialHeader(d), len(body), body)
	entry := "-"
	if d.Subject != nil && d.Subject.Port != 0 {
		entry = d.Subject.Host + ":" + strconv.FormatInt(d.Subject.Port, 10)
	} else if d.Subject != nil {
		entry = d.Subject.Host
	}
	log.Printf("DENY by=proxy task=%s code=%s what=%s entry=%s id=%s", task, d.Code, d.What, entry, d.ID)
}

// tunnel relays both ways until both are done. An EOF half-closes the other side, so a client that finished sending
// still gets its answer; an error on either side (revoke closing the task's end, a reset) closes both at once.
func tunnel(c net.Conn, br io.Reader, up net.Conn) {
	var wg sync.WaitGroup
	pipe := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			c.Close()
			up.Close()
			return
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}
	wg.Add(2)
	go pipe(up, br)
	pipe(c, up)
	wg.Wait()
}

// Pinned is the Dialer on rootd's resolve socket at this path: internal/dial's pinned dialing, naming the task, so rootd
// checks the entry against that task's agent and refuses a task that ended.
type Pinned string

// Dial is Dialer.Dial.
func (p Pinned) Dial(ctx context.Context, task string, e resolve.Entry) (net.Conn, error) {
	return dial.Dialer{Sock: string(p), Task: task}.DialContext(ctx, "tcp", e.String())
}

// dialWhat is a failed dial's EGRESS_DIAL_FAILED what: the *dial.Error's (refused for a reset, timeout when the budget
// ran out), and blocked for any other failure (§6.3).
func dialWhat(err error) string {
	var de *dial.Error
	if errors.As(err, &de) {
		return de.What
	}
	return dial.Blocked
}

// Audit is Server.Taint for auditd's producer socket at path: one connection per record, nil only on its ACK.
//
// shortcut: #21's audit.Send is the same call; use it once that lands.
func Audit(path string) func(map[string]any) error {
	return func(rec map[string]any) error {
		c, err := net.DialTimeout("unix", path, 2*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		b, _ := json.Marshal(rec)
		if _, err := c.Write(append(b, '\n')); err != nil {
			return err
		}
		line, err := bufio.NewReader(c).ReadBytes('\n')
		var rep audit.Reply
		if err != nil || json.Unmarshal(line, &rep) != nil {
			return fmt.Errorf("no reply: %v", err)
		}
		if !rep.OK {
			return fmt.Errorf("NACK %s", rep.Code)
		}
		return nil
	}
}

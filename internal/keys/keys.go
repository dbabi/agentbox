// Package keys is agentbox-keys (ARCHITECTURE.md §6.3, §4.3): the LLM broker. Each task reaches it on its own
// keys.sock (internal/broker) with a placeholder key, its canary (#105). keys checks each request against a closed
// schema, reserves its worst-case price against the agent's day share and the task's trace, audits it, swaps in the
// real key and sends it to the vendor over pinned dialing. On the way back it strips what only the box may say, turns
// an auth failure into its own denial, and refuses any reply that carries the key back (#18).
package keys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentbox/internal/broker"
	"agentbox/internal/canary"
	"agentbox/internal/ids"
	"agentbox/internal/ops"
)

// Caps on what passes through (#115): a request body as sent and decoded, and a reply keys holds whole to check it.
const (
	MaxBody  = 32 << 20 // Anthropic's own request limit
	MaxReply = 64 << 20
)

// Server is keys' request path, shared by every task socket.
type Server struct {
	Ledger    *Ledger
	Transport http.RoundTripper   // pinned dialing to the vendors (§6.3); tests use their own
	Upstream  map[string]string   // vendor -> base URL: https://api.anthropic.com, https://api.openai.com
	Key       func(string) string // vendor -> the key to inject, "" if none is set (secret.set, #108)
	// Audit sends one record on keys' auditd producer socket and returns nil only on its ACK (audit.Send)
	Audit func(map[string]any) error
	// Limits are the caps for one request of agent: its day share, the trace budget and the box backstop
	Limits func(agent string) (Limits, error)
	// ServerTools are the server-tool families the policy allows (web_search, ...); each taints the task. nil: none.
	ServerTools func() []string
	Local       *Local // the local LLM (agentbox-llm@task); nil: /local is refused like any unknown endpoint
	Now         func() time.Time
	// DenyBetas are refused even though they are in the allowlist: AGENTBOX_TEST_KEYS_DENY_BETA, a test VM's way to
	// see Claude Code retry without a value it really sends (#18)
	DenyBetas []string
	// CanaryHit tells rootd that a task's model request carried its canary (#105, canary.hit on resolve-keys.sock):
	// rootd taints the task, audits and alerts. nil: none.
	CanaryHit func(task string) error

	bodies chan struct{} // MaxBodies: the request bodies being read and checked at once, box-wide
	once   sync.Once
	mu     sync.Mutex
	agents map[string]chan struct{} // AgentBodies of the slots per agent
	hits   sync.Map                 // task ids whose canary hit rootd recorded: a canary kept in a conversation alerts once
}

// MaxBodies is how many request bodies keys reads and checks at once, across every task (#115, #315). One slot holds
// at most 64 MiB of body (MaxBody as sent and decoded) and a check's peak: about 110 MiB for a MaxBody of MaxValues
// strings, the costliest shape measured. So the slots stay near 1 GiB, half the unit's MemoryMax=, and its
// GOMEMLIMIT= has the runtime collect garbage before that. AgentBodies of them at most go to one agent, so one agent's
// slow senders never starve another's requests; broker.ReadBody cuts a body that trickles in.
const (
	MaxBodies   = 6
	AgentBodies = 2
)

// slot takes one of the agent's AgentBodies, then one of the box's MaxBodies; release gives both back. ok is false
// when the client went away while it waited.
func (s *Server) slot(ctx context.Context, agent string) (release func(), ok bool) {
	s.once.Do(func() { s.bodies = make(chan struct{}, MaxBodies) })
	s.mu.Lock()
	a := s.agents[agent]
	if a == nil {
		if s.agents == nil {
			s.agents = map[string]chan struct{}{}
		}
		a = make(chan struct{}, AgentBodies)
		s.agents[agent] = a // one per agent on the box, kept: agents are few
	}
	s.mu.Unlock()
	select {
	case a <- struct{}{}:
	case <-ctx.Done():
		return nil, false
	}
	select {
	case s.bodies <- struct{}{}:
	case <-ctx.Done():
		<-a
		return nil, false
	}
	return func() { <-s.bodies; <-a }, true
}

// Format is keys' denial surface for internal/broker (§5.6 Surfaces): the vendor's error envelope with the
// agentbox member, and keys' headers.
func (s *Server) Format(h http.Header, d ops.Denial, status int) []byte {
	ops.KeysHeaders(h, d, s.now())
	return ops.KeysError(d, errorType(status), "")
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// errorType is the vendor's error type for status: what an SDK reads to pick its exception.
func errorType(status int) string {
	switch status {
	case 400:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403:
		return "permission_error"
	case 404:
		return "not_found_error"
	case 413:
		return "request_too_large"
	case 429:
		return "rate_limit_error"
	case 503, 529:
		return "overloaded_error"
	}
	return "api_error"
}

// refuse writes d. detail is grammar-checked request bytes or a fixed string only (§5.6 leak rule 1): the vendor's
// wording for a field, or capability_rejected: beta_header:<value>, which Claude Code's retry matches (#18).
func (s *Server) refuse(w http.ResponseWriter, t *broker.Task, d ops.Denial, status int, detail string) {
	ptr := ""
	if d.Subject != nil && d.Subject.Pointer != "" {
		ptr = " ptr=" + d.Subject.Pointer // the caller's own field, grammar-checked: never a value
	}
	log.Printf("DENY by=keys task=%s code=%s what=%s id=%s%s", t.ID, d.Code, d.What, d.ID, ptr)
	h := w.Header()
	ops.KeysHeaders(h, d, s.now())
	body := ops.KeysError(d, errorType(status), detail)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	w.Write(body)
}

// reject is a KEYS_REQUEST_REJECTED: 400, the vendor's status, for a beta value and a field outside the schema, so
// Claude Code retries without them (#18); 403 for every other what, as §6.3 has it.
func (s *Server) reject(w http.ResponseWriter, t *broker.Task, r *rej) {
	var lim *int64
	if r.limit > 0 {
		lim = &r.limit
	}
	sub := ops.Subject{Pointer: r.ptr}
	if r.what == "model" {
		sub.Model = r.name
	}
	d := ops.Deny(ops.KeysRequestRejected, r.what, ops.Slots{By: "keys", Subject: sub, Limit: lim})
	status := http.StatusForbidden
	if r.what == "beta_header" || (r.what == "field" && r.wording != "") {
		status = http.StatusBadRequest
	}
	s.refuse(w, t, d, status, r.wording)
}

func (s *Server) upstreamFail(w http.ResponseWriter, t *broker.Task, what string) {
	d := ops.Deny(ops.KeysUpstream, what, ops.Slots{By: "keys"})
	s.refuse(w, t, d, ops.Status(d), "")
}

func (s *Server) auditDown(w http.ResponseWriter, t *broker.Task) {
	d := ops.Deny(ops.AuditUnavailable, "", ops.Slots{By: "keys"})
	s.refuse(w, t, d, ops.Status(d), "")
}

// Handler serves t's socket. internal/broker has already checked the peer, the admission caps on the head and that t
// is still registered.
func (s *Server) Handler(t *broker.Task) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serve(w, r, t) })
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, t *broker.Task) {
	if r.Method == http.MethodHead && r.URL.Path == Hello && r.URL.RawQuery == "" {
		w.Header().Set("Content-Length", "0")
		return
	}
	ep, ok := endpoints[r.URL.Path]
	if ok && ep.vendor == "local" && s.Local == nil {
		ok = false
	}
	if !ok || r.Method != ep.method || !(r.URL.RawQuery == "" || ep.betaQuery && r.URL.RawQuery == "beta=true") {
		d := ops.Deny(ops.KeysRequestRejected, "endpoint", ops.Slots{By: "keys"})
		s.refuse(w, t, d, http.StatusForbidden, "")
		return
	}
	release, ok := s.slot(r.Context(), t.Agent)
	if !ok {
		return
	}
	body, err := broker.ReadBody(w, r, MaxBody)
	var c checked
	var rj *rej
	var local []byte
	var dropped []string
	switch {
	case err != nil:
	case ep.vendor == "local":
		local, dropped, rj = s.Local.rebuild(body) // it builds the same tree as validate, so it holds the slot too
	default:
		c, rj = validate(ep, body, s.allowed)
	}
	release()
	var capped *broker.Capped
	switch {
	case errors.As(err, &capped):
		d, st := broker.Cap("keys", capped.What, capped.Limit)
		s.refuse(w, t, d, st, "")
		return
	case errors.Is(err, broker.ErrEncoding):
		s.reject(w, t, &rej{what: "field", ptr: "/", wording: "Content-Encoding: only identity and gzip are accepted"})
		return
	case err != nil:
		return // the client went away
	}
	if ep.vendor == "local" {
		if rj != nil {
			s.reject(w, t, rj)
			return
		}
		s.Local.serve(w, r, t, local, dropped, s)
		return
	}
	allow, hdr := betas, "anthropic-beta"
	if ep.vendor == "openai" {
		allow, hdr = openaiBetas, "openai-beta"
	}
	allow = slices.DeleteFunc(slices.Clone(allow), func(b string) bool { return slices.Contains(s.DenyBetas, b) })
	if rj := checkBetas(r.Header.Values(hdr), allow); rj != nil {
		s.reject(w, t, rj)
		return
	}
	if rj != nil {
		s.reject(w, t, rj)
		return
	}
	key := s.Key(ep.vendor)
	if key == "" {
		s.upstreamFail(w, t, "auth") // no key for this vendor yet: a human runs agentbox secret set
		return
	}
	id := ids.New(ids.Denial)[3:] // a ULID for the ledger row, never shown to the task
	reserved := int64(0)
	if !ep.free {
		reserved = c.price.reserve(c.maxOut, int64(len(c.body)))
		if !s.reserve(w, t, id, c.model, reserved) {
			return
		}
	}
	settled := false
	settle := func(n int64) {
		if ep.free || settled {
			return
		}
		settled = true
		if err := s.Ledger.Settle(id, n); err != nil {
			log.Printf("task %s: ledger: %v", t.ID, err)
		}
	}
	defer settle(reserved) // any path that didn't settle from usage is billed in full
	// §6.3: vendor web tools taint the task, and INTENT is ACKed before forwarding
	for _, f := range c.server {
		if err := s.Audit(map[string]any{"type": "TAINT", "subject": "task:" + t.ID, "source": "keys:" + f}); err != nil {
			log.Printf("task %s: TAINT keys:%s not ACKed: %v", t.ID, f, err)
			settle(0)
			s.auditDown(w, t)
			return
		}
	}
	if carriesCanary(r, t, c.body) {
		s.canaryHit(t)
	}
	sum := sha256.Sum256(c.body)
	if err := s.Audit(map[string]any{"type": "LLM", "task": t.ID, "agent": t.Agent, "trace": t.Trace, "vendor": ep.vendor,
		"endpoint": ep.path, "model": c.model, "reservedNanos": reserved, "server": c.server,
		"body": map[string]any{"sha256": hex.EncodeToString(sum[:]), "len": len(c.body)}}); err != nil {
		log.Printf("task %s: LLM record not ACKed: %v", t.ID, err)
		settle(0)
		s.auditDown(w, t)
		return
	}
	resp, err := s.send(r, ep, c, key)
	if err != nil {
		what := "unreachable"
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
			what = "timeout"
		}
		log.Printf("task %s: %s %s: %v", t.ID, ep.vendor, ep.path, err)
		if r.Context().Err() == nil {
			s.upstreamFail(w, t, what)
		}
		return
	}
	defer resp.Body.Close()
	settle(s.relay(w, t, ep, c, key, resp, reserved))
}

// carriesCanary is #105's check of what leaves for the vendor: the forwarded headers and the checked body. Never the
// client's auth headers: the canary is the task's key slot, so they always hold it, and they never leave.
func carriesCanary(r *http.Request, t *broker.Task, body []byte) bool {
	sc := canary.New(t.Canary)
	if sc == nil {
		return false
	}
	for _, k := range forwardHeaders {
		for _, v := range r.Header.Values(k) {
			sc.Write([]byte(v + "\n"))
		}
	}
	sc.Write(body)
	return sc.Hit()
}

// canaryHit has rootd record t's canary hit, once per task. keys only alerts (#105): the request still goes to the
// vendor, which holds no credential of the box's in it.
func (s *Server) canaryHit(t *broker.Task) {
	if _, seen := s.hits.LoadOrStore(t.ID, true); seen {
		return
	}
	log.Printf("ALERT keys: task %s: a model request carried the task's canary", t.ID)
	if s.CanaryHit == nil {
		return
	}
	if err := s.CanaryHit(t.ID); err != nil {
		log.Printf("task %s: rootd did not record the canary hit: %v", t.ID, err)
		s.hits.Delete(t.ID) // the next request that carries it tries again
	}
}

func (s *Server) allowed(f string) bool {
	return s.ServerTools != nil && slices.Contains(s.ServerTools(), f)
}

// reserve books the request against its caps (§6.3), or refuses it with KEYS_BUDGET: agent (the agent's own day
// share, which resets at 00:00 UTC) or trace. A box backstop hit has no what, and alerts.
func (s *Server) reserve(w http.ResponseWriter, t *broker.Task, id, model string, nanos int64) bool {
	now := s.now()
	lim, err := s.Limits(t.Agent)
	if err == nil {
		err = s.Ledger.Reserve(id, t.Agent, t.Trace, t.ID, model, nanos, lim, now)
	}
	var over *Over
	switch {
	case errors.As(err, &over):
		what, sl := over.What, ops.Slots{By: "keys"}
		if what == "agent" {
			r := NextDay(now).UnixMilli()
			sl.ResetsAt = &r
		}
		if what == "box" {
			what = ""
			log.Printf("ALERT keys: the box day cap stopped task %s of agent %s, below its own share", t.ID, t.Agent)
			go s.Audit(map[string]any{"type": "ALERT", "source": "keys", "reason": "box_backstop", "task": t.ID, "agent": t.Agent})
		}
		d := ops.Deny(ops.KeysBudget, what, sl)
		s.refuse(w, t, d, ops.Status(d), "")
		return false
	case err != nil:
		log.Printf("task %s: ledger: %v", t.ID, err)
		s.auditDown(w, t) // the spend can't be recorded, so nothing is sent
		return false
	}
	return true
}

// forwardHeaders are the client headers keys passes on, besides its own auth: the API version, the checked betas, and
// the content negotiation. Client auth never goes: the placeholder key, an Authorization header, a cookie.
var (
	forwardHeaders = []string{"Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta", "User-Agent",
		"X-Openai-Internal-Codex-Responses-Lite"} // Codex's request format; keys passes only "true"
	reVersion = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// send is the upstream request: the checked body, the forwarded headers and the injected key.
func (s *Server) send(r *http.Request, ep endpoint, c checked, key string) (*http.Response, error) {
	u := s.Upstream[ep.vendor] + ep.path
	if r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery // only beta=true reaches here
	}
	var body io.Reader
	if ep.method == http.MethodPost {
		body = strings.NewReader(string(c.body))
	}
	req, err := http.NewRequestWithContext(r.Context(), ep.method, u, body)
	if err != nil {
		return nil, err
	}
	for _, k := range forwardHeaders {
		for _, v := range r.Header.Values(k) {
			if k == "Anthropic-Version" && !reVersion.MatchString(v) || k == "X-Openai-Internal-Codex-Responses-Lite" && v != "true" {
				continue
			}
			req.Header.Add(k, v)
		}
	}
	if ep.vendor == "anthropic" {
		req.Header.Set("X-Api-Key", key)
	} else {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Accept-Encoding", "identity") // the reply is scanned for the key as sent: no compressed bytes
	req.ContentLength = int64(len(c.body))
	if ep.method != http.MethodPost {
		req.ContentLength = 0
	}
	return s.Transport.RoundTrip(req)
}

// hopHeaders never pass from the vendor to the task.
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding",
	"Upgrade", "Content-Length", "Set-Cookie"}

// relay sends the vendor's reply on to the task (§6.3 Upstream responses) and returns what the request spent. A 401
// or 403 is KEYS_UPSTREAM{auth} with no upstream byte; Agentbox-* headers and a non-2xx body's agentbox member go; a
// reply that carries the key in any form never reaches the task: KEYS_UPSTREAM{reflect} if it is found before the
// head goes out, else the stream is cut and an ALERT is audited (#18).
func (s *Server) relay(w http.ResponseWriter, t *broker.Task, ep endpoint, c checked, key string, resp *http.Response, reserved int64) int64 {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		log.Printf("task %s: %s %s: upstream %d: the key was refused", t.ID, ep.vendor, ep.path, resp.StatusCode)
		s.upstreamFail(w, t, "auth")
		return 0
	}
	m := newMatcher(key)
	reflected := func(where string) int64 {
		log.Printf("ALERT keys: task %s: the %s reply held the injected key (%s); none of it reached the task", t.ID, ep.vendor, where)
		go s.Audit(map[string]any{"type": "ALERT", "source": "keys", "reason": "reflect", "task": t.ID, "agent": t.Agent, "where": where})
		return reserved
	}
	ops.StripUpstream(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			if m.contains(v) {
				s.upstreamFail(w, t, "reflect")
				return reflected("header " + strings.ToLower(k))
			}
		}
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		log.Printf("task %s: %s %s: upstream sent Content-Encoding %q", t.ID, ep.vendor, ep.path, enc)
		s.upstreamFail(w, t, "unreachable") // keys asked for identity, and can't scan other bytes
		return reserved
	}
	h := w.Header()
	for k, vs := range resp.Header {
		if !slices.Contains(hopHeaders, http.CanonicalHeaderKey(k)) {
			h[k] = vs
		}
	}
	sse := strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
	if !sse || resp.StatusCode/100 != 2 {
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxReply+1))
		if err != nil || len(b) > MaxReply {
			for k := range h {
				delete(h, k)
			}
			s.upstreamFail(w, t, "unreachable")
			return reserved
		}
		if out, found := m.feed(b); found || m.contains(string(out)) {
			for k := range h {
				delete(h, k)
			}
			s.upstreamFail(w, t, "reflect")
			return reflected("body")
		}
		if resp.StatusCode/100 != 2 {
			b = ops.StripMember(b)
		}
		h.Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(resp.StatusCode)
		w.Write(b)
		if u, ok := fromJSON(ep.vendor, b); ok && resp.StatusCode/100 == 2 {
			return c.price.cost(u)
		}
		if resp.StatusCode/100 != 2 {
			return 0 // the vendor bills no failed request
		}
		return reserved
	}
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	rc.Flush()
	us := &sseUsage{vendor: ep.vendor}
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			us.feed(buf[:n])
			out, found := m.feed(buf[:n])
			if found {
				reflected("stream")
				panic(http.ErrAbortHandler) // the task sees a cut stream, never the bytes that held the key
			}
			if len(out) > 0 {
				if _, werr := w.Write(out); werr != nil {
					break
				}
				rc.Flush()
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("task %s: %s %s: stream: %v", t.ID, ep.vendor, ep.path, err)
			}
			break
		}
	}
	w.Write(m.rest())
	rc.Flush()
	if us.final {
		return c.price.cost(us.u)
	}
	// cut before the terminal usage event, by the client or the vendor: the vendor may bill up to max_tokens, which
	// only the reservation covers, and message_start's usage counts 1 output token (#315)
	if us.u.known {
		return max(reserved, c.price.cost(us.u))
	}
	return reserved
}

// CredName is each vendor's credential (#108): the name secret.set takes, which agentbox-keys.service loads with
// LoadCredentialEncrypted= into its own credentials dir.
var CredName = map[string]string{"anthropic": "anthropic-api-key", "openai": "openai-api-key"}

// LocalMaxTokens is the local LLM's max_tokens cap, and what a request that names none gets.
const LocalMaxTokens = 8192

// Cents is a budget in cents as nanodollars, the ledger's unit.
func Cents(c int64) int64 { return c * nanosPerCent }

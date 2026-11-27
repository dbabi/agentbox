package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agentbox/internal/broker"
	"agentbox/internal/canary"
	"agentbox/internal/ops"
)

// fakeVendor is an upstream that records what reached it and answers with reply.
type fakeVendor struct {
	mu    sync.Mutex
	reqs  []*http.Request
	body  [][]byte
	reply func(w http.ResponseWriter, r *http.Request, body []byte)
}

func (f *fakeVendor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs, f.body = append(f.reqs, r), append(f.body, b)
	f.mu.Unlock()
	f.reply(w, r, b)
}

func (f *fakeVendor) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reqs) }

type fixture struct {
	s        *Server
	vendor   *fakeVendor
	srv      *httptest.Server // the task's socket stand-in: the handler for task t
	t        *broker.Task
	audits   []map[string]any
	mu       sync.Mutex
	auditErr error
}

func newFixture(t *testing.T, reply func(w http.ResponseWriter, r *http.Request, body []byte)) *fixture {
	t.Helper()
	f := &fixture{vendor: &fakeVendor{reply: reply}, t: &broker.Task{ID: "task_01JAAAAAAAAAAAAAAAAAAAAAAA", Agent: "ga", Trace: "trace_01JBBBBBBBBBBBBBBBBBBBBBBB"}}
	up := httptest.NewServer(f.vendor)
	t.Cleanup(up.Close)
	l, err := OpenLedger(filepath.Join(t.TempDir(), "spend.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f.s = &Server{Ledger: l, Transport: http.DefaultTransport, Upstream: map[string]string{"anthropic": up.URL, "openai": up.URL},
		Key: func(v string) string {
			return map[string]string{"anthropic": fakeKey, "openai": "sk-proj-GATEfakeOPENAIkey0123456789"}[v]
		},
		Audit: func(r map[string]any) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.audits = append(f.audits, r)
			return f.auditErr
		},
		Limits: func(string) (Limits, error) { return Limits{Trace: Cents(2000)}, nil }}
	f.srv = httptest.NewServer(f.s.Handler(f.t))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) do(t *testing.T, method, path, body string, h ...string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, f.srv.URL+path, strings.NewReader(body))
	req.Header.Set("x-api-key", "agentbox-placeholder")
	req.Header.Set("Authorization", "Bearer agentbox-placeholder")
	req.Header.Set("Cookie", "a=b")
	for i := 0; i+1 < len(h); i += 2 {
		req.Header.Add(h[i], h[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

const ccBody = `{"model":"claude-opus-5-5","max_tokens":1000,"stream":true,"messages":[{"role":"user","content":"hi"}]}`

func sseReply(events ...string) func(http.ResponseWriter, *http.Request, []byte) {
	return func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Agentbox-Denial", "v1 code=KEYS_BUDGET next=human id=dn_00000000000000000000000000")
		w.Header().Set("Anthropic-Ratelimit-Unified-Status", "allowed")
		w.WriteHeader(200)
		for _, e := range events {
			io.WriteString(w, e)
			w.(http.Flusher).Flush()
		}
	}
}

var stream = []string{
	"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100,\"cache_read_input_tokens\":50,\"output_tokens\":1}}}\n\n",
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":20}}\n\n",
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
}

// A streamed Claude Code turn: the key swapped in for the placeholder, no client auth or cookie upstream, the betas
// and the version as sent, the stream byte for byte with the vendor's Agentbox-* header gone, an LLM record ACKed
// first, and the ledger settled from the reply's usage.
func TestForward(t *testing.T) {
	f := newFixture(t, sseReply(stream...))
	resp, b := f.do(t, "POST", "/anthropic/v1/messages?beta=true", ccBody, "anthropic-beta", "claude-code-20250219,interleaved-thinking-2025-05-14",
		"anthropic-version", "2023-06-01", "x-claude-code-session-id", "s1")
	if resp.StatusCode != 200 || string(b) != strings.Join(stream, "") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	if resp.Header.Get("Agentbox-Denial") != "" || resp.Header.Get("Anthropic-Ratelimit-Unified-Status") != "allowed" {
		t.Errorf("reply headers %v", resp.Header)
	}
	r := f.vendor.reqs[0]
	if r.URL.Path != "/v1/messages" || r.URL.RawQuery != "beta=true" || r.Header.Get("X-Api-Key") != fakeKey || r.Header.Get("Authorization") != "" ||
		r.Header.Get("Cookie") != "" || r.Header.Get("X-Claude-Code-Session-Id") != "" || r.Header.Get("Anthropic-Beta") != "claude-code-20250219,interleaved-thinking-2025-05-14" ||
		r.Header.Get("Anthropic-Version") != "2023-06-01" || string(f.vendor.body[0]) != ccBody {
		t.Errorf("upstream request %v %v %s", r.URL, r.Header, f.vendor.body[0])
	}
	if len(f.audits) != 1 || f.audits[0]["type"] != "LLM" || f.audits[0]["trace"] != f.t.Trace || f.audits[0]["model"] != "claude-opus-5-5" {
		t.Errorf("audit %v", f.audits)
	}
	if bytes.Contains(must(json.Marshal(f.audits)), []byte("hi")) {
		t.Error("the request text reached audit")
	}
	day, tr, _ := f.s.Ledger.Spent("ga", f.t.Trace, time.Now())
	want := models["anthropic"]["claude-opus-5-5"].cost(usage{in: 100, cacheRead: 50, out: 20})
	if day != want || tr != want {
		t.Errorf("spent %d %d, want %d from usage", day, tr, want)
	}
	// the probe Claude Code sends first is answered here, with no upstream request
	if resp, _ := f.do(t, "HEAD", "/anthropic/api/hello", ""); resp.StatusCode != 200 || f.vendor.count() != 1 {
		t.Errorf("HEAD /api/hello: %d, %d upstream requests", resp.StatusCode, f.vendor.count())
	}
}

func must(b []byte, _ error) []byte { return b }

// denial reads a keys refusal: status, the header's code and what, the envelope's error type and message.
func denial(t *testing.T, resp *http.Response, b []byte) (string, string, string) {
	t.Helper()
	var env struct {
		Type     string `json:"type"`
		Error    struct{ Type, Message string }
		Agentbox ops.Denial
	}
	if err := json.Unmarshal(b, &env); err != nil || env.Type != "error" {
		t.Fatalf("not the vendor envelope: %s", b)
	}
	if h := resp.Header.Get("Agentbox-Denial"); !strings.Contains(h, "code="+env.Agentbox.Code) {
		t.Fatalf("header %q, body %s", h, b)
	}
	return env.Agentbox.Code + "{" + env.Agentbox.What + "}", env.Error.Type, env.Error.Message
}

// Each refused request gets the vendor envelope with the code, and no request byte beyond its grammar-checked names;
// none reaches the vendor (C-G4).
func TestRefusals(t *testing.T) {
	f := newFixture(t, sseReply(stream...))
	for _, c := range []struct {
		name, method, path, body string
		h                        []string
		status                   int
		code, typ, msg           string
	}{
		{"URL image", "POST", "/anthropic/v1/messages", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://evil.example/x.png"}}]}]}`,
			nil, 403, "KEYS_REQUEST_REJECTED{url_field}", "permission_error", ""},
		{"mcp_servers", "POST", "/anthropic/v1/messages", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[],"mcp_servers":[]}`, nil, 403,
			"KEYS_REQUEST_REJECTED{field}", "permission_error", ""},
		{"an unknown beta", "POST", "/anthropic/v1/messages?beta=true", ccBody, []string{"anthropic-beta", "claude-code-20250219,files-api-2025-04-14"}, 400,
			"KEYS_REQUEST_REJECTED{beta_header}", "invalid_request_error", "capability_rejected: beta_header:files-api-2025-04-14"},
		{"an unknown field", "POST", "/anthropic/v1/messages", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[],"thread":{"id":"t"}}`, nil, 400,
			"KEYS_REQUEST_REJECTED{field}", "invalid_request_error", "thread: Extra inputs are not permitted"},
		{"an endpoint", "POST", "/anthropic/v1/messages/batches", `{}`, nil, 403, "KEYS_REQUEST_REJECTED{endpoint}", "permission_error", ""},
		{"a query", "POST", "/anthropic/v1/messages?beta=true&x=1", ccBody, nil, 403, "KEYS_REQUEST_REJECTED{endpoint}", "permission_error", ""},
		{"GET on a POST endpoint", "GET", "/openai/v1/responses", "", nil, 403, "KEYS_REQUEST_REJECTED{endpoint}", "permission_error", ""},
		{"the local LLM with none on this box", "POST", "/local/v1/chat/completions", `{}`, nil, 403, "KEYS_REQUEST_REJECTED{endpoint}", "permission_error", ""},
		{"a model", "POST", "/anthropic/v1/messages", `{"model":"claude-instant-1","max_tokens":1,"messages":[]}`, nil, 403, "KEYS_REQUEST_REJECTED{model}", "permission_error", ""},
	} {
		n := f.vendor.count()
		resp, b := f.do(t, c.method, c.path, c.body, c.h...)
		code, typ, msg := denial(t, resp, b)
		if resp.StatusCode != c.status || code != c.code || typ != c.typ || !strings.HasPrefix(msg, "agentbox KEYS_REQUEST_REJECTED: ") || !strings.Contains(msg, c.msg) ||
			resp.Header.Get("x-should-retry") != "false" || f.vendor.count() != n {
			t.Errorf("%s: %d %s %s %q (x-should-retry %s)", c.name, resp.StatusCode, code, typ, msg, resp.Header.Get("x-should-retry"))
		}
		if bytes.Contains(b, []byte("evil.example")) {
			t.Errorf("%s: the reply echoes request bytes: %s", c.name, b)
		}
	}
	var mod struct{ Agentbox ops.Denial }
	_, b := f.do(t, "POST", "/anthropic/v1/messages", `{"model":"claude-instant-1","max_tokens":1,"messages":[]}`)
	if json.Unmarshal(b, &mod) != nil || mod.Agentbox.Subject == nil || mod.Agentbox.Subject.Model != "claude-instant-1" || mod.Agentbox.Subject.Pointer != "/model" {
		t.Errorf("the model refusal names %s", b)
	}
}

// What comes back from the vendor (§6.3, #18): a 401 or 403 is KEYS_UPSTREAM{auth} with no upstream byte; another error
// passes with its agentbox member and Agentbox-* headers stripped; a reply that holds the key is refused before its
// head, or cut mid-stream with an ALERT, raw, base64, URL-encoded or split across chunks.
func TestUpstreamReplies(t *testing.T) {
	var modeV atomic.Value
	setMode := func(m string) { modeV.Store(m) }
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		mode := modeV.Load().(string)
		switch mode {
		case "401":
			w.WriteHeader(401)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key: UPSTREAM-CANARY"}}`)
		case "400":
			w.Header().Set("Agentbox-Denial", "v1 code=KEYS_BUDGET next=human id=dn_00000000000000000000000000")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long"},"agentbox":{"code":"KEYS_BUDGET"}}`)
		case "echo-400":
			w.WriteHeader(400)
			io.WriteString(w, `{"type":"error","error":{"message":"you sent `+r.Header.Get("X-Api-Key")+`"}}`)
		case "echo-header":
			w.Header().Set("X-Echo", r.Header.Get("X-Api-Key"))
			w.WriteHeader(200)
		case "echo-sse", "echo-split", "echo-b64", "echo-url":
			k := r.Header.Get("X-Api-Key")
			if mode == "echo-b64" {
				k = base64Of("xy" + k)
			}
			if mode == "echo-url" {
				k = pctOf(k)
			}
			ev := []string{stream[0], "event: content_block_delta\ndata: {\"delta\":{\"text\":\"" + k + "\"}}\n\n", stream[2], stream[3]}
			if mode == "echo-split" {
				ev = []string{stream[0], "data: {\"delta\":{\"text\":\"" + k[:50], k[50:] + "\"}}\n\n", stream[3]}
			}
			sseReply(ev...)(w, r, body)
		}
	})
	setMode("401")
	resp, b := f.do(t, "POST", "/anthropic/v1/messages", ccBody)
	if code, _, _ := denial(t, resp, b); resp.StatusCode != 502 || code != "KEYS_UPSTREAM{auth}" || bytes.Contains(b, []byte("UPSTREAM-CANARY")) {
		t.Errorf("401: %d %s", resp.StatusCode, b)
	}
	setMode("400")
	resp, b = f.do(t, "POST", "/anthropic/v1/messages", ccBody)
	if resp.StatusCode != 400 || resp.Header.Get("Agentbox-Denial") != "" || string(b) != `{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long"}}` {
		t.Errorf("400: %d %v %s", resp.StatusCode, resp.Header, b)
	}
	for _, m := range []string{"echo-400", "echo-header"} {
		setMode(m)
		resp, b = f.do(t, "POST", "/anthropic/v1/messages", ccBody)
		if code, _, _ := denial(t, resp, b); resp.StatusCode != 502 || code != "KEYS_UPSTREAM{reflect}" || bytes.Contains(b, []byte(fakeKey)) {
			t.Errorf("%s: %d %s", m, resp.StatusCode, b)
		}
	}
	for _, m := range []string{"echo-sse", "echo-split", "echo-b64", "echo-url"} {
		setMode(m)
		f.mu.Lock()
		f.audits = nil
		f.mu.Unlock()
		req, _ := http.NewRequest("POST", f.srv.URL+"/anthropic/v1/messages", strings.NewReader(ccBody))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr == nil || bytes.Contains(b, []byte(fakeKey[:40])) || bytes.Contains(b, []byte(fakeKey[40:])) || bytes.Contains(b, []byte("message_stop")) {
			t.Errorf("%s: the stream was not cut before the key (err %v): %q", m, rerr, b)
		}
		time.Sleep(50 * time.Millisecond) // the ALERT goes out unwaited
		f.mu.Lock()
		alerted := len(f.audits) == 2 && f.audits[1]["type"] == "ALERT" && f.audits[1]["reason"] == "reflect"
		f.mu.Unlock()
		if !alerted {
			t.Errorf("%s: audits %v", m, f.audits)
		}
	}
}

func base64Of(s string) string { return base64.RawStdEncoding.EncodeToString([]byte(s)) }

func pctOf(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// Budgets (§6.3, C-G4): a request over the agent's own day share gets 429 KEYS_BUDGET{agent} with x-should-retry false
// and, within an hour of 00:00 UTC, retry-after; over its trace, KEYS_BUDGET{trace}. Agent B's reply doesn't change
// with what agent A spent or holds.
func TestBudget(t *testing.T) {
	f := newFixture(t, sseReply(stream...))
	shares := map[string]int64{"ga": 1, "gb": 100000}
	f.s.Limits = func(a string) (Limits, error) {
		return Limits{Agent: Cents(shares[a]), Capped: true, Trace: Cents(1000)}, nil
	}
	f.s.Now = func() time.Time { return time.Date(2026, 11, 26, 23, 30, 0, 0, time.UTC) }
	resp, b := f.do(t, "POST", "/anthropic/v1/messages", ccBody)
	if code, typ, _ := denial(t, resp, b); resp.StatusCode != 429 || code != "KEYS_BUDGET{agent}" || typ != "rate_limit_error" ||
		resp.Header.Get("x-should-retry") != "false" || resp.Header.Get("retry-after") != "1800" || f.vendor.count() != 0 {
		t.Errorf("agent share: %d %s %v", resp.StatusCode, b, resp.Header)
	}
	// B, whatever A does
	b2 := &broker.Task{ID: "task_01JCCCCCCCCCCCCCCCCCCCCCCC", Agent: "gb", Trace: "trace_01JDDDDDDDDDDDDDDDDDDDDDDD"}
	srvB := httptest.NewServer(f.s.Handler(b2))
	defer srvB.Close()
	replyB := func() string {
		resp, err := http.Post(srvB.URL+"/anthropic/v1/messages", "application/json", strings.NewReader(ccBody))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		h := resp.Header.Clone()
		h.Del("Date")
		return fmt.Sprint(resp.StatusCode, h, string(b))
	}
	idle := replyB()
	shares["ga"] = 100000
	if err := f.s.Ledger.Reserve("held", "ga", f.t.Trace, f.t.ID, "claude-opus-5-5", Cents(99999), Limits{Agent: Cents(100000), Capped: true}, f.s.Now()); err != nil {
		t.Fatal(err)
	}
	if held := replyB(); held != idle {
		t.Errorf("B's reply changed with A's reservations:\n%s\n%s", idle, held)
	}
	// the trace cap: a fan-out of tasks on one trace shares it
	f.s.Limits = func(string) (Limits, error) { return Limits{Trace: 1}, nil }
	resp, b = f.do(t, "POST", "/anthropic/v1/messages", ccBody)
	if code, _, _ := denial(t, resp, b); code != "KEYS_BUDGET{trace}" || resp.Header.Get("retry-after") != "" {
		t.Errorf("trace: %s %v", b, resp.Header)
	}
}

// INTENT before forwarding (§6.3): with auditd refusing, nothing reaches the vendor and nothing is billed; a server
// tool the policy allows taints the task first, and one it doesn't is refused.
func TestAuditFirst(t *testing.T) {
	f := newFixture(t, sseReply(stream...))
	f.auditErr = errors.New("auditd down")
	resp, b := f.do(t, "POST", "/anthropic/v1/messages", ccBody)
	if code, _, _ := denial(t, resp, b); resp.StatusCode != 503 || code != "AUDIT_UNAVAILABLE{}" || f.vendor.count() != 0 {
		t.Errorf("auditd down: %d %s", resp.StatusCode, b)
	}
	if day, _, _ := f.s.Ledger.Spent("ga", f.t.Trace, time.Now()); day != 0 {
		t.Errorf("billed %d for a request that never went out", day)
	}
	f.auditErr = nil
	ws := `{"model":"claude-opus-5-5","max_tokens":10,"messages":[],"tools":[{"type":"web_search_20260209","name":"web_search"}]}`
	resp, b = f.do(t, "POST", "/anthropic/v1/messages", ws)
	if code, _, _ := denial(t, resp, b); code != "KEYS_REQUEST_REJECTED{server_tool}" {
		t.Errorf("web_search without the policy: %s", b)
	}
	f.s.ServerTools = func() []string { return []string{"web_search"} }
	f.mu.Lock()
	f.audits = nil
	f.mu.Unlock()
	if resp, _ := f.do(t, "POST", "/anthropic/v1/messages", ws); resp.StatusCode != 200 || len(f.audits) != 2 || f.audits[0]["type"] != "TAINT" ||
		f.audits[0]["subject"] != "task:"+f.t.ID || f.audits[0]["source"] != "keys:web_search" || f.audits[1]["type"] != "LLM" {
		t.Errorf("web_search with the policy: %d %v", resp.StatusCode, f.audits)
	}
}

// #291: a model request that carries the task's canary, raw or base64 in the body or in a forwarded header, still
// goes to the vendor and tells rootd once for the task; a clean one doesn't, though its auth headers hold the canary,
// as every task's do. A canary.hit rootd didn't record is sent again with the next such request.
func TestCanaryAlert(t *testing.T) {
	f := newFixture(t, sseReply(stream...))
	c := canary.Mint()
	f.t.Canary = c
	var mu sync.Mutex
	var hits []string
	fail := true
	f.s.CanaryHit = func(task string) error {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, task)
		if fail {
			fail = false
			return errors.New("rootd down")
		}
		return nil
	}
	body := func(text string) string {
		b, _ := json.Marshal(map[string]any{"model": "claude-opus-5-5", "max_tokens": 10, "messages": []any{map[string]any{"role": "user", "content": text}}})
		return string(b)
	}
	for i, r := range []struct {
		body string
		h    []string
		hits int
	}{
		{body("hi"), []string{"x-api-key", c, "Authorization", "Bearer " + c}, 0},
		{body("env: ANTHROPIC_API_KEY=" + c), nil, 1}, // rootd fails this one
		{body("b64 " + base64.StdEncoding.EncodeToString([]byte("token="+c+"\n"))), nil, 2},
		{body("again " + c), nil, 2}, // the task's hit is recorded: no second alert
	} {
		n := f.vendor.count()
		if resp, b := f.do(t, "POST", "/anthropic/v1/messages", r.body, r.h...); resp.StatusCode != 200 || f.vendor.count() != n+1 {
			t.Fatalf("request %d: %d %s, %d reached the vendor", i, resp.StatusCode, b, f.vendor.count()-n)
		}
		mu.Lock()
		if len(hits) != r.hits || r.hits > 0 && hits[r.hits-1] != f.t.ID {
			t.Errorf("request %d: canary.hit %v, want %d", i, hits, r.hits)
		}
		mu.Unlock()
	}
	// a forwarded header is scanned too
	f2 := newFixture(t, sseReply(stream...))
	f2.t.Canary = c
	n := 0
	f2.s.CanaryHit = func(string) error { n++; return nil }
	if resp, _ := f2.do(t, "POST", "/anthropic/v1/messages", body("hi"), "User-Agent", "x/"+c); resp.StatusCode != 200 || n != 1 {
		t.Errorf("the canary in User-Agent: %d, %d hits", resp.StatusCode, n)
	}
	f3 := newFixture(t, sseReply(stream...))
	f3.s.CanaryHit = func(string) error { t.Error("a task with no canary reported one"); return nil }
	f3.do(t, "POST", "/anthropic/v1/messages", body(c))
}

// OpenAI: the Bearer key, store forced to false, and no key at all is KEYS_UPSTREAM{auth} before any upstream byte.
func TestOpenAI(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"resp_1","usage":{"input_tokens":10,"input_tokens_details":{"cached_tokens":4},"output_tokens":3}}`)
	})
	resp, _ := f.do(t, "POST", "/openai/v1/responses", `{"model":"gpt-5.5","input":"hi","store":true}`, "OpenAI-Beta", "responses=experimental")
	r := f.vendor.reqs[0]
	if resp.StatusCode != 200 || r.Header.Get("Authorization") != "Bearer sk-proj-GATEfakeOPENAIkey0123456789" || r.Header.Get("X-Api-Key") != "" ||
		!bytes.Contains(f.vendor.body[0], []byte(`"store":false`)) || r.Header.Get("Openai-Beta") != "responses=experimental" {
		t.Errorf("%d %v %s", resp.StatusCode, r.Header, f.vendor.body[0])
	}
	if resp, _ := f.do(t, "GET", "/openai/v1/models", ""); resp.StatusCode != 200 || f.vendor.reqs[1].Method != "GET" {
		t.Errorf("models: %d", resp.StatusCode)
	}
	f.s.Key = func(string) string { return "" }
	resp, b := f.do(t, "POST", "/openai/v1/responses", `{"model":"gpt-5.5","input":"hi"}`)
	if code, _, _ := denial(t, resp, b); code != "KEYS_UPSTREAM{auth}" || f.vendor.count() != 2 {
		t.Errorf("no key: %s", b)
	}
}

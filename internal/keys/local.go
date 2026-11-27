package keys

import (
	"bytes"
	"context"
	"encoding/json"
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
	"agentbox/internal/ops"
)

// Local is the local LLM path (§6.3 Local LLM): POST /local/v1/chat/completions only, a body rebuilt from a closed
// field list, and instance taint. The instance (agentbox-llm@task, behind Socket) is dirty once it served a tainted
// request since it last started; a dirty instance serves only tainted requests. An untainted request waits until the
// instance is idle, then keys has rootd restart it (llm.recycle) and serves the untainted requests first. Requests
// take the one instance in turn, the agent served longest ago first.
type Local struct {
	Socket    string                          // /run/agentbox-llm/llama.sock
	Tainted   func(task string) (bool, error) // rootd's view of the task's effective taint
	Recycle   func() error                    // llm.recycle on resolve-keys.sock: returns once the new instance runs
	MaxTokens int64                           // the max_tokens cap

	mu        sync.Mutex
	dirty     bool // served a tainted request since it last started
	busy      bool // a request or a restart holds the instance
	waiting   []*waiter
	lastTurn  map[string]int64 // agent -> the turn it was last served at
	turn      int64
	transport *http.Transport
}

type waiter struct {
	agent   string
	tainted bool
	ready   chan error
}

// localFields are the only fields keys sends the local LLM (§6.3): everything else is dropped, and named.
var localFields = []string{"messages", "max_tokens", "temperature", "top_p", "stop", "tools", "tool_choice"}

var reField = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// rebuild is the body the local LLM gets, and the names of what it dropped: unknown top-level fields, and tools that
// are not type function (as "tools").
func (l *Local) rebuild(body []byte) ([]byte, []string, *rej) {
	v, err := decodeJSON(body)
	top, ok := v.(map[string]any)
	if err != nil || !ok || !utf8Valid(body) {
		return nil, nil, &rej{what: "field", ptr: "/", wording: "the request body must be one JSON object with unique keys"}
	}
	out, dropped := map[string]any{}, []string{}
	for _, k := range sortedKeys(top) {
		if slices.Contains(localFields, k) {
			out[k] = top[k]
		} else if reField.MatchString(k) {
			dropped = append(dropped, k)
		} else {
			dropped = append(dropped, "field")
		}
	}
	if ts, ok := out["tools"].([]any); ok {
		keep := slices.DeleteFunc(slices.Clone(ts), func(t any) bool { m, _ := t.(map[string]any); return m["type"] != "function" })
		if len(keep) != len(ts) {
			dropped = append(dropped, "tools")
		}
		out["tools"] = keep
	}
	if r := urlScan(map[string]any{"messages": out["messages"]}, nil); r != nil { // the server must fetch nothing either
		return nil, nil, r
	}
	if r := (obj{"messages": list(chatMessage), "max_tokens": num, "temperature": num, "top_p": num, "stop": strOr(list(str)),
		"tools": tools(map[string]obj{"function": chatTool}, nil, new([]string)), "tool_choice": toolChoiceAny}).check(out, nil); r != nil {
		return nil, nil, r
	}
	if n, ok := out["max_tokens"].(json.Number); ok {
		if i, err := n.Int64(); err != nil || i < 0 || i > l.MaxTokens {
			return nil, nil, &rej{what: "max_tokens", ptr: "/max_tokens", limit: l.MaxTokens}
		}
	} else {
		out["max_tokens"] = l.MaxTokens
	}
	return encodeJSON(out), slices.Compact(dropped), nil
}

func (l *Local) serve(w http.ResponseWriter, r *http.Request, t *broker.Task, body []byte, s *Server) {
	out, dropped, rj := l.rebuild(body)
	if rj != nil {
		s.reject(w, t, rj)
		return
	}
	tainted, err := l.Tainted(t.ID)
	if err != nil {
		log.Printf("task %s: local LLM: taint unknown (%v): served as tainted", t.ID, err)
		tainted = true // fail closed: the instance turns dirty, never a clean caller's
	}
	if err := l.acquire(r.Context(), t.Agent, tainted); err != nil {
		if r.Context().Err() == nil {
			log.Printf("task %s: local LLM: %v", t.ID, err)
			s.upstreamFail(w, t, "unreachable")
		}
		return
	}
	defer l.release()
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://llama/v1/chat/completions", bytes.NewReader(out))
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client().RoundTrip(req)
	if err != nil {
		log.Printf("task %s: local LLM: %v", t.ID, err)
		s.upstreamFail(w, t, "unreachable")
		return
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxReply))
	if err != nil {
		s.upstreamFail(w, t, "unreachable")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	if len(dropped) > 0 {
		d := ops.Deny(ops.KeysRequestRejected, "dropped_field", ops.Slots{By: "keys"})
		h.Set(ops.DenialHeaderName, ops.DenialHeader(d))
		h.Set("Agentbox-Dropped-Fields", strings.Join(dropped, ","))
		log.Printf("DENY by=keys task=%s code=%s what=dropped_field id=%s fields=%s", t.ID, d.Code, d.ID, strings.Join(dropped, ","))
	}
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(resp.StatusCode)
	w.Write(b)
}

func (l *Local) client() *http.Transport {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.transport == nil {
		l.transport = &http.Transport{DisableKeepAlives: true, DisableCompression: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", l.Socket)
			}, ResponseHeaderTimeout: 10 * time.Minute}
	}
	return l.transport
}

// acquire waits for the instance: the caller's turn, and an instance a clean caller may use.
func (l *Local) acquire(ctx context.Context, agent string, tainted bool) error {
	wt := &waiter{agent: agent, tainted: tainted, ready: make(chan error, 1)}
	l.mu.Lock()
	l.waiting = append(l.waiting, wt)
	l.mu.Unlock()
	l.dispatch()
	select {
	case err := <-wt.ready:
		return err
	case <-ctx.Done():
		l.mu.Lock()
		if i := slices.Index(l.waiting, wt); i >= 0 {
			l.waiting = slices.Delete(l.waiting, i, i+1)
			l.mu.Unlock()
			return ctx.Err()
		}
		l.mu.Unlock()
		if err := <-wt.ready; err == nil { // dispatch picked it as the context ended: give the turn back
			l.release()
		}
		return ctx.Err()
	}
}

func (l *Local) release() {
	l.mu.Lock()
	l.busy = false
	l.mu.Unlock()
	l.dispatch()
}

// dispatch hands the idle instance to the next waiter: untainted ones first, each kind in agent turn order. An
// untainted waiter on a dirty instance gets a restart first, so it never sees output of an instance that served a
// tainted request.
func (l *Local) dispatch() {
	l.mu.Lock()
	if l.busy || len(l.waiting) == 0 {
		l.mu.Unlock()
		return
	}
	if l.lastTurn == nil {
		l.lastTurn = map[string]int64{}
	}
	pick := -1
	for _, clean := range []bool{true, false} {
		for i, w := range l.waiting {
			if !w.tainted == clean && (pick < 0 || l.lastTurn[w.agent] < l.lastTurn[l.waiting[pick].agent]) {
				pick = i
			}
		}
		if pick >= 0 {
			break
		}
	}
	w := l.waiting[pick]
	l.busy = true
	if !w.tainted && l.dirty {
		l.mu.Unlock()
		err := l.Recycle() // the queue drained: busy was false, so nothing runs on the instance now
		l.mu.Lock()
		if err != nil {
			l.waiting = slices.Delete(l.waiting, pick, pick+1)
			l.busy = false
			l.mu.Unlock()
			w.ready <- err
			l.dispatch()
			return
		}
		l.dirty = false
		pick = slices.Index(l.waiting, w) // a waiter may have left while rootd restarted the instance
		if pick < 0 {
			l.busy = false
			l.mu.Unlock()
			l.dispatch()
			return
		}
	}
	l.waiting = slices.Delete(l.waiting, pick, pick+1)
	l.turn++
	l.lastTurn[w.agent] = l.turn
	if w.tainted {
		l.dirty = true
	}
	l.mu.Unlock()
	w.ready <- nil
}

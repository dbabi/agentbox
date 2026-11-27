package keys

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// The ledger (§6.3): a reservation counts until it settles, an agent's day share and a trace each cap their own
// spend, the day resets at 00:00 UTC, and a reservation a crash left open counts in full after a restart.
func TestLedger(t *testing.T) {
	p := filepath.Join(t.TempDir(), "spend.db")
	l, err := OpenLedger(p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	lim := Limits{Agent: 100, Capped: true, Trace: 150}
	over := func(err error) string {
		var o *Over
		if errors.As(err, &o) {
			return o.What
		}
		return ""
	}
	if err := l.Reserve("a1", "ga", "trace_1", "task_1", "m", 60, lim, now); err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve("a2", "ga", "trace_1", "task_1", "m", 60, lim, now); over(err) != "agent" {
		t.Fatalf("over the share: %v", err)
	}
	if err := l.Settle("a1", 10); err != nil {
		t.Fatal(err)
	}
	if err := l.Settle("a1", 10); err == nil {
		t.Fatal("settled twice")
	}
	if err := l.Reserve("a2", "ga", "trace_1", "task_1", "m", 60, lim, now); err != nil {
		t.Fatalf("after settling low: %v", err)
	}
	// another agent's spend leaves this one's share alone; the shared trace still caps both
	if err := l.Reserve("b1", "gb", "trace_1", "task_2", "m", 81, lim, now); over(err) != "trace" {
		t.Fatalf("trace: %v", err)
	}
	if err := l.Reserve("b1", "gb", "trace_2", "task_2", "m", 80, lim, now); err != nil {
		t.Fatalf("gb on its own trace: %v", err)
	}
	if err := l.Reserve("c1", "gc", "trace_3", "task_3", "m", 1, Limits{Agent: 100, Capped: true, Box: 150}, now); over(err) != "box" {
		t.Fatalf("box backstop: %v", err)
	}
	if err := l.Reserve("a3", "ga", "trace_9", "task_1", "m", 60, lim, now.Add(12*time.Hour)); err != nil {
		t.Fatalf("the next UTC day: %v", err)
	}
	if NextDay(now) != time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC) {
		t.Error(NextDay(now))
	}
	l.Close()
	l, err = OpenLedger(p) // a2 never settled: a crash after it went upstream
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if day, tr, _ := l.Spent("ga", "trace_1", now); day != 70 || tr != 70 {
		t.Errorf("after the restart: day %d trace %d, want 70 (a2 at its reservation)", day, tr)
	}
	if err := l.Settle("a2", 0); err == nil {
		t.Error("a restart left a2 open")
	}
}

// Usage from each vendor's reply shape, streamed or whole.
func TestUsage(t *testing.T) {
	s := &sseUsage{vendor: "anthropic"}
	for _, c := range stream {
		for i := 0; i < len(c); i += 7 {
			s.feed([]byte(c[i:min(i+7, len(c))]))
		}
	}
	if s.u != (usage{in: 100, cacheRead: 50, out: 20, known: true}) {
		t.Errorf("anthropic stream: %+v", s.u)
	}
	o := &sseUsage{vendor: "openai"}
	o.feed([]byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":30,\"input_tokens_details\":{\"cached_tokens\":10},\"output_tokens\":5}}}\n\n"))
	if o.u != (usage{in: 20, cacheRead: 10, out: 5, known: true}) {
		t.Errorf("responses stream: %+v", o.u)
	}
	if u, ok := fromJSON("openai", []byte(`{"usage":{"prompt_tokens":9,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":4}}}`)); !ok || u != (usage{in: 5, cacheRead: 4, out: 2, known: true}) {
		t.Errorf("chat: %+v", u)
	}
	if u, _ := fromJSON("anthropic", []byte(`{"usage":{"input_tokens":1,"cache_creation_input_tokens":8,"cache_creation":{"ephemeral_5m_input_tokens":3,"ephemeral_1h_input_tokens":5},"output_tokens":2}}`)); u.cacheWrite5m != 3 || u.cacheWrite1h != 5 {
		t.Errorf("cache writes: %+v", u)
	}
	p := models["anthropic"]["claude-opus-5-5"]
	if c := p.cost(usage{in: 1_000_000}); c != 4000*1_000_000 {
		t.Errorf("$4 per million input tokens: %d nanodollars", c)
	}
	if r := p.reserve(1000, 3000); r != p.cost(usage{in: 1000, out: 1000}) {
		t.Errorf("reserve %d", r)
	}
}

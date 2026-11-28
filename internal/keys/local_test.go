package keys

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agentbox/internal/broker"
)

// fakeLlama is the local LLM: each Recycle starts a new instance, and every reply names the instance that served it.
type fakeLlama struct {
	instance atomic.Int64
	bodies   chan map[string]any
	hold     chan struct{} // a request whose messages say "hold" waits on it
	recycles atomic.Int64
}

func newLocal(t *testing.T, tainted map[string]bool) (*Local, *fakeLlama) {
	dir, err := os.MkdirTemp("", "llm") // short: a socket path holds 104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "llama.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	fl := &fakeLlama{bodies: make(chan map[string]any, 64), hold: make(chan struct{})}
	fl.instance.Store(1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		fl.bodies <- m
		if b, _ := json.Marshal(m["messages"]); strings.Contains(string(b), "hold") {
			<-fl.hold
		}
		io.WriteString(w, `{"instance":`+itoa(fl.instance.Load())+`}`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	var mu sync.Mutex
	l := &Local{Socket: sock, MaxTokens: 100,
		Tainted: func(task string) (bool, error) { mu.Lock(); defer mu.Unlock(); return tainted[task], nil },
		Recycle: func() error { fl.recycles.Add(1); fl.instance.Add(1); return nil }}
	return l, fl
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func localCall(t *testing.T, s *Server, task *broker.Task, body string) (*http.Response, int64) {
	t.Helper()
	srv := httptest.NewServer(s.Handler(task))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/local/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r struct{ Instance int64 }
	json.NewDecoder(resp.Body).Decode(&r)
	return resp, r.Instance
}

// The local LLM (§6.3): the body rebuilt from the field list, with the dropped names on the 200; a clean caller never
// gets output from an instance that served a tainted request since it started; queued clean callers go first.
func TestLocal(t *testing.T) {
	ta := &broker.Task{ID: "task_01JTAINTEDAAAAAAAAAAAAAAAA", Agent: "ga", Trace: "trace_01JAAAAAAAAAAAAAAAAAAAAAAA"}
	tb := &broker.Task{ID: "task_01JCLEANBBBBBBBBBBBBBBBBBB", Agent: "gb", Trace: "trace_01JBBBBBBBBBBBBBBBBBBBBBBB"}
	l, fl := newLocal(t, map[string]bool{ta.ID: true})
	s := &Server{Local: l}
	resp, inst := localCall(t, s, tb, `{"messages":[{"role":"user","content":"hi"}],"grammar":"x","n_probs":3,"model":"m","stream":true,
		"tools":[{"type":"function","function":{"name":"f"}},{"type":"web_search"}],"temperature":0.2}`)
	got := <-fl.bodies
	if resp.StatusCode != 200 || inst != 1 || resp.Header.Get("Agentbox-Dropped-Fields") != "grammar,model,n_probs,stream,tools" ||
		!strings.Contains(resp.Header.Get("Agentbox-Denial"), "code=KEYS_REQUEST_REJECTED") || got["max_tokens"] != 100.0 || got["grammar"] != nil ||
		len(got["tools"].([]any)) != 1 || got["temperature"] != 0.2 {
		t.Errorf("rebuild: %d %v %v", resp.StatusCode, resp.Header, got)
	}
	if resp, _ := localCall(t, s, tb, `{"messages":[],"max_tokens":101}`); resp.StatusCode != 403 {
		t.Errorf("max_tokens over the cap: %d", resp.StatusCode)
	}
	if resp, _ := localCall(t, s, tb, `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://x/a.png"}}]}]}`); resp.StatusCode != 403 {
		t.Errorf("an image URL for the local LLM: %d", resp.StatusCode)
	}
	if _, inst := localCall(t, s, ta, `{"messages":[]}`); inst != 1 || fl.recycles.Load() != 0 {
		t.Errorf("tainted on the clean instance: instance %d, %d recycles", inst, fl.recycles.Load())
	}
	<-fl.bodies
	// the instance is dirty now: the clean caller gets a fresh one
	if _, inst := localCall(t, s, tb, `{"messages":[]}`); inst != 2 || fl.recycles.Load() != 1 {
		t.Errorf("clean after tainted: instance %d, %d recycles", inst, fl.recycles.Load())
	}
	<-fl.bodies
	// a tainted call holds the instance; a tainted and then a clean call queue; the clean one goes first, on a new
	// instance. The stand-in's order of arrival is the serving order: a reply can be read after the next one's (#327)
	type served struct {
		who  string
		inst int64
	}
	done := make(chan served, 3)
	call := func(who string, tk *broker.Task) {
		_, i := localCall(t, s, tk, `{"messages":[{"role":"user","content":"`+who+`"}]}`)
		done <- served{who, i}
	}
	queued := func(n int) { // n calls wait for the instance: a fixed sleep let a slow runner release it too early
		for i := 0; ; i++ {
			l.mu.Lock()
			k := len(l.waiting)
			l.mu.Unlock()
			if k == n {
				return
			}
			if i == 1000 {
				t.Fatalf("%d calls wait for the instance, want %d", k, n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	go call("hold", ta)
	<-fl.bodies
	go call("tainted", ta)
	queued(1)
	go call("clean", tb)
	queued(2)
	close(fl.hold)
	ran := map[string]int64{}
	for range 3 {
		r := <-done
		ran[r.who] = r.inst
	}
	var order []string
	for range 2 {
		b, _ := json.Marshal((<-fl.bodies)["messages"])
		order = append(order, map[bool]string{true: "clean", false: "tainted"}[strings.Contains(string(b), "clean")])
	}
	if ran["hold"] != 2 || ran["clean"] != 3 || ran["tainted"] != 3 || strings.Join(order, ",") != "clean,tainted" {
		t.Errorf("instances %v, served %v: want the holder on 2, the clean caller on a fresh 3, then the tainted one", ran, order)
	}
}

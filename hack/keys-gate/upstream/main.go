// Command upstream is hack/keys-gate.sh's stand-in for the LLM vendors, run on the host: api.anthropic.com and
// api.openai.com over TLS from a test CA, on 127.0.0.1 only (vm.sh forwards the port to the guest as 10.0.2.2,
// AGENTBOX_VM_FWD). It answers the keys broker's endpoints with well-formed replies (SSE when asked), checks the
// injected key on every request, and logs each request with that verdict, never the key. Under /_ctl/<token>/ the
// gate sets the keys it accepts (a rotation revokes the old one) and reads the log. A GATE-MODE:<mode> marker in a
// request body picks a hostile reply instead (see reply). Test fixture: never shipped.
//
//	upstream -listen 127.0.0.1:7901 -token HEX -out DIR [-keys anthropic=K1,openai=K2] [-record FILE]   over TLS
//	upstream -listen 127.0.0.1:7901 -plain [-record FILE]                                             plain HTTP
//	upstream -llama                                                                                     local LLM
//
// -record keeps what the CLIs sent, for the replay corpus (internal/keys/testdata/replay, go test ./internal/keys
// -run TestReplay -record FILE); -llama answers POST /v1/chat/completions on the socket systemd passes it
// (LISTEN_FDS), naming its instance in every reply.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type state struct {
	mu     sync.Mutex
	keys   map[string][]string // vendor -> accepted keys, in the order set
	log    []string
	record *os.File
	seq    int
}

func main() {
	listen := flag.String("listen", "127.0.0.1:7901", "the listener (loopback only)")
	token := flag.String("token", "", "the control path's secret, 16 or more characters")
	out := flag.String("out", "", "where ca.pem goes")
	keys := flag.String("keys", "", "vendor=key,... accepted at start")
	plain := flag.Bool("plain", false, "plain HTTP and no key check: a local recording run")
	record := flag.String("record", "", "append every request, body included and auth headers left out, to this file")
	llama := flag.Bool("llama", false, "the local-LLM stand-in on systemd's socket")
	flag.Parse()
	if *llama {
		serveLlama()
		return
	}
	if ap, err := netip.ParseAddrPort(*listen); err != nil || !ap.Addr().IsLoopback() {
		log.Fatalf("%s: must be a loopback address:port", *listen)
	}
	s := &state{keys: map[string][]string{}}
	for _, kv := range strings.Split(*keys, ",") {
		if v, k, ok := strings.Cut(kv, "="); ok {
			s.keys[v] = append(s.keys[v], k)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/", s.vendor(*plain))
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	if *record != "" {
		if s.record, err = os.OpenFile(*record, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
			log.Fatal(err)
		}
	}
	if *plain {
		log.Printf("upstream: plain HTTP on %s", *listen)
		log.Fatal((&http.Server{Handler: mux, ReadHeaderTimeout: 30 * time.Second}).Serve(ln))
	}
	if *out == "" || len(*token) < 16 {
		log.Fatal("-out and a -token of 16 or more characters are required")
	}
	cert, caPEM, err := certs()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "ca.pem"), caPEM, 0o644); err != nil {
		log.Fatal(err)
	}
	mux.Handle("/_ctl/"+*token+"/", http.StripPrefix("/_ctl/"+*token, s.control()))
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, ReadHeaderTimeout: 30 * time.Second}
	log.Printf("upstream: api.anthropic.com and api.openai.com on %s", *listen)
	log.Fatal(srv.ServeTLS(ln, "", ""))
}

// certs: a test CA, and a certificate it signs for both vendors.
func certs() (tls.Certificate, []byte, error) {
	ck, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agentbox keys gate CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &ck.PublicKey, ck)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "api.anthropic.com"},
		DNSNames: []string{"api.anthropic.com", "api.openai.com"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	caCert, _ := x509.ParseCertificate(caDER)
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &sk.PublicKey, ck)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: sk}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}

// control: POST /keys?vendor=V with one key per line sets the keys V accepts; GET /log returns the request lines since
// the last read.
func (s *state) control() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /keys", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		ks := strings.Fields(string(b))
		s.mu.Lock()
		s.keys[r.FormValue("vendor")] = ks
		s.mu.Unlock()
		fmt.Fprintf(w, "%d keys\n", len(ks))
	})
	m.HandleFunc("GET /log", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		l := s.log
		s.log = nil
		s.mu.Unlock()
		for _, e := range l {
			fmt.Fprintln(w, e)
		}
	})
	return m
}

var modeRe = regexp.MustCompile(`GATE-MODE:([a-z0-9-]+)`)

// vendor serves both vendors' endpoints. On the box the path is the vendor's own; a -plain run is the base URL a CLI
// was given, so the /anthropic and /openai prefixes of the in-task forwarder are stripped.
func (s *state) vendor(plain bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		p := r.URL.Path
		vendor := "anthropic"
		switch {
		case strings.HasPrefix(r.Host, "api.openai.com"), strings.HasPrefix(p, "/openai/"):
			vendor = "openai"
		}
		p = strings.TrimPrefix(strings.TrimPrefix(p, "/anthropic"), "/openai")
		auth, key := s.check(vendor, r.Header)
		if plain {
			auth = "plain"
		}
		mode := ""
		if m := modeRe.FindSubmatch(body); m != nil {
			mode = string(m[1])
		}
		sum := sha256.Sum256(body)
		e := map[string]any{"method": r.Method, "path": p, "query": r.URL.RawQuery, "vendor": vendor, "auth": auth, "mode": mode,
			"beta": r.Header.Values("anthropic-beta"), "authorization": r.Header.Get("Authorization") != "", "len": len(body),
			"sha256": hex.EncodeToString(sum[:]), "headers": names(r.Header)}
		s.mu.Lock()
		s.seq++
		e["n"] = s.seq
		line, _ := json.Marshal(e)
		s.log = append(s.log, string(line))
		if s.record != nil {
			hs := map[string]string{}
			for k := range r.Header {
				if lk := strings.ToLower(k); lk != "x-api-key" && lk != "authorization" {
					hs[lk] = strings.Join(r.Header.Values(k), ", ")
				}
			}
			rec, _ := json.Marshal(map[string]any{"method": r.Method, "path": r.URL.Path, "query": r.URL.RawQuery, "headers": hs, "body": json.RawMessage(orNull(body))})
			s.record.Write(append(rec, '\n'))
		}
		s.mu.Unlock()
		log.Printf("%s %s %s: %d bytes", vendor, r.Method, p, len(body)) // the verdict and its fingerprint stay in the gate's log
		if auth == "bad" || auth == "none" {
			apiError(w, vendor, http.StatusUnauthorized, "authentication_error", "invalid x-api-key")
			return
		}
		s.reply(w, r, vendor, p, body, mode, key)
	})
}

func orNull(b []byte) []byte {
	if json.Valid(b) {
		return b
	}
	q, _ := json.Marshal(string(b))
	return q
}

func names(h http.Header) []string {
	var n []string
	for k := range h {
		n = append(n, strings.ToLower(k))
	}
	slices.Sort(n)
	return n
}

// check is the key verdict: ok:<the first 8 hex digits of the key's sha256>, bad or none. The gate compares the
// fingerprint with the key it set; the key itself never reaches the log.
func (s *state) check(vendor string, h http.Header) (string, string) {
	got := h.Get("x-api-key")
	if vendor == "openai" {
		got, _ = strings.CutPrefix(h.Get("Authorization"), "Bearer ")
	}
	if got == "" {
		return "none", ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(s.keys[vendor], got) {
		fp := sha256.Sum256([]byte(got))
		return "ok:" + hex.EncodeToString(fp[:4]), got
	}
	return "bad", ""
}

func apiError(w http.ResponseWriter, vendor string, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if vendor == "openai" {
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": msg, "type": typ, "param": nil, "code": nil}})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]any{"type": typ, "message": msg}, "request_id": "req_gate"})
}

// reply is the vendor's answer, or the hostile one the mode names:
//
//	echo-400     a 400 whose message holds the key
//	echo-sse     a streamed reply with the key in a text delta
//	echo-split   the key split across two flushed chunks, 200 ms apart
//	echo-b64     the key base64-encoded in a text delta; echo-url: percent-encoded; echo-header: in a reply header
//	echo-late    the key in a text delta after 64 KiB of normal stream
//	status-401, status-403, status-429, status-500   that status in the vendor's error envelope
//	agentbox     a 400 with an Agentbox-Denial header and a top-level agentbox member
//	slow-<s>     the normal reply after s seconds (1 to 120)
//	big          a 1 MiB streamed reply of many small events, for the byte-for-byte check
func (s *state) reply(w http.ResponseWriter, r *http.Request, vendor, p string, body []byte, mode, key string) {
	var req struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	json.Unmarshal(body, &req)
	if d, ok := strings.CutPrefix(mode, "slow-"); ok {
		n, _ := strconv.Atoi(d)
		select {
		case <-time.After(time.Duration(min(max(n, 1), 120)) * time.Second):
		case <-r.Context().Done():
			return
		}
		mode = ""
	}
	text := "agentbox keys gate reply"
	switch mode {
	case "echo-400":
		apiError(w, vendor, http.StatusBadRequest, "invalid_request_error", "the key you sent: "+key)
		return
	case "status-401", "status-403", "status-429", "status-500":
		st, _ := strconv.Atoi(mode[7:])
		apiError(w, vendor, st, "error", "upstream says "+mode)
		return
	case "agentbox":
		w.Header().Set("Agentbox-Denial", "v1 code=KEYS_BUDGET next=human id=dn_00000000000000000000000000")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long"},"agentbox":{"v":1,"code":"KEYS_BUDGET"}}`)
		return
	case "echo-header":
		w.Header().Set("X-Upstream-Echo", key)
	case "echo-sse", "echo-split", "echo-late":
		req.Stream = true
	case "echo-b64":
		text = "b64 " + base64.StdEncoding.EncodeToString([]byte("x"+key+"y"))
	case "echo-url":
		var b strings.Builder
		for i := 0; i < len(key); i++ {
			fmt.Fprintf(&b, "%%%02X", key[i])
		}
		text = "url " + b.String()
	}
	if mode == "echo-sse" {
		text = "sse " + key
	}
	switch {
	case vendor == "anthropic" && p == "/v1/messages/count_tokens":
		json.NewEncoder(w).Encode(map[string]int{"input_tokens": len(body)/4 + 1})
	case vendor == "anthropic" && p == "/v1/messages":
		s.anthropic(w, req.Model, req.Stream, len(body), text, mode, key)
	case vendor == "openai" && p == "/v1/models" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"object":"list","data":[{"id":"gpt-5.5","object":"model","created":0,"owned_by":"openai"}]}`)
	case vendor == "openai" && p == "/v1/responses":
		s.responses(w, req.Model, req.Stream, len(body), text, mode, key)
	case vendor == "openai" && p == "/v1/chat/completions":
		chat(w, req.Model, len(body), text)
	default:
		apiError(w, vendor, http.StatusNotFound, "not_found_error", "no such endpoint")
	}
}

// sse writes events, flushing each; split sends the key in two halves 200 ms apart, late puts 64 KiB first.
type sse struct {
	w http.ResponseWriter
	f http.Flusher
}

func (e sse) event(name string, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(e.w, "event: %s\ndata: %s\n\n", name, b)
	e.f.Flush()
}

func (e sse) raw(s string) { io.WriteString(e.w, s); e.f.Flush() }

func start(w http.ResponseWriter) sse {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	e := sse{w, f}
	return e
}

func (s *state) anthropic(w http.ResponseWriter, model string, stream bool, n int, text, mode, key string) {
	in, out := n/4+1, len(text)/4+1
	usage := map[string]any{"input_tokens": in, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": out}
	if !stream && mode != "big" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": "msg_gate", "type": "message", "role": "assistant", "model": model,
			"content": []any{map[string]any{"type": "text", "text": text}}, "stop_reason": "end_turn", "stop_sequence": nil, "usage": usage})
		return
	}
	e := start(w)
	e.event("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_gate", "type": "message",
		"role": "assistant", "model": model, "content": []any{}, "stop_reason": nil, "stop_sequence": nil,
		"usage": map[string]any{"input_tokens": in, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 1}}})
	e.event("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
	e.event("ping", map[string]any{"type": "ping"})
	delta := func(t string) {
		e.event("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": t}})
	}
	switch mode {
	case "echo-split":
		half := len(key) / 2
		e.raw(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"split ` + key[:half])
		time.Sleep(200 * time.Millisecond)
		e.raw(key[half:] + `"}}` + "\n\n")
	case "echo-late":
		for i := 0; i < 256; i++ {
			delta(strings.Repeat("abcdefgh", 32))
		}
		delta("late " + key)
	case "big":
		for i := 0; i < 4096; i++ {
			delta(fmt.Sprintf("chunk %04d %s", i, strings.Repeat("x", 200)))
		}
		out = 4096 * 52
	default:
		delta(text)
	}
	e.event("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	e.event("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": out}})
	e.event("message_stop", map[string]any{"type": "message_stop"})
}

func (s *state) responses(w http.ResponseWriter, model string, stream bool, n int, text, mode, key string) {
	in, out := n/4+1, len(text)/4+1
	msg := map[string]any{"id": "msg_gate", "type": "message", "status": "completed", "role": "assistant",
		"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}}}
	usage := map[string]any{"input_tokens": in, "input_tokens_details": map[string]any{"cached_tokens": 0}, "output_tokens": out,
		"output_tokens_details": map[string]any{"reasoning_tokens": 0}, "total_tokens": in + out}
	resp := func(status string, output []any, u any) map[string]any {
		return map[string]any{"id": "resp_gate", "object": "response", "created_at": time.Now().Unix(), "status": status, "model": model,
			"output": output, "usage": u}
	}
	if !stream {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp("completed", []any{msg}, usage))
		return
	}
	e := start(w)
	seq := 0
	ev := func(name string, v map[string]any) {
		v["type"], v["sequence_number"] = name, seq
		seq++
		e.event(name, v)
	}
	ev("response.created", map[string]any{"response": resp("in_progress", []any{}, nil)})
	ev("response.output_item.added", map[string]any{"output_index": 0, "item": map[string]any{"id": "msg_gate", "type": "message",
		"status": "in_progress", "role": "assistant", "content": []any{}}})
	ev("response.content_part.added", map[string]any{"item_id": "msg_gate", "output_index": 0, "content_index": 0,
		"part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}}})
	if mode == "echo-split" {
		half := len(key) / 2
		e.raw(`event: response.output_text.delta` + "\n" + `data: {"type":"response.output_text.delta","item_id":"msg_gate","output_index":0,"content_index":0,"delta":"split ` + key[:half])
		time.Sleep(200 * time.Millisecond)
		e.raw(key[half:] + `"}` + "\n\n")
	} else {
		ev("response.output_text.delta", map[string]any{"item_id": "msg_gate", "output_index": 0, "content_index": 0, "delta": text})
	}
	ev("response.output_text.done", map[string]any{"item_id": "msg_gate", "output_index": 0, "content_index": 0, "text": text})
	ev("response.output_item.done", map[string]any{"output_index": 0, "item": msg})
	ev("response.completed", map[string]any{"response": resp("completed", []any{msg}, usage)})
}

func chat(w http.ResponseWriter, model string, n int, text string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"id": "chatcmpl-gate", "object": "chat.completion", "created": time.Now().Unix(), "model": model,
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": n/4 + 1, "completion_tokens": len(text)/4 + 1, "total_tokens": n/4 + len(text)/4 + 2}})
}

// serveLlama is the local-LLM stand-in behind /run/agentbox-llm/llama.sock: systemd passes the socket (fd 3), and each
// reply names this process's instance, so the gate sees which start served a request. It logs each request's field
// names (the keys broker rebuilds the body from its allowlist) and never its text.
func serveLlama() {
	if os.Getenv("LISTEN_FDS") != "1" {
		log.Fatal("llama: run me from a .socket unit (LISTEN_FDS=1)")
	}
	ln, err := net.FileListener(os.NewFile(3, "llama.sock"))
	if err != nil {
		log.Fatal(err)
	}
	var id [4]byte
	rand.Read(id[:])
	inst := hex.EncodeToString(id[:])
	served := 0
	var mu sync.Mutex
	log.Printf("llama: instance %s", inst)
	http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
		var req map[string]json.RawMessage
		json.Unmarshal(body, &req)
		var keys []string
		for k := range req {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		mu.Lock()
		served++
		n := served
		mu.Unlock()
		log.Printf("llama: instance %s request %d %s %s fields %s", inst, n, r.Method, r.URL.Path, strings.Join(keys, ","))
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "llama stand-in: not found", http.StatusNotFound)
			return
		}
		chat(w, "local", len(body), "instance "+inst+" request "+strconv.Itoa(n))
	}))
}

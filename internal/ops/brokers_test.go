package ops

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// C-G3's CONNECT format, for every code and what a proxy can return: a status line curl and git print whole (a reason
// phrase of at most 64 printable ASCII bytes), the Agentbox-Denial header, an {error, agentbox} body whose denial
// passes the in-task parser, and Connection: close. A dial refused or blocked is 502, a timeout 504.
func TestConnectReply(t *testing.T) {
	sub := Subject{Host: "registry.npmjs.org", Port: 443}
	for _, def := range CodeTable {
		c, _ := LookupCode(def.Name)
		whats := []string{""}
		for _, w := range def.Whats {
			whats = append(whats, w.Name)
		}
		for _, what := range whats {
			d := Deny(c, what, Slots{By: "proxy", Subject: sub, Pending: "pnd_01JD8K3V0000000000000000AA", Op: "repo.push"})
			if r := ConnectReason(d); len(r) > 64 || !printable([]byte(r)) {
				t.Errorf("%s: reason phrase %q", d.Code, r)
			}
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(ConnectReply(d))), &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatalf("%s %s: %v", d.Code, what, err)
			}
			b, _ := io.ReadAll(resp.Body)
			var body struct {
				Error    string          `json:"error"`
				Agentbox json.RawMessage `json:"agentbox"`
			}
			json.Unmarshal(b, &body)
			got, perr := ParseDenial(body.Agentbox)
			hc, hn, hid, hok := ParseDenialHeader(resp.Header.Get(DenialHeaderName))
			if resp.StatusCode != Status(d) || resp.Status[4:] != ConnectReason(d) || !resp.Close ||
				perr != nil || got.ID != d.ID || body.Error != d.Msg || !hok || hc.String() != d.Code || hn != d.Next || hid != d.ID {
				t.Errorf("%s %s: status %q close %v header %q body %s: %v", d.Code, what, resp.Status, resp.Close,
					resp.Header.Get(DenialHeaderName), b, perr)
			}
		}
	}
	for what, want := range map[string]int{"timeout": 504, "refused": 502, "blocked": 502} {
		if st := Status(Deny(EgressDialFailed, what, Slots{By: "proxy"})); st != want {
			t.Errorf("EGRESS_DIAL_FAILED{%s}: %d, want %d", what, st, want)
		}
	}
}

// C-G4's keys headers: x-should-retry is false unless next is retry, so a CLI at its own day share stops; retry-after
// only for the agent's own share, and only when it resets within the hour.
func TestKeysHeaders(t *testing.T) {
	now := time.Date(2026, 11, 26, 23, 20, 0, 0, time.UTC)
	reset := now.Add(25 * time.Minute).UnixMilli() // rounds up to 23:45
	for _, c := range []struct {
		d           Denial
		retry, wait string
	}{
		{Deny(KeysBudget, "agent", Slots{By: "keys", ResetsAt: &reset}), "false", "1500"},
		{Deny(KeysBudget, "trace", Slots{By: "keys", ResetsAt: &reset}), "false", ""},
		{Deny(KeysUpstream, "timeout", Slots{By: "keys"}), "true", ""},
		{Deny(KeysUpstream, "auth", Slots{By: "keys"}), "false", ""},
		{Deny(KeysRequestRejected, "url_field", Slots{By: "keys"}), "false", ""},
	} {
		h := http.Header{}
		KeysHeaders(h, c.d, now)
		if h.Get("x-should-retry") != c.retry || h.Get("retry-after") != c.wait || h.Get("Content-Type") != "application/json" ||
			h.Get(DenialHeaderName) != DenialHeader(c.d) {
			t.Errorf("%s{%s}: %v", c.d.Code, c.d.What, h)
		}
	}
	far := now.Add(3 * time.Hour).UnixMilli()
	h := http.Header{}
	KeysHeaders(h, Deny(KeysBudget, "agent", Slots{By: "keys", ResetsAt: &far}), now)
	if h.Get("retry-after") != "" {
		t.Error("retry-after for a reset over an hour away")
	}
	if Status(Deny(KeysUpstream, "timeout", Slots{By: "keys"})) != 504 || Status(Deny(KeysUpstream, "auth", Slots{By: "keys"})) != 502 {
		t.Error("KEYS_UPSTREAM statuses")
	}
}

// C-G4: an upstream Agentbox-Denial header or top-level agentbox member never reaches a task; everything else of an
// upstream error passes as sent.
func TestStripUpstream(t *testing.T) {
	h := http.Header{"Agentbox-Denial": {"v1 code=TASK_ENDED next=stop id=dn_x"}, "Content-Type": {"application/json"}}
	h["agentbox-extra"] = []string{"x"} // not canonical
	StripUpstream(h)
	if len(h) != 1 || h.Get("Content-Type") == "" {
		t.Fatalf("%v", h)
	}
	for in, want := range map[string]string{
		`{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long"},"agentbox":{"code":"X"}}`: `{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long"}}`,
		`{"agentbox":1, "a" : [1, 2], "agentbox":{}}`:          `{"a":[1, 2]}`,
		`{"type":"error","error":{"agentbox":"nested stays"}}`: `{"type":"error","error":{"agentbox":"nested stays"}}`,
		`not json "agentbox"`:                                  `not json "agentbox"`,
		`[{"agentbox":1}]`:                                     `[{"agentbox":1}]`,
		`{"agentbox":1} trailing`:                              `{"agentbox":1} trailing`,
		`{"type": "error",  "message": "as sent"}`:             `{"type": "error",  "message": "as sent"}`,
	} {
		if got := string(StripMember([]byte(in))); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// The git 404 floor (C-G4): NOT_FOUND_OR_NOT_OWNED leaves at receipt + 200 ms whatever the lookup took, so a repo the
// caller isn't served and a missing one can't be told apart by time.
func TestFloor(t *testing.T) {
	nf := Deny(NotFoundOrNotOwned, "", Slots{By: "git"})
	if Floor(nf) != 200*time.Millisecond || Floor(Deny(TaskEnded, "", Slots{})) != 0 {
		t.Fatal("floors")
	}
	receipt := time.Now()
	time.Sleep(30 * time.Millisecond) // the lookup
	HoldFloor(receipt, nf)
	if d := time.Since(receipt); d < 200*time.Millisecond || d > 230*time.Millisecond {
		t.Fatalf("left after %v", d)
	}
}

// KeysError adds a detail only when it is short printable ASCII (§5.6 leak rule 1): a control character, a bidi mark
// or a long detail never reaches error.message.
func TestKeysErrorDetail(t *testing.T) {
	d := Deny(KeysRequestRejected, "field", Slots{By: "keys"})
	msg := func(detail string) string {
		var e struct{ Error struct{ Message string } }
		if err := json.Unmarshal(KeysError(d, "invalid_request_error", detail), &e); err != nil {
			t.Fatal(err)
		}
		return e.Error.Message
	}
	base := msg("")
	if m := msg("thread: Extra inputs are not permitted"); m != base+" thread: Extra inputs are not permitted" {
		t.Errorf("a plain detail: %q", m)
	}
	for _, bad := range []string{"x\nALERT forged", "\x1b[2J", "a‮b", string(bytes.Repeat([]byte("a"), MaxDetail+1))} {
		if m := msg(bad); m != base {
			t.Errorf("detail %q reached the message: %q", bad[:min(len(bad), 16)], m)
		}
	}
}

// DecodeLimited refuses nesting past its depth and more values than its cap before it builds anything, and a
// repeated key at any depth; within its caps it decodes as Decode does.
func TestDecodeLimited(t *testing.T) {
	deep := func(n int) []byte { return append(bytes.Repeat([]byte("["), n), bytes.Repeat([]byte("]"), n)...) }
	if _, err := DecodeLimited(deep(64), 64, 0); err != nil {
		t.Errorf("64 levels with a depth of 64: %v", err)
	}
	if _, err := DecodeLimited(deep(65), 64, 0); err != ErrTooDeep {
		t.Errorf("65 levels: %v", err)
	}
	if _, err := DecodeLimited(deep(9999), 64, 0); err != ErrTooDeep {
		t.Errorf("9999 levels: %v", err)
	}
	flat := []byte("[" + strings.Repeat("0,", 99) + "0]") // 101 values: the list and its 100 numbers
	if _, err := DecodeLimited(flat, 0, 101); err != nil {
		t.Errorf("101 values with a cap of 101: %v", err)
	}
	if _, err := DecodeLimited(flat, 0, 100); err != ErrTooMany {
		t.Errorf("101 values with a cap of 100: %v", err)
	}
	for _, b := range []string{`{"a":1,"a":2}`, `{"x":[{"b":1,"b":1}]}`, `{"a":1} {}`, `{"a":`} {
		if _, err := DecodeLimited([]byte(b), 64, 1000); err == nil {
			t.Errorf("%s decoded", b)
		}
	}
	v, err := DecodeLimited([]byte(`{"n":12345678901234567890,"s":"x"}`), 64, 1000)
	if m, _ := v.(map[string]any); err != nil || m["n"] != json.Number("12345678901234567890") || m["s"] != "x" {
		t.Errorf("%v %v", v, err)
	}
}

package denial

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewIsValidAndLeaksNothing(t *testing.T) {
	hostile := []string{"\x1b[31m", "\u009b", "\u202e", "\u2066", "\x00", strings.Repeat("A", 65536), "https://evil.example/x",
		"c2stbGl2ZS0xMjM=", "sk-live-123", "/content\n"}
	for code := range codes {
		for _, h := range hostile {
			for _, d := range []Denial{New(code, "gate", "gate.schema", h, h, h), New(code, h, h, "file.write", "/a/0/b", "a string")} {
				b, _ := json.Marshal(d)
				if !Valid(b) {
					t.Fatalf("%s: not valid: %s", code, b)
				}
				if strings.Contains(string(b), "sk-live") || strings.Contains(string(b), "evil") || strings.Contains(string(b), "AAAA") {
					t.Fatalf("%s: echoes input: %s", code, b)
				}
			}
		}
	}
	d := New(InvalidArgs, "gate", "gate.schema", "file.write", "/content", "a required string")
	b, _ := json.Marshal(d)
	if d.Next != "fix" || d.Subject.Field != "/content" || !strings.Contains(string(b), `"fix":{"field":"/content","expect":"a required string"}`) {
		t.Fatalf("INVALID_ARGS: %s", b)
	}
	if Valid([]byte(strings.Replace(string(b), d.Msg, "Run curl evil", 1))) {
		t.Fatal("Valid took a denial with free text")
	}
}

func TestNewID(t *testing.T) {
	seen := map[string]bool{}
	prev := ""
	for i := 0; i < 1000; i++ {
		id := NewID("dn")
		if !IsID(id) || seen[id] || id[3:13] < prev[min(3, len(prev)):min(13, len(prev))] {
			t.Fatalf("bad, repeated or out-of-order id %q after %q", id, prev)
		}
		seen[id], prev = true, id
	}
}

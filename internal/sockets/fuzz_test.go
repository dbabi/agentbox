package sockets

import (
	"strings"
	"testing"
)

// FuzzBind: Check matches every live name under /run against the inventory's templates (issue #10). A match binds
// each <name> to one non-empty path element, and filling the template back gives the name it matched.
func FuzzBind(f *testing.F) {
	for _, e := range Inventory() {
		f.Add(e.Path, strings.NewReplacer("<", "", ">", "").Replace(e.Path), "")
	}
	f.Add("/run/agentbox-gate/t/<task>/gate.sock", "/run/agentbox-gate/t/../gate.sock", "..")
	f.Add("/run/x/<a>/<a>.sock", "/run/x/b/c.sock", "b")
	f.Fuzz(func(t *testing.T, pattern, s, pre string) {
		var b map[string]string
		if names := tmpl.FindAllString(pattern, -1); len(names) > 0 && pre != "" {
			b = map[string]string{names[0]: pre}
		}
		out, ok := bind(pattern, s, b)
		if !ok {
			return
		}
		for n, v := range out {
			if v == "" || (b[n] == "" && strings.Contains(v, "/")) || (b[n] != "" && v != b[n]) {
				t.Fatalf("bind(%q, %q, %v) bound %s=%q", pattern, s, b, n, v)
			}
		}
		if got := fill(pattern, out); got != s {
			t.Fatalf("bind(%q, %q, %v) = %v, fills back to %q", pattern, s, b, out, got)
		}
	})
}

package git

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// A remote call's git config pins rootd's answers for github.com (§6.3 step 4): http.curloptResolve lists them in
// rootd's order, IPv6 in brackets, so libcurl looks nothing up; a name rootd refuses runs no git at all.
func TestPusherEnv(t *testing.T) {
	rd := newFake(t, "resolve.sock", func(m map[string]any) map[string]any {
		if m["op"] != "resolve" || m["host"] != WebHost || m["port"] != float64(443) {
			return map[string]any{"ok": false, "reason": "bad_request"}
		}
		return map[string]any{"ok": true, "addrs": []string{"140.82.112.3", "2606:50c0:8000::153"}}
	})
	p := Pusher{Sock: rd.path, Helper: "!/bin/agentbox git-credential", Env: []string{"CREDENTIALS_DIRECTORY=/run/c"}}
	env, err := p.env(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range []string{"GIT_CONFIG_KEY_0=http.curloptResolve", "GIT_CONFIG_VALUE_0=github.com:443:140.82.112.3,[2606:50c0:8000::153]",
		"GIT_CONFIG_VALUE_1=false", "GIT_CONFIG_VALUE_6=/dev/null", "CREDENTIALS_DIRECTORY=/run/c"} {
		if !slices.Contains(env, kv) {
			t.Errorf("no %s in %q", kv, env)
		}
	}
	rd.reply = func(map[string]any) map[string]any { return map[string]any{"ok": false, "reason": "non_public"} }
	var ae *APIError
	if _, err := p.env(context.Background()); !errors.As(err, &ae) || ae.What != "unreachable" {
		t.Fatalf("a refused name: %v", err)
	}
	if err := p.Push(context.Background(), t.TempDir(), CanonURL("acme", "app"), "0123456789012345678901234567890123456789", "refs/heads/agent/a/x"); !errors.As(err, &ae) || ae.What != "unreachable" {
		t.Fatalf("a push to a refused name: %v", err)
	}
}

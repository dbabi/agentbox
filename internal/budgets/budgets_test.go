package budgets

import (
	"path/filepath"
	"testing"
)

// The strict subset: known keys and explicit shares only, integers only, no repeats; a typo never reads as a default.
func TestParse(t *testing.T) {
	b, err := Parse("# caps\ncache.agent_max_bytes = 1048576\n\nkeys.day_cap_cents=1000\nkeys.agent_day_share.ga = 600\n")
	if err != nil {
		t.Fatal(err)
	}
	if b.Get("cache.agent_max_bytes") != 1<<20 || b.Get("cache.max_idle_days") != 30 || b.Get("keys.day_cap_cents") != 1000 {
		t.Fatalf("%v", b)
	}
	for _, bad := range []string{
		"cache.agent_max_byte = 1",                     // unknown
		"cache.agent_max_bytes = -1",                   // negative
		"cache.agent_max_bytes = 1.5",                  // not an integer
		"cache.agent_max_bytes = \"1\"",                // a string
		"cache.agent_max_bytes = 99999999999999999999", // out of range
		"cache.agent_max_bytes = 1\ncache.agent_max_bytes = 2",
		"[cache]\nagent_max_bytes = 1",
		"keys.agent_day_share.Bad = 1\nkeys.day_cap_cents = 10",
		"keys.agent_day_share.ga = 1",                                                          // a share with no cap
		"keys.day_cap_cents = 100\nkeys.agent_day_share.ga = 60\nkeys.agent_day_share.gb = 41", // above the cap
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if r, err := Parse(b.Render()); err != nil || len(r) != len(b) {
		t.Fatalf("Render does not parse back: %v %v", r, err)
	}
}

// C-G4's shares: equal by default, explicit where set with the rest split among the others, recomputed from the
// active agents; one agent's share never depends on another's spend.
func TestShares(t *testing.T) {
	b, _ := Parse("keys.day_cap_cents = 900")
	s, err := b.Shares([]string{"ga", "gb", "gc"})
	if err != nil || s.Agents["ga"] != 300 || s.Agents["gc"] != 300 {
		t.Fatalf("%+v %v", s, err)
	}
	if s, _ = b.Shares([]string{"ga", "gb"}); s.Agents["ga"] != 450 {
		t.Fatalf("after a remove: %+v", s)
	}
	b, _ = Parse("keys.day_cap_cents = 900\nkeys.agent_day_share.ga = 500\nkeys.agent_day_share.gx = 100")
	if s, _ = b.Shares([]string{"ga", "gb", "gc"}); s.Agents["ga"] != 500 || s.Agents["gb"] != 200 || s.Agents["gc"] != 200 {
		t.Fatalf("explicit: %+v", s)
	}
	if c, capped := s.Of("ga"); c != 500 || !capped {
		t.Fatal("Of")
	}
	if c, capped := s.Of("gz"); c != 0 || !capped {
		t.Fatal("an agent with no share under a cap gets 0")
	}
	if s, _ = (Budgets{}).Shares([]string{"ga"}); s.CapCents != 0 {
		t.Fatal("no cap set")
	} else if _, capped := s.Of("ga"); capped {
		t.Fatal("no cap set, but capped")
	}
	p := filepath.Join(t.TempDir(), "s.json")
	if got, err := ReadShares(p); err != nil || got.CapCents != 0 {
		t.Fatal("a missing shares file is no cap")
	}
}

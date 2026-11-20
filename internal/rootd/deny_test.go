package rootd

import (
	"fmt"
	"testing"
	"time"
)

func TestDenyThrottle(t *testing.T) {
	var got []map[string]any
	d := newDenyAudit(func(r map[string]any) { got = append(got, r) })
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < 100; i++ { // a broker looping on one unlisted name
		d.add(denial{"keys", "evil.example:443", "not_allowlisted", "", t0.Add(time.Duration(i) * 100 * time.Millisecond)})
	}
	if len(got) != 1 || got[0]["count"] != 1 {
		t.Fatalf("want one record for the window, got %v", got)
	}
	d.flush(t0.Add(time.Minute))
	if len(got) != 2 || got[1]["id"] != got[0]["id"] || got[1]["count"] != 100 {
		t.Fatalf("want the window's count under the same id, got %v", got)
	}
	d.add(denial{"keys", "evil.example:443", "not_allowlisted", "", t0.Add(61 * time.Second)})
	if len(got) != 3 || got[2]["id"] == got[0]["id"] {
		t.Fatalf("a new window gets a new record and id: %v", got)
	}
	// distinct names: the per-broker cap, then one DENY_FLOOD with the skipped count
	for i := 0; i < denyCap+20; i++ {
		d.add(denial{"git", fmt.Sprintf("h%d.example:443", i), "not_allowlisted", "", t0})
	}
	if n := len(got) - 3; n != denyCap {
		t.Fatalf("want %d records for git, got %d", denyCap, n)
	}
	d.flush(t0.Add(denyPeriod))
	last := got[len(got)-1]
	if last["type"] != "DENY_FLOOD" || last["svc"] != "git" || last["count"] != 20 {
		t.Fatalf("want a DENY_FLOOD of 20, got %v", last)
	}
	d.add(denial{"git", "new.example:443", "not_allowlisted", "", t0.Add(denyPeriod)})
	if got[len(got)-1]["entry"] != "new.example:443" {
		t.Fatal("the cap did not reset with the period")
	}
}

func TestDenyQueueBounded(t *testing.T) {
	d := newDenyAudit(func(map[string]any) {})
	n := 0
	for i := 0; i < denyQueue+10; i++ {
		if d.deny("keys", "x.example:443", "not_allowlisted", "") {
			n++
		}
	}
	if n != denyQueue {
		t.Fatalf("queued %d, want %d (the rest dropped, never blocking)", n, denyQueue)
	}
}

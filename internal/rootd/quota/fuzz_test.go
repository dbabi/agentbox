package quota

import (
	"strings"
	"testing"
)

// Fuzz targets for the btrfs output the qgroup setup reads (issue #10).

func FuzzParseShow(f *testing.F) {
	f.Add([]byte(show))
	f.Add([]byte(`{"qgroup-show": [{"qgroupid": "0/5", "max_referenced": 18446744073709551616, "parents": null}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		qs, err := parseShow(b)
		if err == nil && len(qs) == 0 {
			t.Fatal("no qgroups and no error")
		}
	})
}

func FuzzParseMode(f *testing.F) {
	f.Add("Quotas on /var/lib/agentbox:\n  Enabled:                 yes\n  Mode:                    qgroup (full accounting)\n  Inconsistent:            no\n")
	f.Add("Enabled: no\n")
	f.Add("Enabled: yes\nMode:\n")
	f.Fuzz(func(t *testing.T, s string) {
		if m, err := parseMode(s); err == nil && strings.ContainsAny(m, " \t\n") {
			t.Fatalf("mode %q", m)
		}
	})
}

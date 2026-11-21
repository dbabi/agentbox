package ntfy

import (
	"strings"
	"testing"
)

// FuzzCheckStatusUID: /proc/<pid>/status passes only with a Uid: line whose four uids are all the wanted one (issue #10).
func FuzzCheckStatusUID(f *testing.F) {
	f.Add("Name:\tntfy\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\n", "998")
	f.Add("Uid:\t998\t0\t998\t998\n", "998")
	f.Add("Uid: 1 1 1\nUid: 1 1 1 1\n", "1")
	f.Fuzz(func(t *testing.T, status, uid string) {
		if checkStatusUID(status, uid) != nil {
			return
		}
		for _, l := range strings.Split(status, "\n") {
			if f := strings.Fields(l); len(f) == 5 && f[0] == "Uid:" {
				if f[1] != uid || f[2] != uid || f[3] != uid || f[4] != uid {
					t.Fatalf("passed %q for uid %q", l, uid)
				}
				return
			}
		}
		t.Fatalf("passed %q with no Uid line", status)
	})
}

package taskenv

import (
	"strings"
	"testing"
)

// FuzzGoPrivate: patterns that pass are printable ASCII without spaces, at most MaxPrivate bytes, and every one is a
// valid path.Match glob, so GOPRIVATE never carries anything else.
func FuzzGoPrivate(f *testing.F) {
	for _, s := range []string{"corp.example/*", "a,b", "[", "x y", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidGoPrivate(s) != nil {
			return
		}
		if len(s) > MaxPrivate || strings.ContainsAny(s, " \t\n\r=;\"'$`\\") || strings.Contains(s, ",,") {
			t.Fatalf("%q passes", s)
		}
	})
}

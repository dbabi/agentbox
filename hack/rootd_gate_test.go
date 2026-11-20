package hack

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"agentbox/internal/rootd/resolve"
)

// The rootd gate's firewall stub must drop exactly the ranges rootd's resolver refuses (Appendix B: one list).
func TestRootdGateStubPrivateSets(t *testing.T) {
	b, err := os.ReadFile("rootd-gate/firewall-stub.nft")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]string{"private4": resolve.Private4, "private6": resolve.Private6} {
		m := regexp.MustCompile(`set ` + name + ` [^}]*elements = \{([^}]*)\}`).FindSubmatch(b)
		if m == nil {
			t.Fatalf("no %s set in the stub", name)
		}
		var got []string
		for _, e := range strings.Split(string(m[1]), ",") {
			got = append(got, strings.TrimSpace(e))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: stub %v, rootd %v", name, got, want)
		}
	}
}

package hack

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"agentbox/internal/ops"
)

// TestRegistryGateShipped keeps registry-gate.sh's expected gen/ listing equal to ops.Shipped, so a new generated
// file fails here and not on the VM.
func TestRegistryGateShipped(t *testing.T) {
	src, err := os.ReadFile("registry-gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`check "the release ships gen/[^"]*" '\[ "\$\(ls "\$G" \| tr "\\n" " "\)" = "([^"]*)" \]'`).FindSubmatch(src)
	if m == nil {
		t.Fatal("registry-gate.sh: no gen/ listing check")
	}
	want := slices.Sorted(slices.Values(ops.Shipped))
	if got := strings.Fields(string(m[1])); !slices.Equal(got, want) {
		t.Errorf("registry-gate.sh expects gen/ = %v, the release ships %v", got, want)
	}
}

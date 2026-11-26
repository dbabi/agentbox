package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// TestUnlisted: a listed skip passes, a new skip fails until it is listed, a "<package> *" line covers the package,
// a "<package> Test*" line its tests but not its fuzz targets, a whole-package skip (no Test) and a pass are ignored,
// and plain-text build errors pass through.
func TestUnlisted(t *testing.T) {
	in := `{"Action":"skip","Package":"agentbox/hack","Test":"TestPowercutCheck","Output":""}
{"Action":"output","Package":"agentbox/hack","Test":"TestNew","Output":"    x_test.go:9: tool not installed\n"}
{"Action":"skip","Package":"agentbox/hack","Test":"TestNew"}
{"Action":"skip","Package":"agentbox/internal/a","Test":"TestB/sub"}
{"Action":"pass","Package":"agentbox/internal/a","Test":"TestC"}
{"Action":"skip","Package":"agentbox/internal/audit","Test":"TestAny"}
{"Action":"skip","Package":"agentbox/internal/f","Test":"TestSealed/sub"}
{"Action":"skip","Package":"agentbox/internal/f","Test":"FuzzSegment"}
{"Action":"skip","Package":"agentbox/internal/empty"}
# agentbox/broken
`
	list := "# why\nagentbox/hack TestPowercutCheck # needs the image\n\nagentbox/internal/a  TestB/sub\nagentbox/internal/audit *\nagentbox/internal/f Test*\n"
	var out bytes.Buffer
	bad, err := unlisted(strings.NewReader(in), &out, list)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"agentbox/hack TestNew", "agentbox/internal/f FuzzSegment"}; !reflect.DeepEqual(bad, want) {
		t.Errorf("unlisted = %q, want %q", bad, want)
	}
	if !strings.Contains(out.String(), "tool not installed") || !strings.Contains(out.String(), "# agentbox/broken") {
		t.Errorf("output not passed through:\n%s", out.String())
	}
	if bad, _ = unlisted(strings.NewReader(in), &out, list+"agentbox/hack TestNew\nagentbox/internal/f FuzzSegment\n"); len(bad) != 0 {
		t.Errorf("listed, still unlisted: %q", bad)
	}
}

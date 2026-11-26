// Command ciskips reads `go test -json` on stdin, prints the test output, and fails if a test skipped that the
// allowlist file does not name. CI runs `go test -json ./... | go run ./hack/ciskips hack/testdata/ci-skips.txt`, so a
// test that starts skipping (a tool went missing from the runner, say) fails CI until someone lists it on purpose.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// event is the part of test2json's output this reads.
type event struct {
	Action, Package, Test, Output string
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go test -json ./... | ciskips <allowlist>")
		os.Exit(2)
	}
	list, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	bad, err := unlisted(os.Stdin, os.Stdout, string(list))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(bad) > 0 {
		fmt.Fprintf(os.Stderr, "skipped tests not in %s:\n  %s\n", os.Args[1], strings.Join(bad, "\n  "))
		os.Exit(1)
	}
}

// unlisted copies each event's output to out and returns the "<package> <test>" of every skip the list lacks. A list
// line is "<package> <test>", where a trailing * matches any rest: "<package> *" is every test in the package, and
// "<package> Test*" its tests but not its fuzz targets. # starts a comment. Subtests are named in full (TestA/sub).
func unlisted(in io.Reader, out io.Writer, list string) ([]string, error) {
	ok := map[string]bool{}
	for _, l := range strings.Split(list, "\n") {
		if l, _, _ = strings.Cut(l, "#"); len(strings.Fields(l)) > 0 {
			ok[strings.Join(strings.Fields(l), " ")] = true
		}
	}
	bad := map[string]bool{}
	sc := bufio.NewScanner(in)
	sc.Buffer(nil, 16<<20)
	for sc.Scan() {
		var e event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			// go test prints build errors as plain text; pass them through, go test's own exit status fails the step
			fmt.Fprintln(out, sc.Text())
			continue
		}
		io.WriteString(out, e.Output)
		if k := e.Package + " " + e.Test; e.Action == "skip" && e.Test != "" && !listed(ok, k) {
			bad[k] = true
		}
	}
	keys := make([]string, 0, len(bad))
	for k := range bad {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, sc.Err()
}

func listed(ok map[string]bool, k string) bool {
	for l := range ok {
		if p, glob := strings.CutSuffix(l, "*"); l == k || glob && strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

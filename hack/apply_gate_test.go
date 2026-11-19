package hack

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestApplyGateChecks runs every check call of apply-gate.sh under dash, with apply-gate.sh's own check(), every
// variable the calls name and every helper they call (the VM's answers) set to shell syntax that creates a marker file
// if the host ever parses it as code. A check must name the guest's values for eval to expand, never splice them into
// the text eval parses: root in the test VM would otherwise run commands as the developer on the Mac.
func TestApplyGateChecks(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	src, err := os.ReadFile("apply-gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	def := regexp.MustCompile(`(?m)^check\(\) \{.*\}$`).Find(src)
	if def == nil {
		t.Fatal("check() not found in apply-gate.sh")
	}
	// each call runs on its own, from `check "` to the end of its line
	var calls [][]byte
	for _, l := range bytes.Split(src, []byte("\n")) {
		if i := bytes.Index(l, []byte(`check "`)); i >= 0 && !bytes.HasPrefix(bytes.TrimSpace(l), []byte("#")) {
			calls = append(calls, l[i:])
		}
	}
	if len(calls) < 20 {
		t.Fatalf("found only %d check calls in apply-gate.sh", len(calls))
	}
	vars := map[string]bool{}
	for _, c := range calls {
		for _, m := range regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`).FindAllSubmatch(c, -1) {
			vars[string(m[1])] = true
		}
	}
	for _, v := range []string{"LOG", "fails", "IFS", "PATH", "HOME"} { // check()'s own state and the shell's
		delete(vars, v)
	}
	var set strings.Builder
	for v := range vars {
		set.WriteString(v + `=$X` + "\n")
	}
	var stubs strings.Builder
	for _, m := range regexp.MustCompile(`(?m)^([a-z_]+)\(\) \{`).FindAllSubmatch(src, -1) {
		if f := string(m[1]); f != "check" && f != "log" && f != "die" {
			stubs.WriteString(f + `() { cat >/dev/null 2>&1; printf '%s\n' "$X"; }` + "\n")
		}
	}
	prelude := "fails=0 LOG=/dev/null\nlog() { printf '%s\\n' \"$*\" >> checks.out; }\ndie() { log \"ABORT $*\"; }\n" +
		stubs.String() + string(def) + "\n" + set.String() + `set -- "$X" "$X" "$X"` + "\n"
	run := func(payload string, lines [][]byte) (marker bool, checks []string, out []byte, err error) {
		dir := t.TempDir()
		script := prelude
		for _, l := range lines {
			script += "( " + string(l) + " ) || :\n"
		}
		c := exec.Command(dash, "-c", script)
		c.Dir = dir
		c.Env = append(os.Environ(), "X="+payload)
		out, err = c.CombinedOutput()
		_, serr := os.Stat(filepath.Join(dir, "ran"))
		b, _ := os.ReadFile(filepath.Join(dir, "checks.out"))
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if strings.HasPrefix(l, "PASS ") || strings.HasPrefix(l, "FAIL ") {
				checks = append(checks, l)
			}
		}
		return serr == nil, checks, out, err
	}
	// each payload breaks out of one way of splicing: single quotes, double quotes, bare words
	payloads := []string{`x';touch ran;'x`, `x";touch ran;"x`, `x;touch ran;#`, `$(touch ran)`, "`touch ran`"}
	// the payloads must run when spliced, or a pass proves nothing
	control := [][]byte{
		[]byte(`check c1 "[ \"\$(committed)\" = '$C' ]"`),
		[]byte(`check c2 "[ \"\$(committed)\" = \"$C\" ]"`),
		[]byte(`check c3 "[ \"\$(committed)\" = $C ]"`),
	}
	for _, p := range payloads {
		if marker, _, out, err := run(p, control); err != nil || !marker {
			t.Errorf("control %q: spliced, it did not run (%v)\n%s", p, err, out)
		}
		marker, checks, out, err := run(p, calls)
		if err != nil {
			t.Errorf("%q: dash: %v\n%s", p, err, out)
		}
		if marker {
			for _, c := range calls {
				if m, _, _, _ := run(p, [][]byte{c}); m {
					t.Errorf("%q: this check runs a guest value as code on the host: %s", p, c)
				}
			}
		}
		if len(checks) != len(calls) {
			t.Errorf("%q: %d of %d check calls ran:\n%s\n%s", p, len(checks), len(calls), strings.Join(checks, "\n"), out)
		}
	}
}

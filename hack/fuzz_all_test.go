package hack

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestFuzzAll runs fuzz-all.sh under dash with a fake go: every listed target runs at nice 10 for the given time, a
// crash fails the run, and the summary names the crasher.
func TestFuzzAll(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	src, err := os.ReadFile("fuzz-all.sh")
	if err != nil {
		t.Fatal(err)
	}
	root, bin := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(root, "hack"), 0o755)
	os.WriteFile(filepath.Join(root, "hack", "fuzz-all.sh"), src, 0o755)
	os.WriteFile(filepath.Join(bin, "go"), []byte(`#!/bin/sh
case "$1 $2" in
"list ./...") echo x/a; echo x/b ;;
"test -list") [ "$4" = x/a ] && { echo FuzzA; echo TestNot; } || echo FuzzB; echo "ok $4 0.1s" ;;
*) echo "$* nice=$(ps -o nice= -p $$ | tr -d ' ')" >> "$OUT/calls"
   case "$*" in *FuzzB*) echo "    Failing input written to testdata/fuzz/FuzzB/abc"; exit 1 ;; esac
   echo "fuzz: elapsed: 1s, execs: 42 (42/sec)" ;;
esac
`), 0o755)
	out := filepath.Join(t.TempDir(), "out")
	cmd := exec.Command(dash, filepath.Join(root, "hack", "fuzz-all.sh"), "3s")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "OUT="+out)
	b, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a crash must fail the run:\n%s", b)
	}
	sum, _ := os.ReadFile(filepath.Join(out, "summary.txt"))
	calls, _ := os.ReadFile(filepath.Join(out, "calls"))
	for _, want := range []string{"targets=2 fails=1", "PASS x/a FuzzA execs=42\n", "FAIL x/b FuzzB execs=0 crasher=testdata/fuzz/FuzzB/abc"} {
		if !strings.Contains(string(sum), want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
	for _, re := range []string{`test -run=\^\$ -fuzz=\^FuzzA\$ -fuzztime=3s -parallel=1 x/a nice=10`, `-fuzz=\^FuzzB\$ -fuzztime=3s -parallel=1 x/b nice=10`} {
		if !regexp.MustCompile(re).Match(calls) {
			t.Errorf("no call matching %s:\n%s", re, calls)
		}
	}
	cmd = exec.Command(dash, filepath.Join(root, "hack", "fuzz-all.sh"), "-l")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	if l, err := cmd.Output(); err != nil {
		t.Fatal(err)
	} else if string(l) != "x/a FuzzA\nx/b FuzzB\n" {
		t.Errorf("-l lists %q", l)
	}
}

// TestFuzzAllListFails: a package whose tests do not build, a failing go list, or no targets at all must fail both -l
// and the run, not shrink the target list.
func TestFuzzAllListFails(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	src, err := os.ReadFile("fuzz-all.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "hack"), 0o755)
	os.WriteFile(filepath.Join(root, "hack", "fuzz-all.sh"), src, 0o755)
	for name, fake := range map[string]string{
		"test build fails": `case "$1 $2" in
"list ./...") echo x/a; echo x/b ;;
"test -list") [ "$4" = x/a ] && { echo "x/a/broken_test.go:1: undefined: undefinedThing" >&2; exit 1; }; echo FuzzB ;;
*) echo "fuzz: elapsed: 1s, execs: 42 (42/sec)" ;;
esac`,
		"go list fails": `case "$1 $2" in
"list ./...") echo x/a; exit 1 ;;
"test -list") echo FuzzA ;;
*) echo "fuzz: elapsed: 1s, execs: 42 (42/sec)" ;;
esac`,
		"no targets": `case "$1 $2" in
"list ./...") echo x/a ;;
"test -list") echo TestNot; echo "ok $4 0.1s" ;;
*) echo "fuzz: elapsed: 1s, execs: 42 (42/sec)" ;;
esac`,
	} {
		bin := t.TempDir()
		os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\n"+fake+"\n"), 0o755)
		for _, arg := range []string{"-l", "1s"} {
			cmd := exec.Command(dash, filepath.Join(root, "hack", "fuzz-all.sh"), arg)
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "OUT="+filepath.Join(t.TempDir(), "out"))
			if b, err := cmd.CombinedOutput(); err == nil {
				t.Errorf("%s: fuzz-all.sh %s exited 0:\n%s", name, arg, b)
			} else if !strings.Contains(string(b), "fuzz-all: ") {
				t.Errorf("%s: fuzz-all.sh %s gave no reason:\n%s", name, arg, b)
			}
		}
	}
}

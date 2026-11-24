package hack

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestFuzzAll runs fuzz-all.sh under dash with a fake go: every listed target runs at nice 10 for the given time, under
// GOMEMLIMIT, one at a time with FUZZ_JOBS=1; a crash fails the run, and the summary names the crasher and each
// target's CPU seconds. Without FUZZ_JOBS, the run picks at least one job and at most one per CPU.
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
*) echo "$* nice=$(ps -o nice= -p $$ | tr -d ' ') mem=$GOMEMLIMIT start" >> "$OUT/calls"
   sleep 1; echo end >> "$OUT/calls"
   case "$*" in *FuzzB*) echo "    Failing input written to testdata/fuzz/FuzzB/abc"; exit 1 ;; esac
   echo "fuzz: elapsed: 1s, execs: 42 (42/sec)" ;;
esac
`), 0o755)
	out := filepath.Join(t.TempDir(), "out")
	cmd := exec.Command(dash, filepath.Join(root, "hack", "fuzz-all.sh"), "3s")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "OUT="+out, "FUZZ_JOBS=1", "FUZZ_MEM=300MiB")
	b, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a crash must fail the run:\n%s", b)
	}
	sum, _ := os.ReadFile(filepath.Join(out, "summary.txt"))
	calls, _ := os.ReadFile(filepath.Join(out, "calls"))
	for _, want := range []string{"targets=2 fails=1", "1 at a time, GOMEMLIMIT=300MiB", "PASS x/a FuzzA execs=42 cpu_s=0\n",
		"FAIL x/b FuzzB execs=0 cpu_s=0 crasher=testdata/fuzz/FuzzB/abc"} {
		if !strings.Contains(string(sum), want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
	for _, re := range []string{`test -run=\^\$ -fuzz=\^FuzzA\$ -fuzztime=3s -parallel=1 x/a nice=10 mem=300MiB start`, `-fuzz=\^FuzzB\$ -fuzztime=3s -parallel=1 x/b nice=10 mem=300MiB start`} {
		if !regexp.MustCompile(re).Match(calls) {
			t.Errorf("no call matching %s:\n%s", re, calls)
		}
	}
	if !regexp.MustCompile(`^[^\n]* start\nend\n[^\n]* start\nend\n$`).Match(calls) {
		t.Errorf("FUZZ_JOBS=1 must run one target at a time:\n%s", calls)
	}
	cmd = exec.Command(dash, filepath.Join(root, "hack", "fuzz-all.sh"), "1s")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "OUT="+filepath.Join(t.TempDir(), "out2"), "FUZZ_JOBS=")
	b, _ = cmd.CombinedOutput()
	if m := regexp.MustCompile(`targets for 1s each, ([0-9]+) at a time, GOMEMLIMIT=1GiB`).FindSubmatch(b); m == nil {
		t.Errorf("no default job count:\n%s", b)
	} else if n, _ := strconv.Atoi(string(m[1])); n < 1 || n > runtime.NumCPU() {
		t.Errorf("default FUZZ_JOBS=%d, want 1 to %d", n, runtime.NumCPU())
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

// #185: the nightly fuzz run fits in a day, so runs don't overlap: ceil(targets / max-parallel) waves of the default
// FUZZTIME plus 15 min each for the build and queueing, and a concurrency group queues a run that is late anyway.
func TestFuzzWorkflowDay(t *testing.T) {
	y, err := os.ReadFile("../.github/workflows/fuzz.yml")
	if err != nil {
		t.Fatal(err)
	}
	find := func(re string) string {
		m := regexp.MustCompile(re).FindSubmatch(y)
		if m == nil {
			t.Fatalf("fuzz.yml has no match for %s", re)
		}
		return string(m[1])
	}
	if find(`(?m)^concurrency:\n  group: (\S+)\n  cancel-in-progress: false$`) != "fuzz" {
		t.Fatal("no fuzz concurrency group")
	}
	par, _ := strconv.Atoi(find(`(?m)^\s+max-parallel: (\d+)`))
	def := find(`(?m)^\s+default: (\d+h)$`)
	if env := find(`FUZZTIME: \$\{\{ inputs\.fuzztime \|\| '(\d+h)' \}\}`); env != def {
		t.Fatalf("FUZZTIME default %s, input default %s", env, def)
	}
	hours, _ := strconv.Atoi(strings.TrimSuffix(def, "h"))
	n := 0
	filepath.WalkDir("..", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() && strings.HasPrefix(d.Name(), ".") && p != ".." {
			return filepath.SkipDir
		}
		if strings.HasSuffix(p, "_test.go") {
			b, _ := os.ReadFile(p)
			n += len(regexp.MustCompile(`(?m)^func Fuzz\w*\(\w+ \*testing\.F\)`).FindAll(b, -1))
		}
		return nil
	})
	waves := (n + par - 1) / par
	t.Logf("%d targets, %d at a time, %d h each: %d waves", n, par, hours, waves)
	if n == 0 || par == 0 || waves*(hours*60+15) > 24*60 {
		t.Fatalf("%d targets, %d at a time, %d h each: %d waves take over 24 h", n, par, hours, waves)
	}
}

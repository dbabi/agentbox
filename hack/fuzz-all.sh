#!/bin/sh
# hack/fuzz-all.sh [DURATION] runs every Go fuzz target at once, each at nice 10, for DURATION (default 24h: PLAN
# milestone row 4's "24 h of fuzzing, no crash"), then writes OUT/summary.txt and exits 1 if any target failed.
# A crasher lands in its package's testdata/fuzz/<target>/; commit it with the fix as the regression test.
# hack/fuzz-all.sh -l lists "<package> <target>" lines (the fuzz workflow's matrix).
# Env: OUT (default .fuzz/<UTC start>), FUZZ_PARALLEL (workers per target, default 1). On a Mac, run it under
# caffeinate -i so the machine does not sleep.
set -eu
cd "$(dirname "$0")/.."

# list fails, rather than quietly dropping targets, when a package does not build or nothing is found: set -e misses a
# failure in a for word list or in a pipeline's first stage, so each go command's output is captured first.
list() {
	pkgs=$(go list ./...) || { echo "fuzz-all: go list failed" >&2; return 1; }
	n=0
	for p in $pkgs; do
		l=$(go test -list '^Fuzz' "$p") || { echo "fuzz-all: $p does not build" >&2; return 1; }
		while read -r t; do
			case $t in Fuzz*) echo "$p $t"; n=$((n + 1)) ;; esac
		done <<-EOF
			$l
		EOF
	done
	[ "$n" -gt 0 ] || { echo "fuzz-all: no fuzz targets found" >&2; return 1; }
}

if [ "${1:-}" = -l ]; then
	list
	exit
fi
dur=${1:-24h}
out=${OUT:-.fuzz/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$out"
: >"$out/pids"
list >"$out/targets" || exit 1
trap 'trap - INT TERM; kill 0' INT TERM # the go test children and their fuzz workers too
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
commit=$(git describe --always --dirty 2>/dev/null || echo unknown) # before the run: a commit during it must not be credited
while read -r p t; do
	log=$out/$(echo "$p" | tr / _).$t.log
	nice -n 10 go test -run='^$' -fuzz="^$t\$" -fuzztime="$dur" -parallel="${FUZZ_PARALLEL:-1}" "$p" >"$log" 2>&1 &
	echo "$! $p $t $log" >>"$out/pids"
done <"$out/targets"
echo "fuzz-all: $(wc -l <"$out/targets" | tr -d ' ') targets for $dur, logs in $out"

fail=0
: >"$out/results"
while read -r pid p t log; do
	if wait "$pid"; then r=PASS; else r=FAIL fail=$((fail + 1)); fi
	execs=$(grep -o 'execs: [0-9]*' "$log" | tail -n 1 | cut -d' ' -f2)
	crash=$(sed -n 's/.*Failing input written to //p' "$log")
	echo "$r $p $t execs=${execs:-0}${crash:+ crasher=$crash}" >>"$out/results"
done <"$out/pids"
{
	echo "fuzz-all $dur per target, commit $commit, $start to $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "targets=$(wc -l <"$out/results" | tr -d ' ') fails=$fail"
	cat "$out/results"
} >"$out/summary.txt"
cat "$out/summary.txt"
[ "$fail" -eq 0 ]

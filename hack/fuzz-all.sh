#!/bin/sh
# hack/fuzz-all.sh [DURATION] runs every Go fuzz target at once, each at nice 10, for DURATION (default 24h: PLAN
# milestone row 4's "24 h of fuzzing, no crash"), then writes OUT/summary.txt and exits 1 if any target failed.
# A crasher lands in its package's testdata/fuzz/<target>/; commit it with the fix as the regression test.
# hack/fuzz-all.sh -l lists "<package> <target>" lines (the fuzz workflow's matrix).
# Env: OUT (default .fuzz/<UTC start>), FUZZ_PARALLEL (workers per target, default 1). On a Mac, run it under
# caffeinate -i so the machine does not sleep.
set -eu
cd "$(dirname "$0")/.."

list() {
	for p in $(go list ./...); do
		go test -list '^Fuzz' "$p" | while read -r t; do
			case $t in Fuzz*) echo "$p $t" ;; esac
		done
	done
}

if [ "${1:-}" = -l ]; then
	list
	exit 0
fi
dur=${1:-24h}
out=${OUT:-.fuzz/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$out"
: >"$out/pids"
list >"$out/targets"
trap 'trap - INT TERM; kill 0' INT TERM # the go test children and their fuzz workers too
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
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
	echo "fuzz-all $dur per target, commit $(git describe --always --dirty 2>/dev/null || echo unknown), $start to $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "targets=$(wc -l <"$out/results" | tr -d ' ') fails=$fail"
	cat "$out/results"
} >"$out/summary.txt"
cat "$out/summary.txt"
[ "$fail" -eq 0 ]

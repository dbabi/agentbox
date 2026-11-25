#!/bin/sh
# hack/fuzz-all.sh [DURATION] runs every Go fuzz target for DURATION each (default 24h: PLAN milestone row 4's "24 h of
# fuzzing, no crash"), at nice 10 and at most FUZZ_JOBS targets at a time, then writes OUT/summary.txt with each
# target's CPU seconds and exits 1 if any target failed. Go keeps each target's corpus in $(go env GOCACHE)/fuzz, so
# the next run starts from it. A crasher lands in its package's testdata/fuzz/<target>/; commit it with the fix as the
# regression test. hack/fuzz-all.sh -l lists "<package> <target>" lines (the fuzz workflow's matrix).
# Env: OUT (default .fuzz/<UTC start>), FUZZ_PARALLEL (workers per target, default 1), FUZZ_MEM (GOMEMLIMIT of each
# go test and worker process, default 1GiB), FUZZ_JOBS (targets at a time; default: what half the RAM holds at
# FUZZ_MEM per process, at most one per CPU). On a Mac, run it under caffeinate -i so the machine does not sleep.
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
par=${FUZZ_PARALLEL:-1}
mem=${FUZZ_MEM:-1GiB}
case $par in '' | *[!0-9]* | 0) echo "fuzz-all: FUZZ_PARALLEL must be a positive integer" >&2; exit 1 ;; esac
env time -p true >/dev/null 2>&1 || { echo "fuzz-all: needs the time utility for CPU seconds" >&2; exit 1; }
if [ -z "${FUZZ_JOBS:-}" ]; then
	ram=$(sysctl -n hw.memsize 2>/dev/null || awk '/^MemTotal:/ { print $2 * 1024 }' /proc/meminfo)
	mib=$(echo "$mem" | awk '/^[0-9]+MiB$/ { print $0 + 0 } /^[0-9]+GiB$/ { print $0 * 1024 }')
	[ -n "$ram" ] && [ -n "$mib" ] || { echo "fuzz-all: set FUZZ_JOBS, or FUZZ_MEM as <n>MiB or <n>GiB" >&2; exit 1; }
	# each target is a go test process plus FUZZ_PARALLEL workers, each with its own GOMEMLIMIT
	FUZZ_JOBS=$(awk -v r="$ram" -v m="$mib" -v p="$par" -v c="$(getconf _NPROCESSORS_ONLN)" \
		'BEGIN { j = int(r / 2 / 1048576 / m / (p + 1)); if (j > c) j = c; if (j < 1) j = 1; print j }')
fi
case $FUZZ_JOBS in '' | *[!0-9]* | 0) echo "fuzz-all: FUZZ_JOBS must be a positive integer" >&2; exit 1 ;; esac
out=${OUT:-.fuzz/$(date -u +%Y%m%dT%H%M%SZ)}
# an earlier run's .rc would count as this run's result for a target that never wrote one
[ ! -e "$out/targets" ] || { echo "fuzz-all: $out holds an earlier run; set OUT to a new dir" >&2; exit 1; }
mkdir -p "$out"
list >"$out/targets" || exit 1
trap 'trap - INT TERM; kill 0' INT TERM # the go test children and their fuzz workers too
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
commit=$(git describe --always --dirty 2>/dev/null || echo unknown) # before the run: a commit during it must not be credited
echo "fuzz-all: $(wc -l <"$out/targets" | tr -d ' ') targets for $dur each, $FUZZ_JOBS at a time, GOMEMLIMIT=$mem, logs in $out"

# FUZZ_JOBS lanes, each running every FUZZ_JOBS-th target in turn: every target runs for the same time, so a static
# split finishes together, and dash has no wait -n for a shared queue
lane=0
while [ "$lane" -lt "$FUZZ_JOBS" ]; do
	awk -v n="$FUZZ_JOBS" -v l="$lane" 'NR % n == l' "$out/targets" | while read -r p t; do
		log=$out/$(echo "$p" | tr / _).$t.log
		# time -p adds the user and sys seconds of go test, the test binary and its fuzz workers. In an if, a failing
		# target does not end the lane under set -e: the targets after it still run
		if nice -n 10 env GOMEMLIMIT="$mem" time -p go test -run='^$' -fuzz="^$t\$" -fuzztime="$dur" -parallel="$par" "$p" \
			>"$log" 2>&1; then rc=0; else rc=$?; fi
		echo $rc >"$log.rc"
	done &
	lane=$((lane + 1))
done
wait

fail=0
: >"$out/results"
while read -r p t; do
	log=$out/$(echo "$p" | tr / _).$t.log
	[ -f "$log" ] || : >"$log" # a lane that died left none: FAIL with no execs, not an awk error before summary.txt
	if [ "$(cat "$log.rc" 2>/dev/null)" = 0 ]; then r=PASS; else r=FAIL fail=$((fail + 1)); fi
	execs=$(grep -o 'execs: [0-9]*' "$log" | tail -n 1 | cut -d' ' -f2)
	cpu=$(awk '/^(user|sys) [0-9.]+$/ { s += $2 } END { printf "%.0f", s }' "$log")
	crash=$(sed -n 's/.*Failing input written to //p' "$log")
	echo "$r $p $t execs=${execs:-0} cpu_s=$cpu${crash:+ crasher=$crash}" >>"$out/results"
done <"$out/targets"
{
	echo "fuzz-all $dur per target, $FUZZ_JOBS at a time, GOMEMLIMIT=$mem, commit $commit, $start to $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "targets=$(wc -l <"$out/results" | tr -d ' ') fails=$fail"
	cat "$out/results"
} >"$out/summary.txt"
cat "$out/summary.txt"
[ "$fail" -eq 0 ]

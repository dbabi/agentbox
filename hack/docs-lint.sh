#!/bin/sh
# docs-lint.sh: check reader-facing docs against docs/STYLE.md. Prints file:line: rule for each problem.
# Usage: hack/docs-lint.sh [file.md ...]
# With no files it checks the pages STYLE.md covers, plus the privacy rules on docs/design/.
# These are regression guards: they catch known jargon and broken links, not bad prose.
set -u

if [ $# -eq 0 ]; then
	cd "$(dirname "$0")/.." || exit 2
	set -- README.md SECURITY.md docs/THREAT-MODEL.md docs/wiki/*.md mascot/README.md
	design=$(find docs/design -name '*.md' | sort)
else
	design=
fi

# name, grep flags (i = ignore case, - = exact case), scope (all, private or evidence), POSIX ERE
rules=$(cat <<'EOF'
plan-version	i	all	(plan|design)[[:space:][:punct:]]+v[0-9]+([.][0-9]+)*
staffing	i	all	(^|[^[:alnum:]_])([0-9]+|one|two|three|four|five)[[:space:]-]+engineers?([^[:alnum:]_]|$)
schedule	i	all	[0-9]+-week[[:space:]]+plan|[0-9]+[[:space:]]+weeks[[:space:]]+(of[[:space:]]+)?build[[:space:]]+work|^[|][[:space:]]*Weeks[[:space:]]*[|]
phase-weeks	i	all	rows[^.!?]*phases|phases,[[:space:]]*not[[:space:]]+(calendar[[:space:]]+)?weeks
proposal-letter	-	all	[Pp]roposals?[[:space:]]+[(]?[A-Z](-[A-Z])?([)]|[^[:alnum:]_]|$)
planning-record	-	all	(^|[^[:alnum:]_])(LEDGER|PROPOSALS)([.]md)?([^[:alnum:]_]|$)
finding-id	i	all	(^|[^[:alnum:]_])(finding|round)[-_][0-9]+([^[:alnum:]_]|$)
plan-section	i	all	(plan|design)[[:space:]]+§[[:space:]]*[0-9]+([.][0-9]+)*
author-path	-	private	/Users/[[:alnum:]_.-]+/
private-key	-	private	-----BEGIN ([A-Z]+ )?PRIVATE KEY-----
commit-evidence	i	evidence	(^|[^[:alnum:]_])(commit|revision|at)[[:space:]:]+`[[:xdigit:]]{7,40}`
suite-id	i	evidence	(^|[^[:alnum:]_])(w[0-9]+-[[:alnum:]_-]+|gate[-_][0-9]+)([^[:alnum:]_-]|$)
gate-count	i	evidence	(^|[^[:alnum:]_])[0-9]+(/[0-9]+)?[[:space:]]+(gate[[:space:]]+)?(checks|gates|suites)[[:space:]]+(passed|passing|green)([^[:alnum:]_]|$)
EOF
)
tab=$(printf '\t')
bad=0
tmp=$(mktemp) || exit 2
trap 'rm -f "$tmp"' EXIT

# check <file> <scopes>: run the rules whose scope is in <scopes>
check() {
	# the evidence rules and the link check skip fenced code blocks; blank those lines to keep line numbers
	awk '/^[[:space:]]*(```|~~~)/ { f = !f; print ""; next } { print (f ? "" : $0) }' "$1" > "$tmp"
	while IFS=$tab read -r name flags scope re; do
		case " $2 " in *" $scope "*) ;; *) continue ;; esac
		in=$1
		[ "$scope" = evidence ] && in=$tmp
		if [ "$flags" = i ]; then hits=$(LC_ALL=C grep -En -i -e "$re" "$in"); else hits=$(LC_ALL=C grep -En -e "$re" "$in"); fi
		for n in $(printf '%s\n' "$hits" | cut -d: -f1); do
			echo "$1:$n: $name"
			bad=1
		done
	done <<EOF
$rules
EOF
}

# links <file>: every relative link, image and reference definition must name a file that exists
links() {
	dir=$(dirname "$1")
	awk '{
		s = $0
		while (match(s, /\]\([^)[:space:]]+\)/)) { print NR "\t" substr(s, RSTART + 2, RLENGTH - 3); s = substr(s, RSTART + RLENGTH) }
		s = $0
		while (match(s, /(src|href)="[^"]+"/)) { t = substr(s, RSTART, RLENGTH); sub(/^[a-z]+="/, "", t); sub(/"$/, "", t); print NR "\t" t; s = substr(s, RSTART + RLENGTH) }
		if (match($0, /^\[[^]]+\]:[[:space:]]+[^[:space:]]+/)) { t = $0; sub(/^\[[^]]+\]:[[:space:]]+/, "", t); sub(/[[:space:]].*/, "", t); print NR "\t" t }
	}' "$tmp" > "$tmp.links"
	while IFS=$tab read -r n target; do
		case $target in http://* | https://* | mailto:* | '#'*) continue ;; esac
		path=${target%%#*}
		[ -e "$dir/$path" ] && continue
		echo "$1:$n: broken-link $target"
		bad=1
	done < "$tmp.links"
	rm -f "$tmp.links"
}

for f do
	case $f in
	*Testing-and-Gates.md) check "$f" "all private" ;;
	*) check "$f" "all private evidence" ;;
	esac
	links "$f"
done
for f in $design; do
	check "$f" private
done
exit $bad

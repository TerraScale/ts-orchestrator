#!/usr/bin/env bash
# Rank the tests CI retried and passed ("race flaky" lines in the flakes-*
# artifacts of race shards) over the last seven days:
# flaky-report.sh <output file>
set -euo pipefail
out=${1:?usage: flaky-report.sh <output file>}
since=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
: > "$work/flakes"
gh api --paginate "repos/${GITHUB_REPOSITORY:?}/actions/artifacts?per_page=100" \
	--jq ".artifacts[] | select((.name | startswith(\"flakes-\")) and .created_at >= \"$since\" and (.expired | not)) | .id" |
	while read -r id; do
		gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$id/zip" > "$work/$id.zip"
		unzip -p "$work/$id.zip" >> "$work/flakes"
	done
# "<retries> <package> <tests>", most retried first.
sed -n 's/^race flaky //p' "$work/flakes" | sort | uniq -c | sort -k1,1nr > "$out"
printf 'flaky tests since %s:\n' "$since"
cat "$out"

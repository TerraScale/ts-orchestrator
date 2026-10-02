#!/usr/bin/env bash
# Check that every committed *_templ.go file is exactly what the pinned templ
# generator (the go.mod tool directive) produces from its .templ source, and
# that the sources are templ-formatted. Generation runs on a scratch copy so
# this check never rewrites the tree while other ci-verify jobs compile it.
set -euo pipefail

# GO may be a command with arguments, such as "mise exec -- go".
read -r -a go <<< "${GO:-go}"
root=$(pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

mapfile -d '' sources < <(find . -type f -name '*.templ' -not -path './.git/*' -not -path './third_party/*' -print0)
if [ "${#sources[@]}" -eq 0 ]; then
	exit 0
fi
for source in "${sources[@]}"; do
	mkdir -p "$scratch/$(dirname "$source")"
	cp "$source" "$scratch/$source"
done

status=0
if ! (cd "$scratch" && "${go[@]}" -C "$root" tool templ fmt -fail "$scratch" >/dev/null 2>&1); then
	echo 'templ sources need formatting: run make generate' >&2
	status=1
fi
# Formatting the scratch copy must not change what generation sees, so
# regenerate from pristine copies.
for source in "${sources[@]}"; do
	cp "$source" "$scratch/$source"
done
"${go[@]}" tool templ generate -path "$scratch" >/dev/null 2>&1 || {
	"${go[@]}" tool templ generate -path "$scratch" >&2 || true
	echo 'templ generation failed' >&2
	exit 1
}
for source in "${sources[@]}"; do
	generated="${source%.templ}_templ.go"
	if ! cmp -s "$scratch/$generated" "$generated"; then
		echo "$generated is stale: run make generate" >&2
		status=1
	fi
done
# A generated file whose source was removed is stale too.
while IFS= read -r -d '' generated; do
	if [ ! -f "${generated%_templ.go}.templ" ]; then
		echo "$generated has no .templ source" >&2
		status=1
	fi
done < <(find . -type f -name '*_templ.go' -not -path './.git/*' -not -path './third_party/*' -print0)
exit "$status"

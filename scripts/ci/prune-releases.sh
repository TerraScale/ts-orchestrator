#!/usr/bin/env bash
set -euo pipefail

fail() { echo "$*" >&2; exit 1; }
[[ $# == 2 ]] || { echo "usage: $0 REPOSITORY PINS" >&2; exit 2; }
repository=$1 pins_file=$2
[[ $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "invalid repository $repository"
: "${GH_TOKEN:?GitHub token is required}"
export GH_HOST=github.com
keep=${TS_PRUNE_KEEP:-20} keep_days=${TS_PRUNE_KEEP_DAYS:-7} dry_run=${TS_PRUNE_DRY_RUN:-false}
[[ $keep =~ ^[0-9]+$ && $keep_days =~ ^[0-9]+$ && $dry_run =~ ^(true|false)$ ]] ||
	fail 'TS_PRUNE_KEEP and TS_PRUNE_KEEP_DAYS must be numbers, TS_PRUNE_DRY_RUN true or false'

mapfile -t pins < <(grep -oE '\b((ci|image)-[0-9a-f]{40}-run-[0-9]+(-attempt-[0-9]+)?|[0-9a-f]{64}|[0-9a-f]{40})\b' \
	"$pins_file" | sort -u)
((${#pins[@]} > 0)) || fail "$pins_file names no pin; refusing to prune without the live releases"
declare -A pinned
for pin in "${pins[@]}"; do pinned[$pin]=1; done
echo "pins: ${pins[*]}"

umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
echo '[]' > "$work/releases.json"
for ((page = 1; ; page++)); do
	gh api "repos/$repository/releases?per_page=50&page=$page" > "$work/page.json"
	[[ $(jq length "$work/page.json") == 0 ]] && break
	jq -s 'add' "$work/releases.json" "$work/page.json" > "$work/all.json"
	mv "$work/all.json" "$work/releases.json"
done

cutoff=$(date -u -d "-$keep_days days" +%s)
draft_cutoff=$(date -u -d '-1 day' +%s)
jq -c --argjson draft_cutoff "$draft_cutoff" --argjson keep "$keep" --argjson cutoff "$cutoff" '
	[.[] | select(.prerelease and (.tag_name | test("^(ci|image)-[0-9a-f]{40}-run-[0-9]+(-attempt-[0-9]+)?$")))]
	| ((map(select(.draft | not)) | sort_by(.published_at) | reverse | .[$keep:][]),
		(.[] | select(.draft)))
	| select(if .draft then (.created_at | fromdateiso8601) < $draft_cutoff
		else (.published_at | fromdateiso8601) < $cutoff end)
	| {id, draft, tag: .tag_name, published_at: (.published_at // .created_at), bytes: ([.assets[].size] | add // 0),
		manifests: [.assets[] | select((.name | test("(\\.json|\\.sha256|^SHA256SUMS)$")) and .size <= 1048576)
			| .name]}' "$work/releases.json" > "$work/candidates.json"

names_pin() {
	local tag=$1 name word
	shift
	[[ -n ${pinned[$tag]:-} || -n ${pinned[$(cut -d- -f2 <<< "$tag")]:-} ]] && return 0
	for name in "$@"; do
		rm -f -- "$work/manifest"
		gh release download "$tag" --repo "$repository" --pattern "$name" --output "$work/manifest" || { echo "kept $tag: cannot read $name" >&2; return 0; }
		for word in $(grep -oE '\b[0-9a-f]{64}\b' "$work/manifest" || true); do
			[[ -n ${pinned[$word]:-} ]] && return 0
		done
	done
	return 1
}

deleted=0 freed=0 kept=0
while IFS= read -r release; do
	tag=$(jq -r .tag <<< "$release")
	mapfile -t manifests < <(jq -r '.manifests[]' <<< "$release")
	if [[ $(jq -r .draft <<< "$release") == false ]] && names_pin "$tag" "${manifests[@]}"; then
		echo "kept $tag: pinned"
		kept=$((kept + 1))
		continue
	fi
	bytes=$(jq -r .bytes <<< "$release")
	if [[ $dry_run == false ]]; then
		gh api --method DELETE "repos/$repository/releases/$(jq -r .id <<< "$release")"
	fi
	echo "deleted $tag published=$(jq -r .published_at <<< "$release") bytes=$bytes dry_run=$dry_run"
	deleted=$((deleted + 1)) freed=$((freed + bytes))
done < "$work/candidates.json"
printf 'TS_RELEASE_PRUNE repository=%s releases=%s deleted=%s kept_pinned=%s bytes=%s dry_run=%s\n' \
	"$repository" "$(jq length "$work/releases.json")" "$deleted" "$kept" "$freed" "$dry_run"

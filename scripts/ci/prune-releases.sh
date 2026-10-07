#!/usr/bin/env bash
# Delete old CI pre-releases of one repository through the Forgejo API (TS-608),
# which also removes their attachments from the ts-forgejo bucket. Git tags
# stay. CI pre-releases are the ci-<sha>-run-<id> and
# image-<sha>-run-<id>-attempt-<n> releases; every other release is left alone.
#
# usage: prune-releases.sh REPOSITORY PINS
#   REPOSITORY  owner/name, e.g. TerraScale/ts-orchestrator
#   PINS        file of pinned source revisions (40 hex), binary digests
#               (64 hex) and release tags, separated by any whitespace or
#               JSON; it must name at least one pin
#
# Kept: the newest TS_PRUNE_KEEP (default 20) CI pre-releases, any created in
# the last TS_PRUNE_KEEP_DAYS (default 7) days, and any release whose tag
# names a pinned revision or tag, or whose small manifests (*.json, *.sha256,
# SHA256SUMS) name a pinned digest. A manifest that cannot be read keeps its
# release. TS_PRUNE_DRY_RUN=true only logs. Environment: FORGEJO_SERVER_URL
# and FORGEJO_TOKEN, which may delete the repository's releases.
set -euo pipefail

fail() { echo "$*" >&2; exit 1; }
[[ $# == 2 ]] || { echo "usage: $0 REPOSITORY PINS" >&2; exit 2; }
repository=$1 pins_file=$2
[[ $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "invalid repository $repository"
: "${FORGEJO_SERVER_URL:?Forgejo server URL is required}"
: "${FORGEJO_TOKEN:?Forgejo token is required}"
keep=${TS_PRUNE_KEEP:-20} keep_days=${TS_PRUNE_KEEP_DAYS:-7} dry_run=${TS_PRUNE_DRY_RUN:-false}
[[ $keep =~ ^[0-9]+$ && $keep_days =~ ^[0-9]+$ && $dry_run =~ ^(true|false)$ ]] ||
	fail 'TS_PRUNE_KEEP and TS_PRUNE_KEEP_DAYS must be numbers, TS_PRUNE_DRY_RUN true or false'

# A pin is any revision, digest or CI tag in the file: the same words whether
# it is fleet-status JSON or a plain list.
mapfile -t pins < <(grep -oE '\b((ci|image)-[0-9a-f]{40}-run-[0-9]+(-attempt-[0-9]+)?|[0-9a-f]{64}|[0-9a-f]{40})\b' \
	"$pins_file" | sort -u)
((${#pins[@]} > 0)) || fail "$pins_file names no pin; refusing to prune without the live releases"
declare -A pinned
for pin in "${pins[@]}"; do pinned[$pin]=1; done
digest_pins=$(printf '%s\n' "${pins[@]}" | grep -cE '^[0-9a-f]{64}$' || true)
echo "pins: ${pins[*]}"

umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# curl reads the token from a private config file, never from its arguments,
# and drops the header on a redirect to another host.
printf 'header = "Authorization: token %s"\n' "$FORGEJO_TOKEN" > "$work/auth"
unset FORGEJO_TOKEN
api="${FORGEJO_SERVER_URL%/}/api/v1/repos/$repository"
forgejo() { curl -fsS --retry 3 -K "$work/auth" "$@"; }

echo '[]' > "$work/releases.json"
for ((page = 1; ; page++)); do
	forgejo "$api/releases?draft=false&limit=50&page=$page" > "$work/page.json"
	[[ $(jq length "$work/page.json") == 0 ]] && break
	jq -s 'add' "$work/releases.json" "$work/page.json" > "$work/all.json"
	mv "$work/all.json" "$work/releases.json"
done

cutoff=$(date -u -d "-$keep_days days" +%s)
# Candidates: CI pre-releases past the newest $keep and older than the cutoff.
jq -c --argjson keep "$keep" --argjson cutoff "$cutoff" '
	[.[] | select(.prerelease and (.tag_name | test("^(ci|image)-[0-9a-f]{40}-run-[0-9]+(-attempt-[0-9]+)?$")))]
	| sort_by(.created_at) | reverse | .[$keep:][]
	| select((.created_at | fromdateiso8601) < $cutoff)
	| {id, tag: .tag_name, created_at, bytes: ([.assets[].size] | add // 0),
		manifests: [.assets[] | select((.name | test("(\\.json|\\.sha256|^SHA256SUMS)$")) and .size <= 1048576)
			| .browser_download_url]}' "$work/releases.json" > "$work/candidates.json"

# names_pin TAG MANIFEST_URL...: whether the release is pinned; an unreadable
# manifest counts as pinned.
names_pin() {
	local tag=$1 url word
	shift
	[[ -n ${pinned[$tag]:-} || -n ${pinned[$(cut -d- -f2 <<< "$tag")]:-} ]] && return 0
	((digest_pins > 0)) || return 1
	for url in "$@"; do
		forgejo -L "$url" -o "$work/manifest" || { echo "kept $tag: cannot read $url" >&2; return 0; }
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
	if names_pin "$tag" "${manifests[@]}"; then
		echo "kept $tag: pinned"
		kept=$((kept + 1))
		continue
	fi
	bytes=$(jq -r .bytes <<< "$release")
	if [[ $dry_run == false ]]; then
		forgejo -X DELETE "$api/releases/$(jq -r .id <<< "$release")"
	fi
	echo "deleted $tag created=$(jq -r .created_at <<< "$release") bytes=$bytes dry_run=$dry_run"
	deleted=$((deleted + 1)) freed=$((freed + bytes))
done < "$work/candidates.json"
printf 'TS_RELEASE_PRUNE_V1 repository=%s releases=%s deleted=%s kept_pinned=%s bytes=%s dry_run=%s\n' \
	"$repository" "$(jq length "$work/releases.json")" "$deleted" "$kept" "$freed" "$dry_run"

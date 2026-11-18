#!/usr/bin/env bash
set -euo pipefail

[[ $# == 1 && $1 =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "usage: $0 REPOSITORY" >&2; exit 2; }
: "${GH_TOKEN:?GitHub token is required}"
export GH_HOST=github.com
repository=$1
cutoff=$(date -u -d '-1 day' +%s)
umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

gh api --paginate --slurp "repos/$repository/releases?per_page=100" > "$work/pages.json"
jq -r --argjson cutoff "$cutoff" '
  .[][] | select(.draft and .prerelease and
    (.tag_name | test("^(ci|image)-[0-9a-f]{40}-run-[0-9]+(-attempt-[0-9]+)?$")) and
    (.created_at | fromdateiso8601) < $cutoff) | .id' "$work/pages.json" > "$work/ids"

while IFS= read -r id; do
    gh api "repos/$repository/releases/$id" > "$work/current.json"
    state=$(jq -er --argjson cutoff "$cutoff" '
      if (.draft | type) != "boolean" then error("release draft state unavailable")
      elif .draft and (.created_at | fromdateiso8601) < $cutoff then "expired"
      else "keep" end' "$work/current.json")
    if [[ $state != expired ]]; then
        echo "kept release $id: no longer an expired draft"
        continue
    fi
    gh api --method DELETE "repos/$repository/releases/$id"
    echo "deleted expired draft $(jq -r .tag_name "$work/current.json")"
done < "$work/ids"

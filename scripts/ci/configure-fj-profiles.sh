#!/usr/bin/env bash
# Create private fj profiles for a CI job under DIRECTORY:
#   DIRECTORY/read        fj data home authenticated with FORGEJO_READ_TOKEN
#   DIRECTORY/read-token  the read token, for Actions API calls with curl
#   DIRECTORY/write       fj data home authenticated with FORGEJO_WRITE_TOKEN
# Select a profile per command with XDG_DATA_HOME. Tokens never reach argv.
set -euo pipefail

directory=${1:-}
[[ -n $directory && $# == 1 ]] || { echo "usage: $0 DIRECTORY" >&2; exit 2; }
: "${FORGEJO_READ_TOKEN:?Forgejo read token is required}"
: "${FORGEJO_WRITE_TOKEN:?Forgejo write token is required}"
: "${FORGEJO_SERVER_URL:?Forgejo server URL is required}"
command -v fj >/dev/null || { echo 'fj is required' >&2; exit 1; }

umask 077
[[ ! -e $directory ]] || { echo "profile directory already exists: $directory" >&2; exit 1; }
mkdir -m 0700 "$directory" "$directory/read" "$directory/write"
printf '%s\n' "$FORGEJO_READ_TOKEN" > "$directory/read-token"
for profile in read write; do
	token_variable="FORGEJO_${profile^^}_TOKEN"
	if ! printf '%s\n' "${!token_variable}" | XDG_DATA_HOME="$directory/$profile" \
		fj auth add-token --host "$FORGEJO_SERVER_URL" >/dev/null 2>&1; then
		echo "fj could not configure the $profile profile" >&2
		exit 1
	fi
done
echo "fj read and write profiles configured under $directory"

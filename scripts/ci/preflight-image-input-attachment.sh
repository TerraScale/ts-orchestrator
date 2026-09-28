#!/usr/bin/env bash
set -euo pipefail

for tool in fj jq; do
	command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

: "${FORGEJO_READ_TOKEN:?Forgejo read token is required}"
: "${FORGEJO_SERVER_URL:?Forgejo server URL is required}"
: "${IMAGE_INPUT_TAG:?image-input release tag is required}"
: "${IMAGE_INPUT_MANIFEST_SHA256:?image-input manifest SHA-256 is required}"
: "${IMAGE_INPUT_MANIFEST_BYTES:?image-input manifest byte count is required}"

[[ $IMAGE_INPUT_TAG =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ &&
	$IMAGE_INPUT_MANIFEST_SHA256 =~ ^[0-9a-f]{64}$ &&
	$IMAGE_INPUT_MANIFEST_BYTES =~ ^[1-9][0-9]*$ ]] || {
	echo 'invalid image-input tag, manifest SHA-256, or byte count' >&2
	exit 2
}
[[ ${RUNNER_TEMP:-/tmp} == /* ]] || {
	echo 'RUNNER_TEMP must be an absolute path' >&2
	exit 2
}

umask 077
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/image-input-preflight.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
read_profile="$work/fj-read-auth"
mkdir -m 0700 "$read_profile"
read_token=$FORGEJO_READ_TOKEN
unset FORGEJO_READ_TOKEN FORGEJO_TOKEN GITHUB_TOKEN
fj_read() { XDG_DATA_HOME="$read_profile" fj "$@"; }
if ! printf '%s\n' "$read_token" | fj_read auth add-token --host "$FORGEJO_SERVER_URL" \
	>/dev/null 2>"$work/auth.stderr"; then
	echo 'pinned fj could not configure temporary read authentication' >&2
	exit 1
fi
read_token=
unset read_token

set +e
probe_json=$(fj_read --host "$FORGEJO_SERVER_URL" release --repo TerraScale/ts-orchestrator \
	asset probe "$IMAGE_INPUT_TAG" image-inputs.json \
	--expect-sha256 "$IMAGE_INPUT_MANIFEST_SHA256" \
	--expect-bytes "$IMAGE_INPUT_MANIFEST_BYTES" --compare-anonymous \
	2>"$work/probe.stderr")
probe_status=$?
set -e

if [[ -z $probe_json ]]; then
	echo 'pinned fj attachment probe produced no diagnostic JSON' >&2
	exit 1
fi

if ! safe_probe_json=$(jq -ce --arg tag "$IMAGE_INPUT_TAG" '
  def safe_origin:
    type == "string" and test("^https?://[^/?#@[:space:]]+$");
  def optional_origin: . == null or safe_origin;
  def optional_bool: . == null or type == "boolean";
  def optional_string: . == null or type == "string";
  def optional_id: . == null or (type == "number" and floor == . and . > 0);
  def optional_status:
    . == null or (type == "number" and floor == . and . >= 100 and . <= 599);
  def optional_bytes:
    . == null or (type == "number" and floor == . and . >= 0 and . <= 9007199254740991);
  def optional_digest: . == null or (type == "string" and test("^[0-9a-f]{64}$"));
  def optional_error:
    . == null or IN(
      "invalid_expected_sha256", "expected_bytes_out_of_bounds", "invalid_server_url",
      "api_client_error", "metadata_timeout", "metadata_error",
      "release_metadata_incomplete", "asset_not_found", "asset_metadata_mismatch",
      "asset_metadata_incomplete", "legacy_url_error", "advertised_url_missing",
      "invalid_advertised_url", "origin_mismatch", "authorization_unavailable",
      "size_mismatch", "sha256_mismatch", "client_error", "authorization_error",
      "request_build_error", "redirect_state", "body_too_large", "timeout",
      "redirect_error", "connection_error", "body_error", "request_error", "http_status",
      "body_budget_exhausted"
    );
  def safe_redirects:
    type == "array" and length <= 5 and all(.[]; safe_origin);
  if .schema != "terrascale.fj-attachment-probe.v1" or
     (.repository.private | optional_bool | not) or
     (.release.tag | optional_string | not) or
     (.release.draft | optional_bool | not) or
     (.release.prerelease | optional_bool | not) or
     (.release.id | optional_id | not) or
     (.asset.name | optional_string | not) or
     (.asset.size | optional_bytes | not) or
     (.asset.id | optional_id | not) or
     (.server_version != null and
       (.server_version | type != "string" or test("^[A-Za-z0-9._+-]{1,128}$") | not)) or
     (.url_comparison.origin_equal | optional_bool | not) or
     (.url_comparison.path_equal | optional_bool | not) or
     (.url_comparison.query_equal | optional_bool | not) or
     (.authenticated.sent_authorization | type != "boolean") or
     (.authenticated.status | optional_status | not) or
     (.authenticated.initial_origin | optional_origin | not) or
     (.authenticated.final_origin | optional_origin | not) or
     (.authenticated.redirect_count | type != "number" or floor != . or . < 0 or . > 5) or
     (.authenticated.redirect_origins | safe_redirects | not) or
     (.authenticated.body_bytes | optional_bytes | not) or
     (.authenticated.body_sha256 | optional_digest | not) or
     (.authenticated.matches_expected | type != "boolean") or
     (.authenticated.error | optional_error | not) or
     (.anonymous.skipped | type != "boolean") or
     (.anonymous.status | optional_status | not) or
     (.anonymous.initial_origin | optional_origin | not) or
     (.anonymous.final_origin | optional_origin | not) or
     (.anonymous.redirect_count | type != "number" or floor != . or . < 0 or . > 5) or
     (.anonymous.redirect_origins | safe_redirects | not) or
     (.anonymous.body_bytes | optional_bytes | not) or
     (.anonymous.body_sha256 | optional_digest | not) or
     (.anonymous.error | optional_error | not)
  then error("unsafe or malformed probe report")
  else {
    schema: .schema,
    repository: {private: .repository.private},
    server_version: .server_version,
    release: {
      tag: (if .release.tag == $tag then $tag else null end),
      draft: .release.draft,
      prerelease: .release.prerelease,
      id: .release.id
    },
    asset: {
      name: (if .asset.name == "image-inputs.json" then "image-inputs.json" else null end),
      size: .asset.size,
      id: .asset.id
    },
    url_comparison: .url_comparison,
    authenticated: {
      status: .authenticated.status,
      sent_authorization: .authenticated.sent_authorization,
      initial_origin: .authenticated.initial_origin,
      final_origin: .authenticated.final_origin,
      redirect_count: .authenticated.redirect_count,
      redirect_origins: .authenticated.redirect_origins,
      body_bytes: .authenticated.body_bytes,
      body_sha256: .authenticated.body_sha256,
      matches_expected: .authenticated.matches_expected,
      error: .authenticated.error
    },
    anonymous: {
      status: .anonymous.status,
      skipped: .anonymous.skipped,
      initial_origin: .anonymous.initial_origin,
      final_origin: .anonymous.final_origin,
      redirect_count: .anonymous.redirect_count,
      redirect_origins: .anonymous.redirect_origins,
      body_bytes: .anonymous.body_bytes,
      body_sha256: .anonymous.body_sha256,
      error: .anonymous.error
    }
  }
  end
' <<<"$probe_json" 2>"$work/probe-jq.stderr"); then
	echo 'pinned fj attachment probe returned an unsafe or malformed report' >&2
	exit 1
fi
printf '%s\n' "$safe_probe_json"

if ! jq -e --arg tag "$IMAGE_INPUT_TAG" \
	--arg sha256 "$IMAGE_INPUT_MANIFEST_SHA256" \
	--argjson bytes "$IMAGE_INPUT_MANIFEST_BYTES" '
  .schema == "terrascale.fj-attachment-probe.v1" and
  .release.tag == $tag and .release.draft == false and
  .asset.name == "image-inputs.json" and
  .asset.size == $bytes and
  .authenticated.sent_authorization == true and
  .authenticated.status == 200 and
  .authenticated.matches_expected == true and
  .authenticated.body_bytes == $bytes and
  .authenticated.body_sha256 == $sha256 and
  (.repository.private == false or .anonymous.skipped == true)
' <<<"$safe_probe_json" >/dev/null 2>"$work/probe-gate.stderr"; then
	echo 'authenticated image-input attachment did not match its pinned digest and size' >&2
	exit 1
fi

if (( probe_status != 0 )); then
	echo 'pinned fj attachment probe reported an authenticated request failure' >&2
	exit "$probe_status"
fi

echo 'authenticated image-input attachment matches the pinned digest and size'

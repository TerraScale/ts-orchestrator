#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ -n "${REPOSITORY:-}" ]; then
    : "${DOCKER_CONFIG:?repository-scoped login requires DOCKER_CONFIG}"
    test ! -e "$DOCKER_CONFIG/config.json"
    mkdir -p "$DOCKER_CONFIG"
    printf '%s\n' '{"auths":{}}' > "$DOCKER_CONFIG/config.json"
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
jwt=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=terrascale-ocir" | jq -r .value)
echo "::add-mask::$jwt"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/key.pem" 2>/dev/null
public_key=$(openssl pkey -in "$work/key.pem" -pubout -outform DER | base64 -w0)
upst=$(curl -sSf -u "$CLIENT_ID:$CLIENT_SECRET" "$DOMAIN_URL/oauth2/v1/token" \
    --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    --data-urlencode requested_token_type=urn:oci:token-type:oci-upst \
    --data-urlencode subject_token_type=jwt \
    --data-urlencode "subject_token=$jwt" \
    --data-urlencode "public_key=$public_key" | jq -r .token)
echo "::add-mask::$upst"
region_login_seconds=30
run_region() {
    local region=$1
    shift
    local status=0
    timeout "${region_login_seconds}s" "$@" || status=$?
    if [[ $status -eq 124 ]]; then
        echo "$region: OCIR login timed out" >&2
        exit 1
    fi
    if [[ $status -ne 0 ]]; then
        echo "$region: OCIR login failed" >&2
        exit "$status"
    fi
}
read -r -a regions <<< "$REGIONS"
for region in "${regions[@]}"; do
    host="$region.ocir.io"
    target=/20180419/docker/token
    scope=
    if [ -n "${REPOSITORY:-}" ]; then
        scope="repository:$REPOSITORY:pull,push"
        encoded_scope=$(printf '%s' "$scope" | jq -sRr @uri)
        target="$target?scope=$encoded_scope&service=$host"
    fi
    date=$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S GMT')
    signature=$(printf 'date: %s\n(request-target): get %s\nhost: %s' "$date" "$target" "$host" | openssl dgst -sha256 -sign "$work/key.pem" | base64 -w0)
    run_region "$region" curl -sSf -H "date: $date" \
        -H "Authorization: Signature version=\"1\",headers=\"date (request-target) host\",keyId=\"ST\$$upst\",algorithm=\"rsa-sha256\",signature=\"$signature\"" \
        -o "$work/token.json" "https://$host$target"
    jq -e --arg scope "$scope" '.scope == $scope and (.token | type == "string" and length > 0)' "$work/token.json" > /dev/null
    token=$(jq -er .token "$work/token.json")
    echo "::add-mask::$token"
    if [ -n "${REPOSITORY:-}" ]; then
        jq --arg host "$host" --slurpfile token "$work/token.json" \
            '.auths[$host] = {registrytoken: $token[0].token}' "$DOCKER_CONFIG/config.json" > "$work/config.json"
        mv "$work/config.json" "$DOCKER_CONFIG/config.json"
    else
        run_region "$region" docker login "$host" -u BEARER_TOKEN --password-stdin <<<"$token"
    fi
done

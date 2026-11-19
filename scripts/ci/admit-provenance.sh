#!/usr/bin/env bash
set -euo pipefail

repository=${GITHUB_REPOSITORY:?}
sha=${GITHUB_SHA:?}
run=${GITHUB_RUN_ID:?}
tag="ci-${sha}-run-${run}"
amd64=dist/terrascale-orchestrator-linux-amd64
arm64=dist/terrascale-orchestrator-linux-arm64
bundle=dist/provenance.sigstore.json

verify() {
    python3 -c 'import base64, hashlib, json, sys
bundle = json.load(open(sys.argv[1]))
envelope = bundle.get("dsseEnvelope") or bundle
payload = envelope["payload"]
payload += "=" * (-len(payload) % 4)
statement = json.loads(base64.b64decode(payload))
subjects = {item["name"].rsplit("/", 1)[-1]: item["digest"]["sha256"] for item in statement["subject"]}
for path in sys.argv[2:]:
    name = path.rsplit("/", 1)[-1]
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    attested = subjects.get(name)
    if attested != digest:
        raise SystemExit(f"{name} is {digest}, attestation has {attested}")
' "$@"
}

view() {
    gh release view "$tag" --repo "$repository" --json isDraft,targetCommitish,assets
}

has_provenance() {
    jq -e 'any(.assets[]; .name == "provenance.sigstore.json" and .state == "uploaded" and .size > 0)' >/dev/null
}

reuse_provenance() {
    if [[ ! -e $bundle ]]; then
        gh release download "$tag" --repo "$repository" --pattern provenance.sigstore.json --output "$bundle"
    fi
    verify "$bundle" "$amd64" "$arm64"
}

case ${1:?} in
check)
    release=$(view)
    if jq -e 'any(.assets[]; .name == "provenance.sigstore.json" and .state == "uploaded" and .size > 0)' <<<"$release" >/dev/null; then
        reuse_provenance
        echo "need_attest=false" >> "$GITHUB_OUTPUT"
    else
        echo "need_attest=true" >> "$GITHUB_OUTPUT"
    fi
    if jq -e '.isDraft == true' <<<"$release" >/dev/null; then
        echo "draft=true" >> "$GITHUB_OUTPUT"
    else
        echo "draft=false" >> "$GITHUB_OUTPUT"
    fi
    ;;
finalize)
    release=$(view)
    draft=$(jq -r '.isDraft' <<<"$release")
    if has_provenance <<<"$release"; then
        reuse_provenance
    else
        [[ $draft == true ]]
        [[ -n ${BUNDLE:-} && -f $BUNDLE ]]
        cp "$BUNDLE" "$bundle"
        gh release upload "$tag" "$bundle" --repo "$repository"
        readback=${RUNNER_TEMP:-/tmp}/provenance.sigstore.json
        gh release download "$tag" --repo "$repository" --pattern provenance.sigstore.json --output "$readback"
        cmp "$bundle" "$readback"
        verify "$bundle" "$amd64" "$arm64"
    fi
    if [[ $draft == true ]]; then
        gh release view "$tag" --repo "$repository" --json targetCommitish,assets |
            jq -e --arg sha "$sha" '
              .targetCommitish == $sha and
              ([.assets[] | select(.state == "uploaded" and .size > 0) | .name] |
                contains(["terrascale-orchestrator-linux-amd64", "terrascale-orchestrator-linux-arm64",
                  "qualification.json", "provenance.sigstore.json"]))' >/dev/null
        gh release edit "$tag" --repo "$repository" --draft=false
    fi
    test "$(gh api "repos/$repository/commits/$tag" --jq .sha)" = "$sha"
    ;;
verify)
    shift
    verify "$@"
    ;;
*)
    echo "usage: admit-provenance.sh check|finalize|verify <bundle> <files>" >&2
    exit 2
    ;;
esac

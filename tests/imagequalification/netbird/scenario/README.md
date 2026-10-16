The native NetBird worker is the `internal/netbird/foundation` test binary. It
uses real upstream processes on explicitly admitted disposable image hosts.
The replacement-host ObjectStore is a signed OCI SDK HTTPS fixture; it does not
prove provider KMS encryption, retention enforcement, or regional durability.

Go omits VCS settings from test binaries. The approved producer therefore
stamps the exact candidate source commit into a **test-only** linker variable.
This stamp is producer metadata, not runtime source attestation. The signed
finite approval must still bind the exact worker executable SHA-256; a matching
source stamp alone grants no execution authority. There is no environment or
runtime argument that overrides the stamp.

Build only from a clean checkout of the exact candidate commit. `candidate_revision`
is the already authenticated candidate's 40-character lowercase Git SHA, and
`artifact_dir` is an existing directory outside the checkout. Obtain the QA
build lease before running the build locally.

```sh
test "$(git rev-parse HEAD)" = "$candidate_revision"
test -z "$(git status --porcelain)"
nice -n 19 go test -c -mod=readonly -trimpath -buildvcs=false \
  -ldflags "-X github.com/TerraScale/ts-orchestrator/internal/netbird/foundation.nativeQualificationSourceRevision=$candidate_revision" \
  -o "$artifact_dir/netbird-worker" ./internal/netbird/foundation
"$artifact_dir/netbird-worker" build-identity > "$artifact_dir/worker-build-identity.json"
sha256sum "$artifact_dir/netbird-worker" > "$artifact_dir/worker.sha256"
go version > "$artifact_dir/compiler.txt"
go version -m "$artifact_dir/netbird-worker" > "$artifact_dir/build-settings.txt"
```

Retain the candidate source manifest, exact command above, compiler/build settings,
worker artifact, SHA-256, and `build-identity` output. Check the reported revision
against the authenticated candidate and its reported worker hash against the
actual artifact hash before constructing the signed approval. Unstamped or
malformed stamps fail both `build-identity` and `serve`. Every SSH command also
requires its source revision to match that stamp. These checks leave the normal
standalone Swarm worker's build provenance unchanged.

`serve` reads the bounded private NDJSON contract on SSH stdin. The parent retains
only typed public observations; it never retains the credential carrier. Native
host identity and pinned SSH/cloud confinement remain separate required checks.

# Build and release boundaries

The Forgejo workflow checks out the event's exact Git revision and requires a
clean tree. It runs Go formatting checks, tests, `go vet`, and race-enabled
tests using Go 1.27.1. The `terrascale-builder` image supplies that exact Go
version; `.mise.toml` pins the same version for local development.

The artifact job cross-compiles one static executable for Linux amd64 and one
for Linux arm64 with cgo disabled. It checks the ELF machine type, absence of a
dynamic interpreter and linked libraries, the embedded Git revision, and
SHA-256 digests. It prints a `SHA256SUMS` receipt in the job log.

The current Forgejo runner does not retain `upload-artifact` outputs, so this
workflow does not create downloadable release assets. It also does not sign,
publish, or promote production artifacts. Those actions require a separately
authorized release path. The orchestrator's delivery boundary is admission of
the exact signed artifact and rollout by digest; repository CI builds and
tests the source but does not make rollout decisions.

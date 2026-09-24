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

## Local static build receipt

On 2026-09-24, `make release-linux` with Go 1.27.1 built source revision
`df09ee5692b4a5dc60230f019d1265efccb2f972`. Both outputs have the expected
ELF machine, no dynamic interpreter or linked libraries, and embedded
`vcs.modified=false` metadata for that revision. The local checksum receipt
is `dist/SHA256SUMS`.

| Artifact | Size | SHA-256 | Execution evidence |
| --- | ---: | --- | --- |
| `dist/terrascale-orchestrator-linux-amd64` | 21,008,544 bytes | `c577a52bbcd0e8dfbfbe6c3910141b42e9eae9444d0e5c92a97dbe29512c93da` | ELF-verified; Firecracker used its separately hashed harness build |
| `dist/terrascale-orchestrator-linux-arm64` | 19,267,744 bytes | `609d662e38bfe4fdf02b9670809865c9621df185f697e67c3b12f6d8144500f6` | Cross-compiled and ELF-verified; not executed |

These local outputs are not published or signed release assets. The distinct
amd64 binary used in the guest qualification is recorded in [local
development](local-development.md#latest-local-qualification).

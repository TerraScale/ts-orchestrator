# OCI Instance Principal context source patch

Review `runtime.patch` against the unmodified OCI SDK `v65.126.0` archive pinned
by the project's existing `go.sum`. `provenance.json` records upstream hashes,
the seven runtime source changes, and their separate local review commit/tree.
The local review commits are source snapshots, not upstream Oracle releases.

This branch does not adopt a dependency or change `go.mod`/`go.sum`. Its new
project APIs require the runtime patch. A reviewed local runtime snapshot must
be composed before compilation or integration; this source branch alone is not
a deployable dependency closure.

The patch carries caller context through actual metadata HTTP/body reads,
region retry waits, URL certificate refresh, x509 federation serialization,
federation HTTP/retry waits, and the existing SDK signer. Existing background
APIs, certificates, session-key cryptography, tenancy checks, retry counts and
retry durations remain. Optional contextual interfaces cover the genuine x509
Instance Principal path; unrelated OAuth/resource-principal paths gain no claim.
The one `common/client.go` change preserves eager-validation error identity.

Project APIs are `InstancePrincipalContext`, `InstancePrincipalProviderContext`,
`Factory.SecretsContext`, and `vaultsecret.SecretsClientContext`. The shared
factory, region mapping, service limiter and retry policy remain shared.
The private generated-Secrets constructor view clears its construction context
synchronously before returning; both provider views preserve SDK refreshability.
Request signing restores original cancellation while retaining request values
and any shorter outer deadline. Context callbacks cancel only child contexts;
no credential operation or mutex acquisition runs in an abandoned goroutine.

Install `WithCredentialSourceGuard` with a local accepted-snapshot revalidator
before cold acquisition, and preserve normal request guards for dispatch. The
credential guard must not read OCI: it also runs while credential refresh is
serialized. CAP owns that caller migration and must create the same
min(parent deadline, 30 seconds, original snapshot expiry) operation context
before both constructors. Do not reset the budget after construction.
Legacy contextless service constructors remain uncovered acquisition paths.

The existing project `instance_principal_test.go` scenario now includes real
local metadata HTTP and federation/Secrets TLS with generated RSA certificate
rotation, verified request signatures and body hashes, and signed token bytes.
It denies unexpected destinations, exercises header/body/backoff cancellation,
queued acquisition/refresh, constructor-context release, shorter deadlines,
shared-factory convergence, local-source denial, tenancy change and key mismatch.
`upstream-protocol-fixture.patch` extends the existing SDK certificate scenario
with real stalled metadata body/queued refresh cancellation. Upstream test code
is review source only and must stay outside the runtime dependency snapshot.

Standalone formatting and whitespace checks passed. Compilation, tests, runtime,
live OCI and cross-platform dependency qualification have not run. No Security
ACK is claimed by these artifacts.

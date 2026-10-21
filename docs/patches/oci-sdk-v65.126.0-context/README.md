# OCI Instance Principal context source patch

Review `runtime.patch` against the unmodified OCI SDK `v65.126.0` archive pinned
by the project's existing `go.sum`. `provenance.json` records upstream hashes,
the seven runtime source changes, and their separate local review commit/tree.
Patches use zero context and full blob IDs; verify the listed upstream hashes
first, then apply with `git apply --unidiff-zero runtime.patch`.
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
`common/client.go` preserves eager-validation error identity and cancels the
existing one-second refreshable-auth 401 retry waits using the effective
post-interceptor request context, captured in a per-call BaseClient value.
The attempt count and one-second duration are unchanged, including the final
wait; the original interceptor and its errors are preserved.

Project APIs are `InstancePrincipalContext`, `InstancePrincipalProviderContext`,
`Factory.SecretsContext`, and `vaultsecret.SecretsClientContext`. The shared
factory, region mapping, service limiter and retry policy remain shared.
The private generated-Secrets constructor view clears its construction context
synchronously before returning; both provider views preserve SDK refreshability.
Request signing restores original cancellation while retaining request values
and any shorter outer deadline. Each restored child uses the original deadline
timer so DeadlineExceeded remains distinct from manual cancellation. Context
callbacks propagate manual cancellation only and cancel only child contexts;
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
queued acquisition/refresh (observed at the real held-lock select before cancel),
constructor-context release, shorter deadlines,
shared-factory convergence, local-source denial, tenancy change and key mismatch.
`upstream-protocol-fixture.patch` extends the existing SDK certificate scenario
with real stalled metadata body/queued refresh cancellation. The project fixture
also observes EOF on an actual TLS 401 response and requires joined cancellation
before 750 ms, for both detached/generated and direct/no-interceptor calls; that
bound has not been runtime-qualified. Upstream test code
is review source only and must stay outside the runtime dependency snapshot.

Standalone formatting and whitespace checks passed. Compilation, tests, runtime,
live OCI and cross-platform dependency qualification have not run. No Security
ACK is claimed by these artifacts.

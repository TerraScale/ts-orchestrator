# Dedicated NetBird image qualification

`Run` consumes an exact final-image candidate and two independently launched,
private, native ARM64 Compute hosts: a primary and a replacement. The shared
image-qualification parent must first verify signed finite approval, effective
credential confinement, every component archive and the ephemeral SSH host keys.
This package has no cloud credential, production membership or signing authority.

The runner uploads the exact-source test executable, three pinned OCI archives
(`server`, `dashboard`, `ingress`) and the pinned native NetBird client through
the shared fixed-host-key SSH transport. Credentials pass only through protected
SSH stdin; retained transcripts contain typed observations and SHA-256 digests.

The worker lives in `internal/netbird/foundation/native_qualification_test.go` so
it can exercise the actual foundation runtime, bootstrap, production account
policy, enrollment and protected backup/restore without adding production test
hooks. It uses a test-only signed OCI SDK protocol fixture on the replacement
host. Those two fixture regions exercise the SDK protocol and protection checks;
they do not establish geographic durability or real OCI retention enforcement.

`netbird-foundation` requires observed native component identities, closed setup,
separate owner/service subjects, an enrolled peer, policy records, service access,
restart continuity, lost-publication recovery and rejection of the rotated PAT.
Actual TLS 1.3, gRPC status and STUN transaction observations are retained. The
disposable Caddy fixture uses its internal CA to avoid production ACME issuance.

`netbird-recovery` requires verified protected off-host copies, the parent's
authenticated OCI `TERMINATED` observation for the original host, restoration
onto the distinct exact-image replacement, and unchanged account/service/peer,
public peer key, policy and access observations. A stopped process cannot satisfy
the removal requirement. The existing qualifier consumes the returned report and
signs the existing dedicated-role proof only after the actual run succeeds.

Local subprocess fixtures verify protocol rejection and credential exclusion.
They emit no native qualification gates. Actual native execution, paid capacity,
production certificates, real regional storage durability and production NetBird
membership remain pending separately authorized qualification.

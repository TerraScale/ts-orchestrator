# Storage transition receipt Vault provisioning, 2026-09-05

The existing host-secret bootstrap now permits the dedicated root receipt key
at `/etc/terrascale/ts-node-bootstrap/storage-transition-receipt.key`. The seed
bound admits all thirteen allowlisted credentials. Existing pinned-version
fetch, private durable publication, journal retry, and ownership protections
apply to this leaf.

The bootstrap-control compiler requires a configured transition to select that
root-only destination and supply an exact Vault reference. It parses a single
P-256 receipt key and rejects missing keys, public delivery, wrong key types,
owner private keys, reused seeded or regional command keys, and receipt keys
shared across hosts. The later signed transition plan remains responsible for
binding the receipt's public key to the host.

Compiler tests use an actual owner-signed candidate manifest and inspect every
decoded cloud-init file, including gzip/base64 content. They verify the emitted
Vault secret ID, version, and SHA-256 and absence of private receipt bytes.
Host-secret restart/handoff tests now include the receipt leaf. A root test
hands service credentials to UID/GID 65534, checks the receipt remains 0600 and
root-owned, and proves that UID cannot read it.

Validation passed:

- `go test -race ./cmd/orchestrator ./src/orchestrator/hostsecrets`
- Targeted compiler tests after adding decoded-metadata assertions.
- Root/race service ownership handoff; see the adjacent root-race log.
- `make check`; see the adjacent portable log.

This qualifies local compilation and filesystem behavior, not real OCI IAM or
Vault retrieval. The operator must first create the pinned Vault secret/version.
Remote plan delivery, continuous polling, the preparation barrier, transition
execution, and live six-host qualification remain incomplete.

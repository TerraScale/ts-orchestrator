# Phase 1 identity, PKI, and vault decision core

## Predecessor

- Contract steward commit: `a1ecba0`
- PKI algorithms, lifetimes, renewal windows, vault backend/storage, offline-root procedure, and owner secret-retention policy remain explicit inputs.

## Goal

Implement pure enrollment, certificate/identity lifecycle, authorization, revocation, and encrypted-secret lease decisions from `ORCHESTRATOR.md:881-923`. No cryptographic provider or secret store is used.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Security/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Security*.cs`
- `docs/work-packages/handoffs/phase1-identity-vault-core.md`

## Required behavior

- Immutable bounded cell/node/workload/role/issuer/key/certificate/secret/version/lease/operation/attestation identities; positive epochs/generations/sequences; closed principal, usage, trust-scope, revocation, lease, and authorization catalogs.
- Enrollment binds one-time bootstrap evidence, machine/workload attestation, expected cell/role/node generation, current issuer/revocation generation, and single-use operation. Replay, wrong scope/role/generation, stale attestation, or consumed token holds/rejects.
- Issue/renew/rotate/revoke decisions receive explicit caller policy and validity evidence. Regional intermediates cannot issue outside their cell/scope; offline roots cannot be represented as online signing capability; revoked/stale/lower-generation identities never authorize.
- Authorization maps closed principal/role/capability/resource scope only. Default deny; unknown enum, incomplete/duplicate/conflicting evidence, cross-cell access, privilege escalation, or stale revocation view rejects.
- Vault decisions handle encrypted secret metadata/version availability and short-lived lease grant/renew/revoke without accepting plaintext secret bytes or key material. Regional survival may reference exact encrypted versions only inside explicit retention/expiry policy.
- Emit closed typed attest/issue/renew/revoke/grant-lease/renew-lease/revoke-lease/hold intents and stable code/numeric trace. No signature algorithm, crypto operation, private key, plaintext secret, credential, arbitrary claim/text, callback, time read, storage, or I/O.
- Defensive copies; culture/permutation determinism; token replay; cross-cell issuer; stale revocation; rotation overlap; compromise revocation; authorization matrix; secret version rollback; lease expiry evidence; forbidden-shape reflection; and secret-safe tests.
- No crypto/vault/NATS/filesystem/network/clock package, lifetime/default algorithm, owner retention choice, or mutation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`


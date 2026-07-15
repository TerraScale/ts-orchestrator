# Phase 1 identity, PKI, and vault decision core handoff

- Work package predecessor: `a1ecba0`
- Branch starting point: `5315e7d`
- Scope changed: `Security/**`, `Security*.cs` tests, and this handoff only
- Cryptographic operations, secret storage, clocks, files, networks, and external mutations: none

## Result

The control plane now has a pure default-deny decision boundary for enrollment, certificate lifecycle, closed capability authorization, encrypted-secret leases, and regional survival secret references.

Enrollment binds the exact operation, principal, public subject-key identity, cell, role, principal generation, one-time bootstrap audience/status, attestation measurement and policy generation, regional issuer generation, and revocation generation. Consumed bootstrap evidence, stale/missing/conflicting evidence, principal replay, cross-cell reuse, and stale issuer/revocation views cannot emit an identity-issuance intent. Missing but otherwise exact attestation evidence emits only a typed attestation intent.

Certificate issue/renew/rotate/revoke decisions consume explicit caller lifecycle policy and validity evidence. Validity evidence binds certificate, operation, principal, cell, public subject-key identity, usage, trust scope, issuer identity/generation, certificate generation, policy generation, and revocation generation. Regional issuers are structurally cell scoped and cannot request global trust. Renewal and rotation require exact next-generation and caller validity evidence; compromise revocation requires an exact certificate/principal/cell/generation proof.

Authorization requires one complete, unique, consistent principal record; independent expected and current principal generations; independent requested and current policy generations; a current revocation view; one exact current-policy grant; same-cell access; and bounded role/capability semantics. No matching grant is a denial. Untrusted CI cannot read or lease encrypted secrets, and non-operator principals cannot administer global trust even if a forged broader grant is supplied.

Vault decisions contain encrypted metadata only: secret/version/scope/purpose, wrapping-key identity, and ciphertext digest. Grant and renewal bind an exact requested lease identity and require current identity, policy, revocation, exact action-specific grant, retained version, availability, explicit maximum lease duration, and exact existing-lease evidence when applicable. Revocation still requires exact lease/principal/secret digest/scope plus current authorization and revocation evidence, but deliberately does not depend on the encrypted version remaining available/retained, retention-policy expiry, or a duration extension. Regional survival accepts exact encrypted version/digest references only when matching available metadata and a current unexpired retention policy exist.

## Structural exclusions

There is no online root issuer kind, private-key carrier, plaintext/ciphertext byte carrier, secret value, credential value, reveal endpoint, callback, executable text, algorithm choice, crypto operation, clock/time type, storage abstraction, or I/O surface in this package. Subject and wrapping keys are represented only by bounded identities; secret content is represented only by a canonical digest and versioned encrypted metadata.

## Adversarial coverage

Security-prefixed tests cover bootstrap replay and consumption, principal/cell/role/generation replay, stale and missing attestation, duplicate/conflicting evidence, stale issuer and revocation views, cross-cell/global regional issuance, validity-proof replay across principal/key/scope/issuer/operation, renewal/rotation overlap, scoped compromise revocation, authorization default deny and escalation, lower-generation identity evidence even when request and evidence agree, encrypted version rollback, missing/unretained versions, lease duration and expiry, action-specific grants, exact lease renewal/revocation, survival reference mismatch, defensive copies, culture determinism, forbidden shapes, malformed identities/digests, unknown enums, and secret-safe traces.

## Verification

```text
dotnet restore tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --locked-mode
dotnet build tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-restore
dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build
git diff --check
```

The final local suite completed with 130 tests passed, 0 failed, and 0 skipped. The build completed with 0 warnings and 0 errors.

## Deferred adapter and owner inputs

No unresolved pure-core authorization gap was identified at handoff. Signature algorithms, certificate lifetimes/windows/overlap values, vault backend and durability, offline/recovery-root procedure, owner retention policy, attestation verification, atomic bootstrap consumption, cryptographic issuance/revocation, lease persistence, and immediate connection termination remain explicit owner or adapter inputs. Adapters must consume these typed intents and return scoped evidence; they may not introduce policy defaults or weaken generation/scope checks.

## Follow-up accepted-output audit

A later independent audit found two accepted-output gaps in the original handoff. First, attestation evidence did not carry the public subject-key identity, so otherwise exact evidence could be replayed while substituting the key in the enrollment request. Attestation evidence now binds that bounded public key identity, and both valid and missing-attestation flows reject substitution before emitting an issue or attestation intent. The complete enrollment trace has fourteen reasons in fixed order; ambiguous evidence still returns only the original three collection reasons.

Second, exact authorization grants did not close the capability/resource-kind pairing. The authorization boundary now permits only enrollment capabilities on enrollment resources, identity lifecycle capabilities on certificate resources, encrypted-secret reads on encrypted-secret resources, lease capabilities on lease resources, and global-trust administration on trust-bundle resources. This remains part of `PrivilegeBounded`; no new principal-role policy was inferred beyond the existing same-cell, untrusted-CI, and operator global-trust restrictions.

The audit inventoried all closed policy catalogs: 6 principal kinds, 9 roles, 8 certificate usages, 2 trust scopes, 2 issuer kinds, 6 evidence statuses, 3 revocation statuses, 4 validity statuses, 4 certificate actions, 10 authorization capabilities, 5 resource kinds, 4 environments, 6 secret purposes, 4 availability states, 3 lease actions, and 3 lease statuses. Outputs remain construction-closed across 27 stable decision codes, 4 outcomes, and 12 intent types. No plaintext, private-key, credential-value, crypto, clock, storage, or I/O surface was added.

After rebasing onto integration commit `05ad65b`, locked restore and the warnings-as-errors Release build completed with zero warnings and zero errors. The focused Security shard passed 35/35, the complete ControlPlane suite passed 485/485, and all five test projects passed 681/681 (Contract 24, ControlPlane 485, Model 38, Protocol 65, Scheduler 69). `git diff --check` passed.

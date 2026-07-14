# Phase 1 observability managed-projection provenance audit 4

## Scope and base

- Initial audited base: central `chore/phase0-bootstrap` at `a4c561d502dbf3b18aac4e39c86c9eafc36eed65`.
- Final rebased integration base: central `chore/phase0-bootstrap` at `a822241b5b5a7cc95b870307af92b9f845a6c62e`.
- Allowed paths: pure observability/Grafana contracts and decision engine, ControlPlane observability tests, and this work package.
- Pure deterministic L0 projection policy only. No Grafana, telemetry backend, plugin, database, network, filesystem, process, provider, VM, cloud, or deployment side effect was performed.

## Executable defect

`ObservedGrafanaResource` previously represented only resource identity, scope, generation, digest, broad projection kind, and ownership. It could not represent the release or exact reviewed catalog selection that produced a resource. Reconciliation nevertheless treated a managed resource as exact when only kind, digest, and generation matched.

Consequently, an exact managed observation for dashboard `d`, generation `5`, digest `A`, and broad kind `Dashboard` authorized an empty projection for both of these distinct desired resources:

```text
release-a / Dashboard.FleetOverview
release-b / Dashboard.CellHealth
```

Changing only the release or only the same-kind catalog selection still emitted `ProjectionExact = Passed` and no update. `ProjectGrafanaIntent` retained the distinct requests, so this was not an identical-complete-output claim. It was an exact-projection authority defect: the accepted inventory could not prove the release/catalog identity whose checkpoint was allowed to advance.

## Correction

`ManagedGrafanaProjectionProvenance` carries the exact immutable `ObservabilityReleaseId` and structural `GrafanaCatalogSelection`. `ObservedGrafanaResource` enforces one state:

- `ManagedExact` ownership requires non-null managed provenance;
- every non-managed ownership requires null managed provenance; and
- managed provenance selection kind must equal the independently observed broad kind.

Exact managed reconciliation now requires release and full structural selection equality in addition to the existing kind, digest, and generation checks. A release or selection mismatch emits `UpdateGrafanaResource` through the existing authorized path. That change continues to retain the exact desired resource, observed resource, inventory evidence, and request. Unmanaged and conflicting resources remain report-only and can neither be adopted nor deleted.

No decision code, numeric value, trace row, trace order, precedence, authorization entry point, or change kind was added. The correction does not claim that the caller-supplied digest cryptographically binds catalog implementation bytes.

## Evidence

The audit tests execute release-only and same-kind selection-only counterexamples, exact no-op behavior, and all six selection families: dashboard, datasource, folder, alert, contact point, and access policy. Access provenance independently varies entry, access level, role identity, user identity, and subject. A length-delimited invariant fingerprint covers release identity, concrete selection type, kind, catalog entry, every access field, and every closed access-subject variant/identity. Replay is stable across `en-US`, `tr-TR`, and `ar-SA`; desired and inventory permutations converge to the same canonical output.

Constructor tests prove managed ownership if and only if provenance exists, reject kind/provenance disagreement, and preserve unmanaged/conflicting drift behavior. Assembly-wide public-surface inspection pins the four decision factories to `ObservabilityDecisionEngine`, proves decisions/intents/changes have no public constructors or alternate public factories, and pins the observed-resource provenance constructor surface.

The historical replay corpus remains byte-identical with SHA-256 `b725a4b56e7b7afc33a2554d2596713ec84989ca64f70dc9d67f3a507dbdf2e8`. Its v1 projection fingerprint covers the historical change/trace/checkpoint surface and intentionally does not claim managed release/catalog provenance. Audit 4's dedicated complete fingerprint and counterexamples provide that evidence; rewriting the historical fixtures would overstate their original coverage.

## Evidence boundary and nonclaims

This audit proves only how the pure evaluator classifies caller-supplied immutable managed inventory. It does not prove that an adapter can obtain, authenticate, persist, or atomically checkpoint Grafana release/catalog metadata. It does not implement or qualify Grafana provisioning, a data-source plugin, operator authentication, OIDC, telemetry ingestion/query/storage, HA, alert delivery, journal persistence, checkpoint atomicity, ARM64, L0C, L3S/L4, or production deployment.

It introduces no query or configuration text, URL, credential, secret, callback, filesystem path, backend/client SDK, clock, I/O, authority permit, provider mutation, VM, cloud, or deployment surface.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore --nologo -warnaserror
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --disable-logo --no-progress
git diff --check
```

Before the final integration rebase, the focused audit passed 7/7 and the ControlPlane executable passed 608/608 with zero failures or skips. Final exact-tree whole-solution counts are recorded in the integration handoff.

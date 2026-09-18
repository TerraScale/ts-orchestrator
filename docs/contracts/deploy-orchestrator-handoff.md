# Deploy-to-Orchestrator handoff contract (mapping v1)

| | |
| --- | --- |
| Mapping version | **1** |
| Ratified by | `TerraScale.Orchestrator` issue #26 (part of #2; dependency #13) |
| Handoff manifest schema | v1 (`minimum 1`, `maximum 1`) |
| Executable contract | `DeliveryRequest` schema version **1** — `src/TerraScale.Orchestrator/ControlPlane/Delivery/DirectDeliveryContracts.cs` (`DeliveryRequest.CurrentSchemaVersion`) |
| Producing side | `TerraScale.Deploy` — `terrascale-deploy deploy` will publish the version-1 handoff manifest shaped by its public manifest conventions (`docs/public-alpha-handoff.md`, multi-architecture OCI image indexes with preserved digests). Contract-first: this document defines the target shape; `TerraScale/TerraScale.Deploy#1`–`#3` are the tickets that will publish producers for it, so until they land only the fixtures here represent the Deploy side |
| Consuming side | `TerraScale.Orchestrator` issue #3 (direct-delivery runtime) and #6; referenced by `TerraScale/TerraScale.Deploy#1`, `#2`, `#3` |
| Implementation | `src/TerraScale.Orchestrator/Delivery/DeployHandoff/DeployHandoffMapper.cs` (pure translation; no I/O) |
| Drift binding | `tests/TerraScale.Orchestrator.Tests/DeployHandoffContractDriftTests.cs` reads the machine-readable table below as the source of truth |

## 1. Purpose and ownership

TerraScale.Deploy owns source discovery, build, test, packaging, publication, and conversion of
its generic descriptors into this typed manifest. TerraScale.Orchestrator owns the canonical
executable contract (`DeliveryRequest`) and this mapping. The mapping is a **pure translation**:
it decides admission from the manifest document plus an optional admitted-operation context, and
it performs no I/O and no mutation. A manifest that fails any rule below is rejected **before any
request data exists**, therefore strictly before authorization, provenance, journaling, or any
target mutation.

This contract does not reintroduce candidate, approval, promotion, readiness, or release-stage
authority. It carries no credentials, provider responses, customer content, or private routes.

## 2. Input: the Deploy handoff manifest (v1)

A single bounded JSON object (≤ 1 MiB, depth ≤ 8) with exactly the fields below. `required`
means the mapping fails with `handoff_field_missing` when the field is absent or empty.

| Field | Required | Meaning |
| --- | --- | --- |
| `schemaVersion` | yes | Handoff manifest schema version; used only for admission negotiation |
| `operationId` | yes | Opaque client-generated operation id (≤ 128 chars, no control characters) |
| `source.repository` | yes | Full repository path, e.g. `TerraScale/TerraScale.Orchestrator` |
| `source.commit` | yes | Exact 40-hex-character Git commit that produced the artifact |
| `source.treeDigest` | yes | `sha256:` digest of the exact source tree |
| `artifact.digest` | yes | Exact published artifact digest (`sha256:` + 64 hex) |
| `artifact.manifestDigest` | yes | Digest of the artifact's manifest (OCI image manifest or package manifest) |
| `artifact.kind` | yes | One of `service`, `package`, `site` |
| `artifact.architecture` | yes | One of `linux/amd64`, `linux/arm64`, `multi` (image index), as published by Deploy |
| `rollback.artifactDigest` | only when `rollback` is present | Exact digest of the currently deployed artifact |
| `rollback.manifestDigest` | only when `rollback` is present | Exact manifest digest of the currently deployed artifact |
| `rollback.kind` | only when `rollback` is present | Must equal `artifact.kind` |
| `rollback.architecture` | only when `rollback` is present | Must equal `artifact.architecture` |
| `target.service` | yes | Named public service |
| `target.environment` | yes | `local`, `development`, or `production` |
| `target.regions` | yes | Ordered region list (1..32, distinct, each ≤ 256 chars) |
| `configurationRevision` | yes | `sha256:` digest of the admitted configuration revision |
| `migrationRevision` | no | `sha256:` digest of the migration revision; absent/null when the target has no migration |
| `requestedBy` | yes | Authenticated actor id (≤ 256 chars) |
| `reason` | yes | Bounded human or automation reason (≤ 1024 chars) |
| `informational.notes` | no | Bounded note (≤ 1024 chars); never executed |
| `informational.notificationChannels` | no | Bounded channel names (≤ 8, each ≤ 256 chars); never executed |

`rollback` as a whole is optional: a first deployment has no prior artifact and omits it. When
present, all four rollback fields are required and the rollback artifact must be **exact and
deployable** — see §6.

## 3. Output: typed bounded request data

The mapping emits `DeployHandoffRequest` — the canonical executable `DeliveryRequest`
(schema version pinned to `DeliveryRequest.CurrentSchemaVersion`) plus the two identities the
version-1 request cannot carry:

- `architecture` — the artifact architecture, preserved verbatim;
- `rollbackArtifact` — the exact rollback identity (digest, manifest digest, kind,
  architecture), or `null` for a first deployment.

Issue #3's runtime consumes this typed shape; the `Delivery` element is exactly what the
direct-delivery coordinator validates and (after its own authorization, provenance, and health
gates) executes. `authorityGeneration`, `writerEpoch`, and `attempt` are pinned to `1` by
mapping v1; the signed command-envelope seam owns the live values.

## 4. Field mapping table (machine-readable source of truth)

The drift test parses this block. Every input field of the manifest DTO and every output field
of a serialized `DeliveryRequest` must appear here. `class` is one of `executable` (flows into
the executable request data), `rollback` (flows into the exact rollback handoff),
`informational` (validated but never executed), or `admission` (gates admission only, no output).

```json
{
  "id": "deploy-handoff-mapping-v1",
  "mappingVersion": 1,
  "manifestSchemaVersions": { "minimum": 1, "maximum": 1 },
  "directDeliveryContract": { "name": "DeliveryRequest", "schemaVersion": 1 },
  "fields": [
    { "input": "schemaVersion", "output": null, "class": "admission", "required": true, "preservation": "negotiated against the admitted schema range; produces no output field" },
    { "input": "operationId", "output": "handoffRequest.delivery.operationId", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "source.repository", "output": "handoffRequest.delivery.source.repository", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "source.commit", "output": "handoffRequest.delivery.source.commit", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "source.treeDigest", "output": "handoffRequest.delivery.source.treeDigest", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "artifact.digest", "output": "handoffRequest.delivery.artifact.digest", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "artifact.manifestDigest", "output": "handoffRequest.delivery.artifact.manifestDigest", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "artifact.kind", "output": "handoffRequest.delivery.artifact.kind", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "artifact.architecture", "output": "handoffRequest.architecture", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "rollback.artifactDigest", "output": "handoffRequest.rollbackArtifact.artifactDigest", "class": "rollback", "required": false, "preservation": "verbatim" },
    { "input": "rollback.manifestDigest", "output": "handoffRequest.rollbackArtifact.manifestDigest", "class": "rollback", "required": false, "preservation": "verbatim" },
    { "input": "rollback.kind", "output": "handoffRequest.rollbackArtifact.kind", "class": "rollback", "required": false, "preservation": "verbatim" },
    { "input": "rollback.architecture", "output": "handoffRequest.rollbackArtifact.architecture", "class": "rollback", "required": false, "preservation": "verbatim" },
    { "input": "target.service", "output": "handoffRequest.delivery.target.service", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "target.environment", "output": "handoffRequest.delivery.target.environment", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "target.regions", "output": "handoffRequest.delivery.target.regions", "class": "executable", "required": true, "preservation": "verbatim, order-preserving" },
    { "input": "configurationRevision", "output": "handoffRequest.delivery.configurationRevision", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "migrationRevision", "output": "handoffRequest.delivery.migrationRevision", "class": "executable", "required": false, "preservation": "verbatim; null when absent" },
    { "input": "requestedBy", "output": "handoffRequest.delivery.requestedBy", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "reason", "output": "handoffRequest.delivery.reason", "class": "executable", "required": true, "preservation": "verbatim" },
    { "input": "informational.notes", "output": null, "class": "informational", "required": false, "preservation": "validated and admitted, never mapped into executable data" },
    { "input": "informational.notificationChannels", "output": null, "class": "informational", "required": false, "preservation": "validated and admitted, never mapped into executable data" },
    { "input": null, "output": "handoffRequest.delivery.schemaVersion", "class": "executable", "required": true, "preservation": "fixed: pinned to DeliveryRequest.CurrentSchemaVersion by mapping v1" },
    { "input": null, "output": "handoffRequest.delivery.authorityGeneration", "class": "executable", "required": true, "preservation": "fixed: 1 under mapping v1; the signed command seam owns live values" },
    { "input": null, "output": "handoffRequest.delivery.writerEpoch", "class": "executable", "required": true, "preservation": "fixed: 1 under mapping v1; the signed command seam owns live values" },
    { "input": null, "output": "handoffRequest.delivery.attempt", "class": "executable", "required": true, "preservation": "fixed: 1 under mapping v1; the signed command seam owns live values" }
  ]
}
```

**Updating the mapping**: adding or changing any field requires (a) a new row here, (b) the
matching mapper change, and (c) updated fixtures. Adding a `DeliveryRequest` or manifest field
without a row fails `DeployHandoffContractDriftTests` with the offending field name and this
document's path. A mapping that removes a field, narrows schema bounds, or changes a preserved
identity requires a new mapping version — never a silent edit of v1.

## 5. Digest semantics

- A digest is `sha256:` followed by exactly 64 hexadecimal characters (upper or lower case).
  `source.commit` is exactly 40 hexadecimal characters.
- **Preservation is byte-exact and verbatim**: every digest, commit, revision, architecture,
  kind, and region string is copied into the typed request unchanged. The mapper never
  normalizes, re-cases, truncates, or re-derives an identity.
- Digest **equality** at this seam is case-insensitive (matching the direct-delivery seam's
  `SameArtifact`/`SameDigest` comparisons). `source.commit` compares **ordinal**: Git object ids
  are canonical lowercase hex and the direct-delivery seam also compares source commits
  ordinally, so a cased commit is never silently forgiven here. Every other identity comparison
  — repository, service, environment, region order, kind, architecture, actor, reason — is
  ordinal.
- The mapper does **not** recompute digests. Manifest↔artifact binding is proven downstream by
  the direct-delivery provenance verifier; this seam guarantees exactness of the declared
  identities only.

## 6. Exact rollback handoff

When `rollback` is present it names the **exact** currently deployed artifact: both digests, the
same kind, and the same architecture as the deployed artifact. It is rejected when it is
incomplete, when its digest equals the artifact being deployed (no real prior artifact), when its
kind or architecture cannot run on the same target, or when its shape is not a deployable
artifact. An omitted `rollback` is a declared first deployment: the typed request carries
`rollbackArtifact: null` and #3's runtime applies its first-deployment rules.

Rollback **execution** stays out of scope here: #3's coordinator observes the current digest
before mutation and rolls back with exact identities; this contract only guarantees the exact
identity is handed over.

## 7. Schema negotiation

- Mapping v1 admits handoff manifest `schemaVersion` in `[1, 1]` (constants
  `DeployHandoffManifestSchema.MinimumSupportedVersion`/`CurrentVersion`). A
  `DeployHandoffAdmissionContext` may **narrow** that range per operation, but never widen it:
  a context whose range leaves the contract bounds is itself rejected as a programmer error
  (`ArgumentException`) rather than silently admitting an undefined schema.
- Unknown manifest schema versions — including newer ones — are rejected with
  `handoff_schema_unsupported` naming the admitted range.
- Widening the range, adding fields, or reclassifying a field requires **mapping v2**: v1 is
  frozen. Unknown-field rejection applies at every version: a mapping version never admits
  generic or open content.

## 8. Informational versus executable

- `executable`: the field becomes part of the request data a runtime could act on.
- `rollback`: the field becomes part of the exact rollback identity.
- `informational`: validated (bounded, secret-scanned) but **never** mapped into request data —
  `informational.notes` and `informational.notificationChannels` exist so generic descriptors
  have a typed home that cannot leak into execution.
- `admission`: gates whether the mapping runs at all (`schemaVersion`); produces no output.

Secret-shaped content is rejected outright (`handoff_secret_rejected`) in **every** admitted
free-text field — `reason`, `informational.notes`, `operationId`, `source.repository`,
`requestedBy`, `target.service`, `target.environment`, each region, and each notification
channel — so no plaintext secret can reach the durable delivery journal through a less-obvious
field. Secrets never travel in handoff data.

## 9. Rejection policy (before any mutation)

Every rejection returns `{ code, message, remediation }` and **no request data**, so no rejected
manifest can reach authorization, provenance, the journal, or a target. Evaluation order:
document validity (including duplicate property names) → generic content → unknown fields →
schema negotiation → required presence → bounds/secrets → identity formats → artifact and
target shape → rollback exactness/compatibility → admitted identity.

| Code | Trigger |
| --- | --- |
| `handoff_document_invalid` | Not JSON, not a single object, over the size/depth bound, a duplicated property name, or a known field with an unexpected value type |
| `handoff_ambiguous_content` | Generic manifest content (OCI-image-index or generic-descriptor keys such as `manifests`, `layers`, `config`, `descriptors`, `mediaType`, `env`, `command`, `files`, …) anywhere in the document |
| `handoff_field_unknown` | Any field not in the table above, at any level — fail closed, no extension fields |
| `handoff_field_missing` | A required input field is absent or empty |
| `handoff_schema_unsupported` | `schemaVersion` outside the admitted range |
| `handoff_unbounded_text` | Empty, over-long, duplicated, or control-character-bearing bounded field |
| `handoff_secret_rejected` | Secret-shaped text in any admitted free-text field (see §8) |
| `handoff_digest_invalid` | `source.commit` or any digest field is malformed |
| `handoff_artifact_invalid` | `artifact.kind` or `artifact.architecture` is not supported |
| `handoff_target_invalid` | `target.environment` is not `local`, `development`, or `production` |
| `handoff_rollback_incompatible` | Declared rollback is incomplete, undeployable, equals the deployed artifact, or mismatches kind/architecture |
| `handoff_digest_stale` | `source.commit`/`source.treeDigest` disagrees with the admitted operation source |
| `handoff_source_mismatch` | `source.repository` disagrees with the admitted operation repository |
| `handoff_target_mismatch` | `target.service`/`environment`/`regions` disagrees with the admitted operation target |

`DeployHandoffAdmissionContext` supplies the admitted operation identity (expected repository,
commit, tree digest, service, environment, regions). Each expectation is optional; when present
the manifest must agree exactly or the mapping is rejected before any request exists.

## 10. Dry run

`DeployHandoffMapper.DryRun` returns exactly the same bounded typed result as `Map` — the mapper
is a pure function with no side effects, so a dry run can never diverge from a real mapping
decision. `IsAdmittedForTargetMutation` is `true` only for an admitted mapping; a rejection
carries no request data at all. A dry-run admission is necessary but **not sufficient** for
mutation: authorization, provenance, health, and journaling remain #3's gates.

## 11. Compatibility fixtures

`tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/` holds the cross-repository corpus
modeled on TerraScale.Deploy's public manifest conventions: `valid-service.json`,
`valid-first-deployment.json`, `missing-tree-digest.json`,
`missing-rollback-manifest-digest.json`, `unknown-field.json`, `stale-digest.json`,
`mismatched-manifest.json`, `incompatible-rollback-artifact.json`,
`incompatible-rollback-architecture.json`, `wrong-schema-version.json`, and
`ambiguous-generic-content.json`. `DeployHandoffMapperTests` binds each fixture to its documented
outcome; `DeployHandoffContractDriftTests` binds this document to the implementation.

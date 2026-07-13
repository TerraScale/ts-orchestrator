# Phase 1 resource-contract handoff

Branch: `phase1/resource-contracts`

## Implemented boundary

This tranche implements provider-neutral metadata and a closed abstract v1 role
catalog under the draft `INV-017` admission boundary. It does not freeze a wire
format or mark registry evidence verified.

Metadata uses explicit immutable objects for the exact v1 API version, bounded
canonical stable IDs, positive generation and resource version, typed ownership and
creation actor, and a bounded canonical opaque audit-correlation ID. The audit ID is
deliberately not mandated to be UUID/GUID/ULID because the architecture selects no
such syntax. Null, default, unknown, noncanonical, and out-of-bound inputs fail.

The role union contains exactly 18 sealed v1 cases behind an abstract base with an
internal-only constructor; consumers cannot subclass it or provide an arbitrary
kind. Metrics storage, regional telemetry, and VPN cases require an
`ApprovedImplementationCatalogKey` tagged for the correct domain. A catalog key is a
typed logical `ResourceId`, not a raw executable, image/tag, unit, package URL, or
command field. No concrete metrics, telemetry-agent, or VPN product is selected.

Descriptors require an explicit nonempty allowed-runtime set and expose only typed
ports, closed role capabilities, closed volume purposes, typed secret-profile
references, health signals, placement constraints, scaling-controller ownership,
and bounded resources. There is no executable/argument, image pull tag, host path,
unit text/directive, privileged flag, Linux capability, or NATS permission surface.
This satisfies representability constraints only; an adapter must still enforce the
built-in mapping.

`RoleDescriptor` construction is assembly-internal. External manifests/clients can
read reviewed descriptors but cannot synthesize combinations such as an API role
with control authority, NATS storage, and unrelated secret profiles. Model tests
receive narrowly scoped friend access. A later same-assembly built-in catalog must
publish the reviewed instances; manifests may reference only those catalog entries.

Collections are defensively copied, duplicate-rejected, enum-validated, and sorted.
String-key ordering is explicitly ordinal; construction, projection, and structural
hashes are identical under invariant, `ar-SA`, and `tr-TR` cultures.
Canonical UTF-8 projections are independent of input ordering and include only
secret-profile references, never secret values, supporting the
`SEC-NO-SECRET-OUTPUT` boundary.

## Verification coverage

Model tests cover every role, metadata invalid/default cases, unknown API version,
default/unknown enum values, wrong implementation domains, missing implementation
inputs, invalid catalog-key syntax, collection duplicates, mutation isolation,
resource-bound inversion, stable projection/equality, and safe secret-reference
projection. Reflection tests prove the union is externally closed, every case is
sealed, and descriptor surfaces expose no raw string collection, `Type`, delegate,
process, arbitrary execution, privilege, host-path, Linux-capability, or NATS-
permission field.

## Intentional limitations

- Serialization, unknown-optional-field round-tripping, and a schema generator are
  steward-owned later work; this tranche freezes none of them.
- Catalog approval/storage is external to these value objects. Possessing a
  well-formed logical key is not proof that an implementation was approved.
- Runtime defaults, concrete metrics/telemetry/VPN products, ports, resources,
  placement, health, and scaling policy remain explicit descriptor inputs.
- Descriptors contain no secret bytes and do not retrieve secrets; adapters consume
  typed references under their separate security contract.
- These tests are L0 model evidence only. The draft registry remains draft with
  missing evidence; no deployment or adapter behavior is claimed.

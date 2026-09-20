# OCI deployment readiness record — 2026-09-20

This record is the current deployment gate for `ts-orchestrator`, TerraBase,
and `ts-auth`. It distinguishes local evidence from OCI evidence. Passing a
local test does not qualify an OCI identity, policy, network, or resource.

## Decision

**Do not start the OCI deployment yet.** The local runtime and VM qualification
gates below pass, but the production OCI mutation path is not implemented or
composed. OCI has not been mutated by this audit.

The next deployment can be a supervised GRU staging deployment only after the
blocking implementation and bootstrap gates are closed, followed by the live
negative-permission tests in the last section.

The required node behavior is part of that gate: a new controller or workload
host must bootstrap from its regional configuration, discover the regional NATS
service, claim one unexpired signed membership slot, converge the regional
topology, and begin consuming only admitted work. No operator should edit a
peer list or manually assign a task to make a replacement useful.

## Evidence captured locally

Evidence files are under `/tmp/ts-oci-readiness-20260920` and are tied to a
dirty shared workspace, so they are qualification evidence for the tested
source state rather than an immutable release receipt.

| Gate | Result | Evidence |
| --- | --- | --- |
| Orchestrator locked Release build | Pass | `orchestrator-build.log` |
| Orchestrator Release single-file linux-x64 publish | Pass | `orchestrator-publish` output from this run |
| Orchestrator unit/integration suites | 2,139 passed, 0 failed, 3 opt-in | prior suite receipt in evidence directory |
| Real local NATS control paths | Pass | NATS fixture receipts in the orchestrator test results |
| Local TerraBase process fleet | Pass, 1/1 | `live-fleet-final.log` |
| Firecracker single-region boot/heal/drain | Pass | `live-vm.log` |
| Firecracker three-region loss/heal | Pass | `live-vm.log` |
| Orchestrator NuGet audit, including transitives | Pass, no known vulnerabilities | vulnerability audit output |
| `ts-auth` Release build and locked restore | Pass | `auth-build.log` |
| Malformed bearer wire probes | Pass, real HTTP 401 responses | `auth-unicode.log` |
| Complete current `ts-auth` suite | **Open** | an independently launched run remained in webhook polling; no final summary |

The VM tests prove guest process lifecycle, health, and local network setup.
They do not prove replicated customer-data correctness, OCI IAM, OCI network
reachability, or an orchestrator running inside the guest.

## Authentication that must exist in production

### Orchestrator control-plane identity

Each regional controller needs its own NATS NKey and complete client mTLS
identity. The regional identity, global authority, global directory publisher,
directory service, infrastructure journal provisioner, and journal writer must
remain distinct. The binary already fails closed on missing TLS/NKey material,
credential-file permissions, URL user-info, replica-count ambiguity, and
identity reuse.

The controller also needs its command-signing key and trusted public keys. CI
ingestion additionally needs the Forgejo source token and the OCI CI runner
identity. Forgejo credentials are optional when CI ingestion is disabled.

### OCI API identity

The intended production identity is OCI Instance Principals on controller
instances. A dynamic group must match only the controller instances in the
controller compartment. No workstation API key or user private key should be
installed on a controller. The bootstrap operator may use an OCI API key to
create the initial estate, but that key is not a runtime credential.

The current source does not yet prove this path: the OCI Instance Principal
adapter is wired for CI-runner capacity (and block-volume expansion), while
`IOciCreateNodeClient` has no production implementation and no
`IMemberHostFleet` composition exists. The attempted workstation
`instance_principal` command was intentionally cancelled when it waited on
the metadata service; it is not evidence of Instance Principal access.

### Secret and workload identity

`ts-auth` requires its TerraBase API key/database route, master key, audit
signing key plus verification keys, operator key, and any webhook/OAuth
secrets. These must be injected through a reviewed secret profile (Infisical
is currently implemented as a bounded file-credential client). Secret values,
OCI signing keys, NATS seeds, and TLS private keys must never be placed in the
estate file, image, desired-state document, or logs.

OCI Vault integration for the final workload bootstrap and key rotation is not
composed in the current orchestrator runtime. Until it is, `ts-auth` can only
be rehearsed with the existing local/Infisical path; that is not a production
OCI secret qualification.

## Required OCI staging estate

Create this estate through the approved `ts-infra` CI workflow. Do not run
`tofu apply` locally and do not edit its state file by hand.

1. Under the existing TerraScale compartment, create separate `terrascale-control`,
   `terrascale-network`, and `terrascale-workload` compartments in each launch
   region as applicable.
2. Create private VCN/subnets and separate control/member NSGs in GRU first.
   NATS, host-agent, and TerraBase member ports must have no internet ingress.
3. Create a controller dynamic group scoped to the controller compartment.
4. Grant only the reviewed controller policy: manage instances and volume
   family in the workload compartment; use the recorded subnet/NSGs; read
   owned work requests, compartments, network objects, Vault metadata/key
   metadata, and the two owned buckets; pull from OCIR without repository
   delete; manage objects only under the owned ledger and backup buckets.
5. Create a private Vault and rotated HSM-protected key plus versioned ledger
   and backup buckets. Record immutable OCIDs, endpoints, retention, and
   lifecycle rules in a root-owned `0600` estate file with no credentials.
6. Publish signed, architecture-specific single-file artifacts for
   `ts-orchestrator`, TerraBase, and `ts-auth`; record SHA-256 digests and
   rollback artifacts before creating a VM.

The existing `ts-infra` checkout currently manages only Email Delivery
resources. It does not create this estate. The runbook in
[`oci-manual-bootstrap.md`](../guides/oci-manual-bootstrap.md) describes the
human bootstrap shape, but its estate verifier and provider client are not
present in the current runtime.

## Automatic regional formation and task pickup

The C# runtime already contains part of the intended behavior:

- `run` auto-provisions the regional controller topology by default
  (`TS_ORCH_AUTO_PROVISION=0` is the explicit opt-out), using idempotent
  create-or-update operations before opening the streams and KV buckets;
- each controller then publishes a signed, renewable `controller.<instance>`
  membership record and discovers peers through the regional runtime bucket
  and NATS service endpoints; and
- a host configured with `TS_ORCH_HOST_ROLES` starts a five-second
  leaderless-convergence loop. It reads the admitted digest from
  `ORCH_DELIVERY`, fetches the immutable artifact from `ORCH_ARTIFACTS`,
  acquires the stateful replacement lease when required, starts the runtime,
  and publishes its observation. This is the automatic pickup path for an
  admitted workload assignment.

Those paths do not yet make a fresh OCI node self-sufficient. The node still
needs a signed bootstrap grant, regional NATS URL/NKey/mTLS files, a stable
instance identity, host-role/environment configuration, and a provider-created
network address. `IMemberHostFleet` and the production OCI CreateNode client
are absent, and the membership document explicitly says that health is not yet
combined with authority as one mutation-eligibility decision. Therefore the
following claim remains unproved until the OCI implementation lands:

> Create a new VM in any admitted region, let it start with only its reviewed
> bootstrap material, have it join the correct regional cluster without manual
> peer edits, receive an admitted `ts-auth` or TerraBase assignment, report
> ready, and begin serving work; repeat after a controller/member loss without
> duplicate allocation or cross-region admission.

The local NATS and Firecracker tests exercise pieces of this sequence, but not
the full provider-to-VM-to-task path. The first live GRU gate therefore
requires an explicit “new node joins and picks up work” receipt before SFO or
FRA is enabled.

## Blocking implementation work

These are prerequisites for saying “ready to deploy”:

- implement and compose the OCI CreateNode client with signed idempotency,
  work-request polling, ownership/ETag reconciliation, and bounded retry;
- implement the production `IMemberHostFleet` adapter for instance observe,
  create, cordon, drain, and exact-instance terminate;
- compose regional placement, storage, network, Vault, and estate-drift
  verification in the single binary;
- admit and compose the `ts-auth` workload as an OCI container with a stable
  artifact identity, secret profile, health contract, dependency ordering on
  TerraBase, and rollback/restore behavior;
- make the controller's first-boot/bootstrap and trust rotation executable,
  including NATS identities and the TerraBase member enrollment path;
- add a staging configuration renderer/preflight that checks compartments,
  dynamic-group rule, policy statements, quotas, image architecture,
  subnet/NSG ownership, Vault key binding, and bucket retention before any
  mutation.
- complete the bootstrap/enrollment handshake so a new node obtains its
  regional identity, NATS trust bundle, host role, and desired-state cursor
  automatically; make the runtime reject wrong-region or stale grants before
  it can claim work.

## Final local gate before the first OCI mutation

Run these against the exact release commit, with no dirty source:

1. Locked restore, format, Release build, single-file `linux-arm64` and
   `linux-x64` publishes, and transitive vulnerability audit for all three
   services.
2. Full orchestrator TUnit suite, real-NATS suite, local TerraBase fleet
   scale/heal, Firecracker one-region and three-region loss/heal, and cleanup
   verification (no tap, bridge, guest, or listener leaked).
3. Full `ts-auth` TUnit suite, including browser tests, malformed UTF-8 bearer
   wire probes, audit export/rotation, user deletion cascade, webhook retry,
   and an external real TerraBase member run with a fresh database.
4. Start the published binaries under a minimal service account and prove
   rejected startup for missing/overbroad credentials, reused NKeys, missing
   TLS, wrong artifact digest, missing secret profile, and invalid runtime
   role. Keep the emitted logs and exit codes.
5. Exercise the OCI client against a deterministic HTTP transport for work
   request success, timeout, duplicate create reconciliation, ownership
   mismatch, authorization denial, and bounded retry. This is a unit gate,
   not live OCI evidence.

## First live GRU staging gate

After the blocking work and local gate pass, deploy one controller and one
throwaway workload in GRU only. Before allowing TerraBase or `ts-auth` traffic,
prove all of the following and retain the command output:

- Instance Principal succeeds from the controller VM and the same API call is
  denied from an untrusted VM and from the operator user outside the allowed
  scope.
- The controller can create, observe, tag, reconcile, cordon, drain, and
  terminate only its owned instance/volume resources; a different region,
  compartment, NSG, bucket, key, and unrelated instance are denied.
- Work-request retry and controller restart return the original OCID rather
  than creating a duplicate.
- NATS mTLS/NKey trust rejects anonymous, wrong-region, reused, expired, and
  journal-writer credentials; no credential material appears in logs.
- TerraBase membership admission, replicated writes, leader loss, replacement,
  drain, backup, and restore pass with customer-data assertions.
- `ts-auth` starts from the OCI secret profile, serves health/readiness, reaches
  TerraBase, survives a controller/VM restart, and its authentication,
  scope-denial, tenant-isolation, audit, and rollback probes pass.
- A newly created GRU host joins the regional controller/member cluster with no
  peer-list edit, claims no work until its signed membership and health are
  accepted, then receives one admitted `ts-auth`/TerraBase assignment. Remove
  the host and repeat to prove replacement, idempotency, and automatic task
  pickup. Repeat the same scenario after the region loses a controller quorum
  and verify that no task crosses into another region.

Only after the GRU receipt is reviewed should SFO and FRA be added. No live OCI
deployment or mutation was performed while creating this record.

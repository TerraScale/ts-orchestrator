# Stateful admission source and qualification — 2026-10-16

Production admission source is implemented through `e7cf1ea6`; the clean focused
check candidate is `ecbe5d6951e12673df0d1706cbf40dccebd3bc17`. This record supersedes
the earlier executor-hook evidence's statement that no concrete `BindingSource`
exists. It establishes source scope and local boundary evidence, not permission
to migrate production data or accept a TerraBase build.

## Production boundaries

`internal/storage/execution.Source` authenticates signed worker sessions,
manager desired/registration/member/volume bindings, actual OCI IMDS identity,
actual local CPU observations, release qualification and historical retained
provenance. `ResolveRuntime` consumes signed OCI manifest/config bytes and uses
the retained host material, TLS, Vault, backup and volume preparation path.
Process, resources, namespaces, image and mount pins remain immutable across
renewals. The runtime observer reads actual containerd metadata, process/kernel
identity, cgroups, namespace identity and retained host/container mounts twice.

The task-scoped ObjectDurable publication socket binds each request to the
current signed grant, admitted running process, socket inode and `SO_PEERCRED`.
Local grant revocation precedes writer stop at expiry. A late-created process
can be observed and retained for termination without receiving start authority.

`internal/storage/executionleader.Producer` reads actual manager task/service/node
state, authenticated caller registration, durable placement, member/desired,
signed delivery intent and read-only OCI volume/attachment observations. It
re-reads local authority and assignment after remote reads. Each immutable member
has one service, one replica, exact admitted node placement, STOP_FIRST updates
and rollbacks, and reservations bounded by actual advertised CPU and signed
guest capacity.

## Mandatory immutable allocation read

`ContainerAllocationResolver` is mandatory in both `NewSource` and `NewProducer`;
nil is denied. Every current or previous bundle resolves its allocation store
separately. APP supplies its canonical `currentContainerAllocations` helper,
which authenticates the historical root-signed migration before selecting its
signed region through the real region factory. Reads use the actual SDK adapter;
the reader cannot write or advance a release head.

`VerifyStatefulCurrent`, `VerifyStatefulDeclared`,
`VerifyNativeRetainedProvenance` and `VerifyRetainedProvenance` require the
resolved `release.SequenceLocation`. Current admission verifies the exact
immutable winning reservation. Historical provenance verifies at the signed
issue instant and reads the original winning reservation; it grants no runtime
permission. The first native migration additionally checks the pinned native
artifact SHA and actual ELF architecture without executing it.

The new allocation fixture uses RSA-signed OCI SDK requests to a loopback HTTP
server, persistent temporary object files, ETags and conditional writes. It
imports a genuine root-signed migration and calls `AllocateWithEvidence` for the
actual worker-family digest. It retains the resulting winning reservation bytes
instead of fabricating a reservation envelope.

## Check state

The mandatory-allocation candidate's two-package check is queued with QA and
has **no passing result yet**. An earlier run failed on malformed synthetic OCI
config JSON; `e7cf1ea6` corrects that fixture. Earlier focused source/qualification
and namespace checks passed before this allocation API change; those results do
not qualify the current candidate. Actual disposable ext4 format/blkid/growth
boundary evidence passed at `843daa1f` in 0.111 seconds.

The candidate includes canonical REL `148d6913` equivalents for container
verification, immutable reservation reads and cancellable OCI object reads, plus
the authoritative `a7520a5c` module files. CORE's initializer adaptation is
`d37e498f`; APP must supply the same mandatory resolver to both constructors.

## Open acceptance gates

1. CORE owns the emergency-stop correction: strict serving observations must
   not prevent killing an independently authenticated, identical retained writer
   after mount/resource drift. Exact PID/start/cgroup/namespace/container identity
   and stopped-proof settlement remain mandatory.
2. No positive actual Source → signed host issue → qualified containerd writer
   chain has been demonstrated. Pure runtime-spec tests still require conversion
   through the real containerd boundary; lifecycle deletion/deadline migration is
   preserved separately and remains unqualified.
3. No actual same-commit TerraBase disk/CPU, restore, replication or SIGTERM
   qualification exists in this evidence. Synthetic signed test evidence tests
   consumers only. Live OCI and native production acceptance remain unqualified.

No live cloud mutation, credentials, paid capacity, production data operation or
TerraBase download/execution was performed.

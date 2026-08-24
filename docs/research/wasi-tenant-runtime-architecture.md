# WASI tenant runtime architecture

Status: accepted architecture evidence

Tracking: [TerraScale.Orchestrator#27](https://git.terrascale.tech/TerraScale/TerraScale.Orchestrator/issues/27)

Accessed: 2026-08-23, America/Sao_Paulo

## Result

Use two deliberately different runtime classes:

1. Run signed TerraScale API and TerraBase images through containerd and runc.
2. Run customer stateless and serverless workloads as WASI Preview 2
   Components through an isolated Wasmtime host. Use containerd and runwasi for
   artifact and allocation lifecycle in the first implementation, but keep
   those implementation names out of the public contract.

The contract also narrows the earlier "arbitrary workload" goal. TerraScale can accept any application that conforms
to the published component world and policy, not every Linux container or
process.

The initial customer contract is:

- WASI Preview 2 Component artifact;
- HTTP or TerraScale Project Queue trigger;
- no durable local state or tenant volume;
- bounded ephemeral scratch;
- no privileged mode, host path, host device, raw socket, or raw NATS
  credential;
- policy-controlled outbound HTTP;
- managed TerraBase access through a versioned TerraScale capability or
  credential-hiding gateway;
- explicit CPU, memory, execution-time, concurrency, request, response,
  logging, and temporary-storage limits.

Existing Docker images, native Linux executables, unrestricted POSIX
applications, child-process supervisors, GPUs, kernel modules, and privileged
networking do not run unchanged. A future full-Linux tier is a separate product
decision.

## Runtime and artifact boundary

runwasi is a containerd subproject that lets containerd manage Wasm workloads.
Its current Wasmtime shim supports core modules, Components, WASI Preview 2
commands, and the `wasi:http/proxy` world. Its demos show both a Wasm module in
a regular OCI image and custom Wasm layers in an OCI image. TerraScale can
therefore reuse registry, digest, signature, provenance, distribution, and
content-store machinery without treating customer code as a Linux container.

The public workload package is the source Component plus its declared WIT
world, policy, and immutable digest. The host may compile it ahead of time, but
precompiled output is an internal cache. runwasi's Wasmtime compiler keys its
cache through Wasmtime's precompile compatibility hash, and Wasmtime generates
native code for the host. Cache identity must include the source digest,
engine compatibility hash, host architecture, relevant compiler settings, and
WIT host version.

Do not make Spin or wasmCloud manifests the public contract. Both projects have
useful SDK, component, and host patterns. wasmCloud also has an embeddable
Wasmtime-based runtime with capability plugins and NATS support. Adopting its
full distributed control plane would duplicate TerraScale scheduling,
identity, desired state, and regional ownership. TerraScale may evaluate an
embedded runtime or development tooling behind the same standards-based
component boundary.

## Isolation model

WebAssembly core memory and control-flow rules isolate an instance from direct
host memory and system calls. Wasmtime exposes outside resources only through
imports. WASI filesystem access follows a capability model. These properties
reduce the guest's available behavior, but a Wasmtime or host-integration bug
can still compromise the containing process. WASI is not a hardware VM
boundary.

The production floor is:

- one tenant and deployment revision per worker process and cgroup;
- a non-root UID with no ambient or inherited capabilities;
- a read-only root and no host paths;
- a bounded empty scratch directory destroyed with the allocation;
- seccomp and Landlock where the qualified host kernel supports the required
  rules;
- Wasmtime limits for memories, tables, and instances, plus separately bounded
  host-side allocations;
- cgroup v2 CPU, memory, PID, I/O, and pressure enforcement;
- epoch interruption for wall-time deadlines, with fuel reserved for contracts
  that require deterministic instruction accounting;
- bounded stdout, stderr, telemetry, request, response, and error material;
- no customer component on a TerraBase, controller, NATS, secret-authority, or
  provider-actuator node;
- immediate allocation retirement and host quarantine when runtime integrity is
  uncertain.

Wasmtime's resource limiter covers Wasm memories, tables, and instance counts,
not every allocation made by the embedder. The host therefore enforces both
Wasmtime limits and operating-system limits.

Pooling compiled code and engine state within one tenant and revision may be
qualified later. Cross-tenant process pooling is outside the launch design.

## HTTP, queues, and NATS

The `wasi:http/proxy` world moves the network accept loop into the host and was
designed to support serverless scaling. TerraScale's ingress owns the listener,
authenticates the request, resolves project and deployment identity, enforces
limits, and invokes an admitted component. The component receives a typed HTTP
request, not a listening socket.

For Project Queue, a platform-owned durable NATS consumer performs delivery,
acknowledgement, redelivery, deduplication, lease, and dead-letter policy. It
invokes the component through a versioned trigger envelope. The component
receives the business event and an opaque invocation context. It never receives
an NKey, account JWT, subject wildcard, JetStream consumer handle, or raw NATS
connection.

This boundary keeps NATS account and subject policy in the control plane. It
also lets the platform change queue topology without changing customer
components.

## Managed TerraBase

TerraBase runs as a trusted, signed OCI container. Container packaging does not
turn its storage into a generic tenant volume. The TerraBase controller retains
exclusive responsibility for stable member and volume identity, single-writer
attachment, formatting rules, topology, replication, backups, restore,
expansion, upgrades, fencing, and recovery.

Tenant components access TerraBase through one of two equivalent public
contracts that need a prototype before selection:

1. A versioned TerraScale WIT capability implemented by the host.
2. A credential-hiding local gateway that accepts a host-issued invocation
   identity and calls TerraBase through its typed API.

Both choices keep database credentials out of component memory and bind access
to the tenant, project, deployment, region, invocation, and allowed operations.
The WIT capability gives the narrowest interface. The gateway can reuse more of
the existing SDK and protocol implementation. A prototype should measure
language support, cancellation, streaming, pagination, error stability,
telemetry, credential exposure, and upgrade compatibility before the contract
freezes.

## Provider and cost effect

WASI tenant workers need no hardware virtualization: OCI `VM.Standard.A1.Flex`
hosts them within Oracle's supported boundary. The provider contract
still owns compute, network, load balancers, IAM, quotas, and regional
availability, but the workload contract does not name Oracle.

At Oracle's published A1 rates of $0.0100 per OCPU-hour and $0.0015 per GB-hour,
six illustrative workers with 4 OCPUs and 24 GB each cost:

```text
6 * ((4 * $0.0100) + (24 * $0.0015)) * 744 = $339.26/month
```

This excludes storage, load balancers, network transfer, tax, support, trusted
services, TerraBase, NATS, observability, and control-plane compute. The shared
A1 allowance may reduce an eligible tenancy's bill, but the production budget
must not assume it until billing and regional capacity are verified.


## Qualification gates

Before customer use, the exact runtime lane must prove:

- component signature, provenance, digest, WIT-world, and policy admission;
- cold and warm start latency, throughput, memory, CPU, cache behavior, and
  scale-to-zero recovery on real ARM64 and x64 hosts;
- memory growth, infinite loop, recursion, oversized table, output flood,
  decompression bomb, slow request, cancellation, and host-call exhaustion;
- denied filesystem, device, process, socket, NATS, metadata, secret, and
  control-plane access;
- tenant isolation under concurrent adversarial workloads;
- request and queue retry, timeout, deduplication, dead-letter, drain, restart,
  and regional outage behavior;
- TerraBase authorization, tenant separation, credential non-exposure,
  cancellation, retries, pagination, streaming, and contract upgrade;
- host compromise response, worker quarantine, allocation evacuation, artifact
  revocation, runtime rollback, and evidence preservation;
- cost per idle, warm, saturated, and drain-reserved allocation;
- no regression to TerraBase latency, NATS quorum, or control-plane
  availability because tenant workers occupy separate node classes.

No benchmark or upstream startup claim becomes a TerraScale service-level
objective without exact-host evidence.

## Primary sources

- [runwasi project and containerd integration](https://github.com/containerd/runwasi/blob/f1401719a3e981956ced9cd685abb2a49190bd1c/README.md)
- [runwasi OCI-image demos](https://github.com/containerd/runwasi/blob/f1401719a3e981956ced9cd685abb2a49190bd1c/docs/src/getting-started/demos.md)
- [runwasi Wasmtime Component and WASI HTTP implementation](https://github.com/containerd/runwasi/blob/f1401719a3e981956ced9cd685abb2a49190bd1c/crates/containerd-shim-wasmtime/src/instance.rs)
- [Wasmtime security model](https://github.com/bytecodealliance/wasmtime/blob/e6b33de5139d915a48127fc78b790e2d306cf896/docs/security.md)
- [Wasmtime resource limiter](https://github.com/bytecodealliance/wasmtime/blob/e6b33de5139d915a48127fc78b790e2d306cf896/crates/wasmtime/src/runtime/limits.rs)
- [Wasmtime execution interruption](https://github.com/bytecodealliance/wasmtime/blob/e6b33de5139d915a48127fc78b790e2d306cf896/docs/examples-interrupting-wasm.md)
- [Wasmtime platform and compiler support](https://github.com/bytecodealliance/wasmtime/blob/e6b33de5139d915a48127fc78b790e2d306cf896/docs/stability-platform-support.md)
- [WebAssembly Component Model](https://github.com/WebAssembly/component-model/blob/1af0b35e1bfc03bd4ad9603be2f676316ff9f420/design/mvp/Explainer.md)
- [WASI HTTP goals and serverless host model](https://github.com/WebAssembly/wasi-http/blob/7c678c4c10238a4bf4db91a0e27023d680ff65fe/README.md)
- [OCI image manifest and artifact relationships](https://github.com/opencontainers/image-spec/blob/af26a05fba5ee648512f4ea3c9fda1fcc1b6d6dc/manifest.md)
- [NATS authorization](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/authorization)
- [NATS JetStream consumers](https://docs.nats.io/nats-concepts/jetstream/consumers)
- [wasmCloud runtime and capability model](https://github.com/wasmCloud/wasmCloud/blob/7cd553cc57cfb5a64717d76b11ddeea2cd8c0a8b/README.md)
- [Spin component framework and language support](https://github.com/spinframework/spin/blob/94a8fc8a7804ec2519bb8d12df70ab77ad2e4f60/README.md)
- [OCI Ampere A1](https://docs.oracle.com/en-us/iaas/Content/Compute/References/arm.htm)
- [OCI Compute pricing](https://www.oracle.com/cloud/compute/pricing/)

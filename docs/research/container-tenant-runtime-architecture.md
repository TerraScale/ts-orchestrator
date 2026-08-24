# Container tenant runtime architecture

Status: accepted architecture evidence

Tracking: [TerraScale.Orchestrator#27](https://git.terrascale.tech/TerraScale/TerraScale.Orchestrator/issues/27)

Accessed: 2026-08-24, America/Sao_Paulo

## Result

Use one runtime substrate for every workload class:

1. Run signed TerraScale API and TerraBase images through containerd and runc.
2. Run customer stateless and serverless workloads as unprivileged,
   digest-pinned OCI containers through the same containerd/runc substrate on
   dedicated tenant-worker nodes.

OCI containers are the only workload runtime. The earlier virtualized-isolation
research and the WebAssembly component runtime were retired by owner
decision on 2026-08-24; [ADR 0031](../adr/0031-run-tenant-workloads-as-unprivileged-oci-containers.md)
records the decision, and the repository retired-runtime policy tests block
the return of virtualized or WebAssembly tenant tiers in living source and
documentation.

The initial customer contract is:

- unprivileged OCI container image, admitted only by immutable digest from
  the tenant registry namespace;
- HTTP or TerraScale Project Queue trigger;
- no durable local state or tenant volume;
- bounded ephemeral scratch;
- no privileged mode, host path, host device, raw socket, or raw NATS
  credential;
- all Linux capabilities dropped, `no-new-privileges` enforced, read-only
  root filesystem, seccomp, and Landlock where supported;
- policy-controlled outbound HTTP;
- managed TerraBase access through a versioned TerraScale capability or
  credential-hiding gateway;
- explicit CPU, memory, execution-time, concurrency, request, response,
  logging, and temporary-storage limits.

Privileged containers, native Linux executables, unrestricted POSIX
applications, child-process supervisors, GPUs, kernel modules, host mounts,
and privileged networking do not run as tenant workloads. The tenant
platform profile validates the image configuration (non-root user, declared
service port, no privileged or host hints honored) before admission;
image-declared limits never replace operating-system limits.

## Isolation model

Tenant isolation is a hardened shared-kernel container boundary:

- one non-root container, process namespace, and cgroup per tenant and
  deployment revision; cross-tenant pooling is forbidden;
- tenant containers run only on the separate tenant-worker node class, which
  hosts no TerraBase, controller, NATS, secret-authority, or provider-actuator
  role;
- the platform owns listeners and queue consumers and invokes containers
  through versioned trigger envelopes on loopback-only or private-namespace
  networking;
- a tenant-runtime integrity failure quarantines the worker and evacuates its
  allocations; it never fails over onto a trusted-service node.

The owner explicitly accepts the residual kernel-sharing risk and controls it
through node-class separation, denial tests, defense-in-depth host policy,
and quarantine. No hardware virtualization boundary is claimed, and
adversarial container-escape and resource-exhaustion tests against the pinned
containerd/runc versions on the real production architecture remain launch
requirements.

## Consequences for the platform

- One lifecycle substrate (containerd/runc) serves trusted, tenant, and CI
  containers, so runtime hardening review concentrates on a single pinned
  stack.
- Tenant admission, scheduling, density measurement, and autoscaling operate
  on OCI images and their resource profiles; no per-language runtime or
  component compilation step exists.
- Rollback, staging, and digest verification reuse the trusted-container
  artifact machinery with a separate tenant registry namespace and policy.

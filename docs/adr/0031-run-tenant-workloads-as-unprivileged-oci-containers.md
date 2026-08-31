# Run tenant workloads as unprivileged OCI containers

Status: accepted for the first post-launch feature

Tracking: [TerraScale.Orchestrator#27](https://git.terrascale.tech/TerraScale/TerraScale.Orchestrator/issues/27)

TerraScale Orchestrator uses OCI containers as its only workload runtime.
Signed first-party TerraScale services run as trusted containers from the
closed catalog, and customer stateless or serverless workloads run as
unprivileged, digest-pinned OCI containers under the tenant contract. There is
no microVM, WebAssembly, or other virtualized tenant tier, and none may be
reintroduced without a superseding decision.

Each customer allocation receives its own non-root container, process
namespace, and cgroup on a tenant-worker node, with all Linux capabilities
dropped, `no-new-privileges`, a read-only root filesystem, bounded disposable
scratch, seccomp, and Landlock where supported. The platform owns public
listeners and NATS consumers, so tenant containers receive neither raw NATS
credentials nor unrestricted host networking. HTTP and TerraScale Project
Queue remain the launch triggers.

Tenant isolation is a hardened shared-kernel container boundary. The owner
accepts the residual kernel-sharing risk explicitly and controls it through
the separate tenant-worker node class, defense-in-depth host policy, denial
tests, and quarantine; it is not claimed to be a hardware virtualization
boundary. Tenant workers never share nodes with TerraBase or control-plane
roles. Tenant images are admitted only by immutable digest from the tenant
registry namespace and cannot request privileged execution, host paths, host
devices, raw sockets, Linux capabilities, or first-party identities.

This ADR permanently retires the previous microVM and WebAssembly runtime
directions. [ADR 0029](0029-offer-stateless-tenant-compute.md) remains in force.

## Consequences

- Customer language support depends on producing a compatible OCI container
  image, not on compiling to a component model or targeting a language-specific
  runtime.
- The scheduler maintains separate trusted-container and tenant-container node
  classes, admission policies, capacity measurements, and runtime tests.
- Container runtime hardening (runc, namespaces, cgroups v2, seccomp,
  capabilities) is now tenant-security-critical and receives the corresponding
  review, testing, and adversarial escape gates.
- TerraBase access uses a versioned capability or credential-hiding gateway
  scoped to the invoking tenant and project.
- Bare metal, KVM, and WebAssembly runtimes are not launch requirements for
  customer compute and may not be reintroduced as tenant tiers without a new
  ADR; the repository retired-runtime policy tests block their return in
  living source and documentation.

# Tenant container runtime

Status: accepted direction for the first post-launch feature.

ADR 0031 records the decision. Tenant compute does not ship in the first
release, but launch architecture must preserve this boundary.

## Runtime

Tenant functions run as unprivileged, digest-pinned OCI containers through the
same rootless Podman and systemd user-unit mechanism used for first-party
workloads. Tenant allocations use a separate node class and security profile.
They never share a host with TerraBase, NATS, controllers, identity issuers, or
provider actuators.

The tenant contract permits:

- a digest-pinned OCI image from the tenant registry namespace;
- HTTP or a platform-owned queue trigger;
- bounded ephemeral scratch;
- policy-controlled outbound HTTP; and
- managed TerraBase access through a scoped credential or capability.

It does not permit durable local volumes, privileged mode, host paths, host
devices, raw sockets, raw NATS credentials, provider credentials, control-plane
identity, or unrestricted networking.

## Isolation

Each allocation receives a non-root container, process namespace, and cgroup.
The runtime drops every Linux capability, sets `no-new-privileges`, uses a
read-only root filesystem, loads the pinned seccomp profile, and applies
Landlock where the host supports it. CPU, memory, task, execution-time,
concurrency, request, response, log, and scratch limits come from the admitted
plan and operating system controls.

Tenant isolation is a hardened shared-kernel boundary, not a hardware virtual
machine boundary. The separate node class, denial tests, quarantine, and host
hardening control the accepted residual risk.

## Failure behavior

A tenant-runtime integrity failure quarantines the node and stops new
allocations. Existing allocations move only after the scheduler and drain
policy permit it. The control plane never fails a tenant onto a trusted-service
node.

Losing an allocation must not require data recovery. Durable application state
lives in managed TerraBase or an explicitly allowed external service.

## Consequences

Tenant admission and autoscaling use OCI images and declared resources. There
is no per-language runtime or component compilation step. Runtime hardening,
container escape tests, resource-exhaustion tests, and tenant-to-tenant denial
tests are required before the post-launch function service opens.

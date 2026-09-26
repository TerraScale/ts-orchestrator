# Offline production restart packet generator

This host-only Go package builds and validates a signed packet for the
three-VM production restart driver. It does not contact OCI or start a VM.
The packet is one canonical, root-signed `manifest.json` plus `manifest.sig`
and exactly the inventoried files. Validation requires an external trusted
Ed25519 public key and a host clock within five minutes of the fixture clock.
The CLI has `emit`, `verify`, `production-preflight`, `stage`, and `serve`
subcommands. The complete-history path is `EmitCompletedRestartPacket`, which
uses public bootstrap and ledger APIs; the generic `emit` command alone does
not create a completed history.

Each `controllers/{slot}/guest-root/` contains the `0444` baked identity,
anchor and public root, accepted-install marker, canonical `lab=false`
controller config, service credentials, verified founder floor, guest OCI CA,
and fixed private network, time, hosts, SSH and cloud-init config. A signed
directory plan records both `0700` service-owned controller state and secrets
directories per slot. `input/orchestrator` pins the exact executable bytes,
SHA-256, size, architecture and fixed guest path. `simulator/tls/` holds a
host-only OCI HTTPS server pair; `simulator/imds/{slot}/` holds separate
host-only instance-principal material. No simulator or signing key is a
`GuestFile`.

`VerifiedPacket.GuestDirectories`, `GuestFiles`, `Executable`,
`SimulatorConfig`, `SimulatorTLS`, and `SimulatorRoutes` return byte copies
after rechecking the signed inventory. `production-preflight` verifies full
source pins, image receipt, executable, all guest configs and credential
digests, HTTPS/IMDS identities, and exact network files. `stage` repeats that
gate, checks the target is a distinct ext4 mount point, checks the image's
real service UID/GID and packaged units, installs the signed files, refreshes
the **guest** CA bundle, and calls the shipped binary's production credential
validator under the service account. `serve` binds per-slot simulators to
the isolated bridge and writes a request audit when stopped.

The completed packet integration test signs synthetic seed and managed peer
histories, captures the public ledger's exact object keys and responses,
generates production-format NATS JWT/TLS/key material, constructs verified
founder floors, and exercises real OCI SDK reads through each simulator. With
the `fixturetest` tag it also calls `OCIInstanceObserver.ObserveInstance`
through its test-only transport seam. These tests establish an offline packet
contract, not a packaged VM restart pass. See [RECIPE.md](RECIPE.md) and the
[driver README](../README.md) for the run boundary.

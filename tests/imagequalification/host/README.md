This test-only package shares disposable-host observations and pinned SSH
transport between image qualification roles. It imports no CORE runtime or
SwarmKit package. `native` retains aliases for the existing report and host API.

The caller supplies approved Compute IDs, private IPv4 addresses, trusted SSH
host-key pins and an owner-only ephemeral root SSH key. `OpenSession` verifies
the exact worker bytes and invokes only `worker serve`. Explicit uploads verify
SHA256 at both ends, reject path traversal and reject existing remote files.
JSON exchanges reject unknown response fields, bound frames to 1 MiB and close
SSH on cancellation. The key stays on the driver.

`MeasureIdentity` observes local component hashes and OCI IMDSv2 instance/image
metadata. It does not cryptographically attest the instance or boot image; the
parent must authenticate their relationship through the OCI SDK. These shared
types and local SSH/filesystem/process/HTTP tests grant no cloud authorization,
workload admission or native acceptance.

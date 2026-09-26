# Offline production restart simulator

`simulator.go` is a host-side, in-memory HTTP handler for a future Firecracker
qualification of the shipped orchestrator with `lab=false`. It has no upstream
proxy or OCI client. It accepts exactly six fixed OCI IMDS GETs, a signed
`POST /v1/x509` on the pinned GRU Auth host, and fixture-listed exact Compute
or Object Storage GETs on their pinned GRU hosts. Compute inventory is limited
to the exact IMDS instance, its VNIC attachment list, and exact VNIC IDs;
Object Storage inventory is limited to exact object keys, never listing. An
expected missing object must be declared separately and receives a 404 only
after service-signature verification. Every unlisted route fails with a
distinct 421 (or 403 if unauthenticated), so an unexpected read cannot be
mistaken for a missing ledger record. All OCI writes fail. The caller must
provide the exact route inventory and signed response bytes; this package
does not synthesize bootstrap records or launch VMs.

The federation request must present the fixture leaf and intermediate
certificates, use a new RSA session public key, and carry the OCI SDK v65.126.0
leaf-key signature over the request target and body headers. The simulator
issues a one-hour, unique JWT and binds it to that session public key. Every
allowed service GET must use `ST$<JWT>` and a valid RSA signature over its exact
method, request URI (including query), date, and host. Object responses include
the exact body length, ETag, Last-Modified, and Date needed by the ledger.
Request logs contain method, host, status, and an exact-route SHA-256.
Listed routes show the pinned path with query values redacted; unlisted paths,
queries, and unknown hosts are fully redacted. Logs contain no IMDS
private key, federation body, JWT, or signature headers. Fixture routes,
aggregate response bytes, sessions, and audit records have fixed limits.
`OverflowCount()` must be zero for an accepted qualification.

The eventual VM driver must expose only a private network path to this handler
and to its peer and NTP fixtures. It must pin private DNS/hosts entries and a
test trust root for the OCI HTTPS names, isolate the fixed link-local IMDS
address, deny all other egress, and check the request log for zero unexpected
requests and zero OCI writes. A completed-seed production restart should not
request Vault or founder launch operations. This package alone is a protocol
test; it does not establish a production VM pass.

`go test ./tests/firecracker/production` exercises IMDS pinning, the real
instance-principal provider and generated Compute/Object Storage clients,
federation session binding, exact query verification, expected missing objects,
unknown request/write rejection, and real `net/http` parsing of the signed
Content-Length header.

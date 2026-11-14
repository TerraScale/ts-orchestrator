# Edge certificate observation

The edge continues to obtain and renew certificates through its existing automatic issuance manager. Observation requests never obtain a certificate.

## Graceful drain

On SIGTERM the edge immediately answers 503 on `/healthz` and `/readyz` on ports 80 and 443.
The edge waits 20 s before closing only when an external health checker probed it in the last minute.
During that wait it keeps its listeners open and serves other requests.

## Readiness

GET or HEAD /edge/ready is available on HTTP port 80 and on the node's mesh-facing HTTP port 9108. It returns 200 when all four edge listeners are bound, routes have loaded, ingress and local application backends are ready, and every routed HTTPS or PostgreSQL name has a valid ECDSA certificate available locally. Otherwise it returns 503. The JSON body includes ready, missing infrastructure conditions, and missing_names. A newly routed name is reported immediately until its certificate becomes available.

The endpoint is an operator signal and a release health input. Release health (`ts.release.health`, which `ts-orch release push` and release app pushes poll to decide a region is healthy after a rollout) joins the edge readiness error with its mesh and service checks on every host that serves an edge: a release whose edge is not ready reports unhealthy, with the missing conditions and names in the health text. RSA certificates are reported by inventory, while readiness requires the ECDSA variant selected by normal automatic handshakes.

It checks local HTTP backend readiness paths without following redirects and checks PostgreSQL backend TCP connectivity, within a three-second budget.

## Inventory

Run ts-orch edge certificates inventory to read every node in the persisted node list over its mesh address. Append local to inspect this node, a node name to select one node, or all for the fleet explicitly. Fleet and named-node reads load the existing node list directly, without initializing or writing node state.

GET /edge/certificates on mesh port 9108 returns certificates, missing_names and errors arrays. This endpoint shares the mesh host telemetry listener and its network access boundary. It is not exposed through the public HTTPS router. Nodes with no edge return an empty inventory and fail readiness.

Each certificate contains names, key_type, issuer, serial, not_before, not_after, fingerprint_sha256, source, valid and problems. The fingerprint is the SHA-256 of the leaf certificate's DER bytes. Source autocert identifies the existing automatic issuance cache. Inventory includes certificates on disk and certificates observed in successful TLS selections or automatic cache writes, deduplicated by fingerprint. Removing a disk file does not remove a certificate that the running automatic issuance manager still holds in memory.

Validation checks the leaf's private-key match, all DNS names, validity dates and the full chain through the system trust roots. Certificates and intermediate chains are parsed locally. No private key bytes enter the response or command output. Missing names are computed from the current local route tables; an optional key variant may be invalid without making a name missing if another valid variant covers it.

The command prints one line per certificate. It exits nonzero when a node cannot be read, its response is invalid, its inventory reports an error, or a served name has no valid certificate. Its errors identify unreadable nodes and missing names. An unserved certificate's failed validation is visible as valid=false.

## Metrics and alerts

The existing host telemetry /metrics scrape includes these series whenever an edge runs:

| Metric | Meaning |
|---|---|
| ts_edge_certificate_not_after{name,key_type} | Expiry timestamp in Unix seconds; the earliest held certificate for each routed name and key type |
| ts_edge_certificate_names_missing | Number of routed names without a valid certificate |
| ts_edge_ecdsa_unsupported_handshakes_total | Failed automatic certificate selections where locally held certificates cover the routed name but none supports the client's key requirements |
| ts_edge_autocert_orders_total{outcome} | Automatic new-order requests accepted (success) or rejected/unreachable (error), including renewal orders |

Name labels come only from the route tables. Key types and outcomes have bounded sets. Counters reset with the process. A successful order metric means the authority accepted the order; it does not mean issuance completed.

The production operational rules emit EdgeCertificateExpiryWarning within 21 days of expiry, EdgeCertificateExpiryCritical within 5 days, and EdgeCertificateMissing after a served name has lacked a valid certificate for 10 minutes. The expiry alerts can both fire within five days. The rules operate on each scraped node independently.

## HTTP-01 challenges

Challenge tokens must contain 22 to 128 ASCII base64url characters. Malformed tokens receive 404 before any lookup.

The challenge path has no rate limit in this build because a refused validation costs a certificate. Each request checks the existing local handler and, for public requests missing locally, the same regional peers over mesh mutual TLS in the same order. Peer requests remain local-only.

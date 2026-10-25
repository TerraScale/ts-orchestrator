# Edge request identity

The HTTP ingress allocates a canonical uppercase ULID in `X-Request-ID` before
routing, body buffering or proxying. Success, validation errors, unknown routes
and dependency failures retain it. Edge replay carries the same identity over
the existing authenticated mesh mTLS channel.

DECISION: first-party callers may preserve an ID with exactly one
`X-TerraScale-Request-Proof`: uppercase hexadecimal HMAC-SHA256 of
`terrascale.request-id.v1\n` followed by the canonical ULID (`\n` is one LF byte,
0x0A). The HMAC key is the exact UTF-8 characters of `TERRABASE_PEER_SECRET`,
preserving stored letter case without hex decoding. Unproven, malformed or
duplicate public identities are replaced.
The edge replaces incoming proofs with a locally signed proof for the backend;
services must verify it even on loopback. Backend response proofs, including
trailers, are removed before returning to the customer.

DECISION: proofs authenticate correlation only, never authorization or tenant
access. They have no time cutoff, preserving long-lived causal work. Never put
proofs or credentials in public responses, application logs or support context.

The edge reuses the admitted TerraBase service's existing
`TERRABASE_PEER_SECRET_FILE` Vault reference through instance principals,
refreshing once a minute. Missing, invalid or unavailable credentials clear
proof trust; ingress still generates fresh IDs and mesh replay still works.
No secret, service reference or configuration option is added.

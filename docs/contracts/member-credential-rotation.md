# Member credential rotation

The global rotation coordinator sends HTTPS `POST /v1/credential-rotation` to
explicit member endpoints. Requests carry the node ID, consumer, operation ID,
generation, and the exact global authority epoch and lease ID. Host configuration
maps controller certificate SPKI SHA-256 digests to election candidate IDs. Every
effect rechecks the current global lease through stream-leader NATS reads; a
controller certificate alone is insufficient authority.

`MemberGatewayFileConfig` contains `members` (`id`, `region`, `url`) and
`certificate_file`, `private_key_file`, `trust_bundle_file`. Its
`OpenForLease` and `OpenReloaderForLease` methods require the active session's
explicit epoch and lease ID. TLS verifies both server and client identities;
redirects and insecure transports are rejected. Identity envelopes returned by
the issuer are maps of exact node IDs to combined certificate/private-key PEM.
Only the target node's entry crosses the member boundary.

Every production orchestrator requires `TS_ORCH_ROTATION_HOST_FILE`. The JSON
file uses these fields:

- `version`: 1; `cell` and `node_id`: the configured host identity.
- `listen`: an explicit HTTPS listen IP and nonzero port.
- `socket_path`, `token_file`: the private TerraBase rotation Unix socket and its
  bearer-token file; `identity_service_socket_path`: the private member identity
  service socket; `state_dir`: private durable control TLS state.
- `control_tls`: `certificateFile`, `privateKeyFile`, `trustBundleFile` for the
  initial HTTPS control listener.
- `nats_url`, `nkey_file`, `nats_identity`: a separately provisioned read-only
  global authority identity (`nats_identity` uses the same TLS file fields).
- `controller_candidates`: lowercase SPKI SHA-256 hex to global candidate ID.

The authority reader needs `$JS.API.STREAM.MSG.GET.KV_ORCH_LEADERS` and its reply
inbox, never authority publication permission. Hosts do not receive the global
controller's private NKey. Credential and state paths must be private, owned by
root or the service identity, with protected ancestors.

The HTTPS receiver forwards member effects to TerraBase's authenticated private
Unix HTTP receiver. The latter owns the durable generation journal and actual
workload key/TLS consumers. Control reloads update the HTTPS listener's dynamic
TLS configuration and durable active/staged/previous snapshots. The configured
host service owns listener shutdown; unexpected receiver exit stops its service
group. A disconnected or ambiguous request is an error; success requires the
consumer's matching receipt.

Stage payloads contain current and previous key IDs, base64 key bytes, the prior
generation, expiry timestamps in Unix seconds, and the target workload PEM/trust
bundle. Verification precedes activation. Retirement identifies the old
generation; a fence uses generation zero and disables the consumer's current
acceptance. Secret bytes are excluded from responses and public journals.

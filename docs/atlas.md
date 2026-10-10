# Atlas publisher

ts-atlas (`https://atlas.terrascale.tech`) serves region discovery to every
SDK: `/v1/discovery`, `/v1/resolve` and `/v1/keys`. It knows only what the
orchestrator publishes through its signed `POST /v1/publish` (ts-atlas
`docs/discovery-v1.md`). Package [`internal/atlas`](../internal/atlas)
publishes it with the ts-go Atlas client (`terrascale.tech/sdk/atlas`).

- The cell spec's `atlas` section
  ([`deploy/oci-region/atlas-gru-1.json`](../deploy/oci-region/atlas-gru-1.json))
  holds Atlas' URL, the Vault ref of the P-256 publish key, every region and
  the service catalog.
- The authority leader probes each region's `GET <api>/readyz` and publishes
  the whole topology every 10 s, so a health change reaches Atlas within
  10 s and Atlas never sees a topology older than its `STALE_AFTER_S` (60 s).
  `updated` is the leader's clock, moved on by one second when two publishes
  share a second. The leader checks its authority epoch (`Guard`) right
  before each POST, so a controller that lost the lease meanwhile publishes
  nothing; a new leader takes over within one tick. Each attempt, the Vault
  key read included, is bounded by 10 s, and at most one key read is in
  flight: a stalled one is waited on again, never started twice.
- Every failed publish logs `Atlas publish failed`. Once none has succeeded
  for 60 s, the leader logs `ALERT Atlas topology is stale` once, as a
  dashboard event, and `Atlas topology is current again` after the next
  success. A refused signature (`401`) re-reads the key from the Vault.
- Only the global home's spec carries the section: one publisher writes the
  topology of every region.

## Automatic discovery and Vault delivery

The publisher must discover every admitted region and its authoritative service
origins automatically. New regions need no catalog amendment or enable step.
Local region identity is inferred from location, and private NetBird membership
admits nodes under the required [operating contract](zero-configuration.md).

OCI Vault must create and deliver publisher/session-pin secrets automatically,
including the corresponding public trust keys. Vendor publication credentials
are stored once in Vault and picked up automatically. Operators do not pipe
secrets into Worker commands or copy regional credentials.

**Current gap (TS-796):** the publisher still depends on the global home's
explicit `atlas` spec, a configured region list and pre-existing Vault key.
Atlas now stores discovery documents in D1; the older TerraBase store-key
recipe is retired. Existing signed publication does not prove automatic
regional admission or secret provisioning.

Preserve authority-epoch fencing, monotonic publication ordering, exact publisher
signature validation and secret-free diagnostics. Stale or missing publication
must remain visibly unavailable; it must not fabricate healthy regions.

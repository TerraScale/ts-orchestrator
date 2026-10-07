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

## Secrets

| Secret | Where | Made by |
| --- | --- | --- |
| `gru-1-atlas-publish-key` | gru-1 Vault; the controllers read it with their instance principal | `ts-orch atlas key --plan deploy/oci-region/plan.json` (once; prints the public `PUBLISH_KEYS`) |
| `gru-1-atlas-store-key`, `gru-1-atlas-terrabase-project-id` | gru-1 Vault | `ts-orch ouroboros bootstrap` (project `atlas`, database `atlas` in organization `terrascale`) |
| Worker `ATLAS_STORE_KEY` | ts-atlas Worker secret | `wrangler secret put`, piped from the Vault secret above |
| Worker `PIN_SIGNING_KEY` | ts-atlas Worker secret | a new private P-256 JWK, piped into `wrangler secret put`; rotating it only makes SDKs resolve again |

`PUBLISH_KEYS` and `ATLAS_STORE_URL`
(`https://gru.api.terrascale.tech/v1/projects/<atlas project id>/databases/atlas`)
are vars in ts-atlas `wrangler.toml`; its CI deploys them from `main`.

## Bring Atlas up

1. `ts-orch ouroboros bootstrap ...` (see [ts-auth deployment](ts-auth-deployment.md)) creates the atlas project and its key.
2. `ts-orch atlas key --plan deploy/oci-region/plan.json` stores the publish key and prints `PUBLISH_KEYS`.
3. Set the Worker secrets, then merge the ts-atlas `wrangler.toml` change with both vars.
4. `ts-orch atlas publish --plan deploy/oci-region/plan.json --section deploy/oci-region/atlas-gru-1.json` publishes once; `/v1/discovery` answers 200.
5. Move the controllers to a binary with binary level 11 in place (`selfupdate`), add the section to the spec (`ts-orch get`, add `"atlas"`, `requires_binary: 11`), `diff`, `release sign-spec --root` and `apply` ([cell spec](cell-spec.md#commands)).
6. Check: `updated` in `/v1/discovery` stays within 10 s of now.

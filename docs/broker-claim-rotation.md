# Regional broker account rotation

Use the same binary as an operator with a signed account JWT for the cell:

```sh
terrascale-orchestrator operator broker-claim-apply \
  --config operator.json --file cell-account.jwt --expected-sequence 42
```

`--expected-sequence` is the current durable broker-claim control-log sequence, or `0` before the first claim. The controller verifies the operator's signed request, the default-deny `can_rotate_broker_account` trusted-signer grant, the exact cell account, and a signature by the operator pinned when the broker started. A different JWT at a stale expected sequence cannot close the bridge. An exact-current JWT is safe to retry with its original expected sequence.

The operator configuration needs `operator.actor`, `operator.signing_key_file`, and `operator.broker_ticket_public_key_file`. The last file pins the controller's broker ticket public key independently of the NATS connection. Production operator NATS credentials need publish grants for `ts.orch.v1.<cell>.broker.claim.apply`, `$JS.API.INFO`, `$JS.API.STREAM.INFO.TS_CONTROL_LOG`, and `$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG`, plus a subscription grant to the caller's private `ts.orch.v1.<cell>.inbox.<user-nkey>.>` reply prefix. The binary validates these grants before applying a claim.

A `fenced` JSON receipt and zero exit status mean the current durable JWT exactly matches the receipt and every configured broker acknowledged local application and closure of old sessions. A `pending` JSON receipt has a nonzero exit status: the JWT is durably committed, but the listed brokers have not acknowledged fencing. Retry the identical JWT and expected sequence after the offline brokers recover. An `outcome unknown` error has no success receipt; the command may have committed before its connection closed. Inspect the durable claim and retry the identical request before changing the JWT or expected sequence.

Success and pending receipts are signed with the controller's pinned broker ticket key, bound to the exact request and authority epoch, and expire no later than the observed lease. The CLI verifies that signature and reads the current durable JWT before printing either receipt. This protects against a forged reply from a controller NATS credential alone. Controller hosts and the ticket signing key remain trusted.

## Role claim

Roles get NATS identities ([role identities](nats-fabric.md#role-identities))
only once the cell account holds the role signer. Material from
`generate-controller-material` carries it in `cell.jwt` since TS-663, so a
region founded from it needs no role claim. A cell founded before (gru-1,
sfo-1) adds it once from the region's offline controller material:

```sh
ts-orch bootstrap role-claim --material-directory "$MATERIAL" \
  --cell-jwt CURRENT_CELL_JWT --out /ABSOLUTE/PATH/cell-role.jwt
```

`CURRENT_CELL_JWT` is the claim the brokers hold: the material's `cell.jwt`
until a claim has been applied, otherwise the last applied JWT. The command
verifies the claim belongs to this material's cell account and operator,
keeps everything in it, adds the signer derived from the material's
`host-nats-issuer.seed`, signs it with `issuer-operator.seed` and prints
`role-signer` and the file's SHA-256. Running it again on its own output
changes only the issue time. Apply the file with `broker-claim-apply` as
above; the actor needs `can_rotate_broker_account`. A release that changes
the role scope (`roleidentity.Scope`, such as TS-668's query grants) needs
the same step again in every cell, right after its controllers run it: the
controllers issue role credentials only while the cell account holds
exactly their scope, and members keep their current credentials, valid for
48 hours, until then. Applying closes every
external NATS session once: clients reconnect when each broker's gate
reopens, within about 3 seconds, well inside a host session's 30 seconds.

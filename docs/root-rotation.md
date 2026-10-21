# Root key rotation

The image's baked trust roots (`/etc/terrascale-orchestrator/bootstrap/trust-roots`)
are only the **genesis** of the cell's root chain. Rotating a root never
needs a new image.

## Model

A rotation statement replaces the whole root set. It names its sequence, the
SHA-256 of the statement it replaces (or of the genesis key IDs for the first
one) and the new roots. It is valid only when signed by a majority of the
roots it replaces **and** by every new root, for exactly the cell's deployment
ID, cell and environment (domain `terrascale.trust.root-rotation`).

The authority leader stores the chain in the replicated JetStream KV record
`TS_TRUST_ROOTS/chain`. Every controller verifies the record from its own
genesis and adopts it only when it extends the chain it already holds. It
writes the adopted chain to
`/var/lib/terrascale-orchestrator-controller/trust/root-chain.json` before it
switches. The leader rewrites a removed, forked or shorter record with its
adopted chain. The record is automatically snapshotted to OCI
Object Storage with the other configuration buckets (see
[storage](storage.md)), so a rebuilt cell restores its rotations before the
chain opens; a restored record still verifies from genesis.

KV desired state (the [cell spec](cell-spec.md)) verifies with the newest
root set only, both when the leader applies a change and when a
controller re-reads the stored record. A rotation that would leave the stored
cell spec signed under a removed root is refused, so rotate make-before-break
when a spec is stored: add the new root, apply the next spec generation signed
under it, then remove the old root.

The pre-NATS bootstrap paths read the same file through
`bootstrapstart.LoadBakedInputs`: they accept genesis and every rotated root,
so the baked anchor and ledger records signed before a rotation, and
retirements signed after it, verify without a rebuild. A missing file means
genesis; a damaged or foreign file fails closed.

## Threat model: a leaked root

Rotating because a root leaked:

- A minority of the current roots cannot rotate. Bake several genesis roots,
  held apart, so one leak cannot rotate the cell.
- After a controller adopted the rotation, the leaked root cannot extend the
  chain, fork it (a rival statement does not extend the adopted chain) or
  roll it back (a shorter or rewritten KV record is refused and rewritten).
  Nothing it signs is accepted as KV desired state, even when written straight
  into the store with controller credentials.
- The leader applies a statement only while it is current (at most 7 days).

Limits of this slice:

- Before the rotation is adopted, the leaked root is as powerful as before.
- The pre-NATS bootstrap paths (baked anchor, bootstrap ledger, manifests,
  retirements) keep accepting every root on the adopted chain, including
  current-validity checks. A leaked replaced root plus write access to the
  bootstrap ledger bucket can still plant ledger records. Separating current
  and historical roots there is follow-up work.
- Controllers check currency only through the leader. A fully signed
  statement that was never applied can still be written into the store by a
  holder of controller credentials. If you abandon a signed statement, apply
  a different statement at the same sequence at once.
- A controller launched later from the same image starts from genesis until
  it reads the KV record (or its snapshot); carrying the chain at launch
  comes with controller scale-out.

## Runbook

1. Read the current chain: `ts-orch operator trust-roots --config OPERATOR_JSON --out chain.json`.
2. Each current root holder, then each new root holder, signs in turn,
   passing the previous output with `--signed`:

   ```sh
   ts-orch release sign-root-rotation --genesis-root 002.pem --chain chain.json \
     --deployment-id ID --cell CELL --environment ENV --new-root new-root.pub.pem \
     --signing-key OWNER_ONLY_KEY.pem [--signed partial.json] [--valid-for 24h] --out signed.json
   ```

   The output reports `"complete": true` once the statement has enough
   signatures.
3. Apply it: `ts-orch operator trust-rotate --config OPERATOR_JSON --file signed.json`.
   Re-applying is a no-op that also rewrites a lost or damaged record. If the
   cell stores a cell spec, the first rotation keeps the old root beside the
   new one; apply the next spec generation signed under the new root (or its
   delegation), then rotate again to drop the old root.
4. Re-issue the delegations the old root signed (for example
   `ts-orch release sign-spec-delegation` with the new root) and store the
   new root in OCI Vault.

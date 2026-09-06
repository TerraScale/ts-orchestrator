# Edge KV production contract repair

The cleanup review traced `cmd/orchestrator/reconcile.go` through `KVWriter`
to the retired `SetRegionHealth` and `SetDBPlacement` methods. They wrote bare
keys and JSON shapes that the current edge parser did not consume. The existing
`workermaps.go` API already defined the edge documents. The production writer
now uses that API; the retired CRUD methods and their separate round-trip test
are deleted. Their required behavior is exercised by current wire tests and
the local HTTP operations qualification.

Each tick replaces one versioned `regions` document before publishing changed
`db:<database-name>` placements. Names follow TerraBase's lowercase 1–63 byte
contract and retain their exact identity. Explicit residency becomes a region
list, with the placement generation preserved. Missing regions disappear from
the complete health document; removed database keys are deleted. Failed
deletions retain their retry baseline. Write accounting counts the single
health document and acknowledged placement keys.

Draining and overloaded observations cannot publish `ok: true`. Replication
lag is optional: absence means unknown and a measured zero remains explicit.
The edge consumer was updated in the same series. The bootstrap control
provider no longer derives or publishes edge health from control-replica
activation. Its descriptive edge-health fields and unused Cloudflare client
and credential dependency are removed. Control readiness and engine serving
readiness therefore have separate publishers.

The authenticated host collector and engine observation integration are
recorded in [observed region health](../operations/observed-region-health.md).
Live provider and six-guest
qualification remain required; local HTTP fixtures do not establish them.

Verification on the working changes:

- Cloudflare writer/current-wire tests and the local HTTP KV qualification pass.
- `go test ./src/orchestrator/cloudflare ./src/orchestrator/vmqualsuite ./cmd/orchestrator`
  passed before the subsequent authenticated collector integration.
- Bootstrap provider and Cloudflare package tests pass after removal of the
  control-derived edge-health publisher.
- Race tests pass for Cloudflare, bootstrap, and the VM qualification suite.
  Integrated race tests also pass for hostagent, hostcontrol, TBEP, ts-node,
  and the orchestrator command after the authenticated collector changes.
- Full repository verification must follow integration of the concurrently
  edited production adapters. No public launch or real-provider claim follows
  from these focused results.

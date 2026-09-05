# Pinned NATS R1-to-R3 empirical audit

This is an actual embedded NATS 2.14.6 / nats.go 1.53.1 experiment, using the repository's unmodified `initialcontrol.buildProfiles("gru", "gru-1")` and `provision`. The additional test exists only through `/tmp/ts-nats-promotion-audit/overlay.json`; no production source is changed.

A subsequent integrated restart failed the original consumer creation timestamp
invariant. See the [follow-up evidence](nats-snapshot-promotion-limits-2026-09-05.md).
The successful samples below do not establish stable consumer creation metadata
across every restart.

## Direct retained-store restart: unsupported by the tested sequence

Both source-first and peers-first were tested. GRU's same standalone file-store directory and account names were retained while adding a named cluster, shared system account, and routes to SFO/FRA. Each process had eight established route connections; JetStream metadata reached an exact three-member quorum, with both replicas current. GRU's local JSz still reported all 15 streams, three consumers, and all retained records (34 in the final run). Nevertheless, the cluster stream API returned `404 / 10059 / stream not found`. The local recovered streams were not registered as cluster stream assignments.

Source-first also showed that a listening GRU broker does not establish JetStream readiness before its declared peers are started: AccountInfo and an early R3 update timed out. Evidence: `result-negative-final.log` (final frozen-code run) and `result-diagnostic.log` and the per-server `TestAuditStandaloneToClusterR3-*.log` files. Each retained-stream phase was bounded to 30 seconds.

## Snapshot restore: content-preserving topology transition

The separate `snapshot-content` branch snapshots the entire original inventory through the public STREAM.SNAPSHOT API, with consumers and message checksum checking. It stops the original standalone broker and leaves that directory untouched, forms a fresh GRU/SFO/FRA cluster with a distinct GRU store directory, requires exact healthy metadata membership, and restores all 15 archives as R1 streams placed on GRU. It removes the temporary restore placement using the original stream configuration, then explicitly promotes all streams and all original durable consumers to R3.

The tested inventory is:

- GRU_CONTROL: CELL_EVENTS, CELL_OPERATIONS, CELL_SPEC; KV_ORCH_COMMAND_REPLAY, KV_ORCH_DELIVERY, KV_ORCH_LEADERS, KV_ORCH_OPERATIONS, KV_ORCH_OPERATION_PROOFS, KV_ORCH_RUNTIME; OBJ_CELL_BUNDLES, OBJ_ORCH_PROTOCOL_PACKAGE.
- GLOBAL_CONTROL: GLOBAL_SPEC; KV_GLOBAL_CELLS, KV_GLOBAL_DELIVERIES, KV_ORCH_LEADERS.
- Original durable consumers: GRU_CONTROL/CELL_EVENTS/runtime_startup; GRU_CONTROL/CELL_SPEC/gitops_cell_spec_gru-1; GLOBAL_CONTROL/GLOBAL_SPEC/global_cell_spec_gru. The audit adds no durable consumers.

Every original raw record is compared by full subject, header map (including multivalue headers and KV deletion markers), payload, sequence, and server-assigned timestamp. Exact stream configuration is compared except the admitted replica change and the metadata difference below. KV values/revisions/deletion semantics and object bytes are read through their actual APIs. All three original consumers are exercised with a real fetch and synchronous acknowledgement before snapshot; configuration, creation timestamp, delivered/ack-floor sequence positions and pending acknowledgement count survive restoration and promotion.

The audit requires two current replicas with the exact GRU/SFO/FRA names for each promoted stream and each original consumer, stops GRU and reads through SFO/FRA, then restarts all three brokers on their retained cluster directories and rechecks contents. After restart it publishes and consumes the exact next stream/consumer sequence using the original durable consumers.

### Material metadata difference

Clustered public snapshot restore resets **StreamInfo.Created** to the restore time for all 15 streams. The original server-assigned message timestamps and original consumer Created values are retained. The strict `snapshot-restore` branch intentionally fails the old stream Created equality assertion; see `result-negative-final.log` and `result-snapshot-strict.log`. The separate content branch records the old/new creation times and only then uses the restored creation time as the identity baseline for promotion and later restart checks. This is not an unchanged-stream-identity pass.

An admitted restoration receipt therefore needs the original account/name, original stream metadata, source snapshot digest, restored creation metadata, and exact retained application state. Stream Created alone cannot serve as an unchanged source identity across this operation.

### Explicit consumer promotion is necessary

All three consumers originally have `Replicas=1`. Increasing only the source streams to R3 does not promote those consumers. An initial stream-only experiment preserved stream contents but left consumer state unavailable when GRU stopped. The successful path explicitly updates each original consumer to `Replicas=3` and waits for its exact current peers. Consumer identity and checkpoints must be verified separately from stream replication.

## Configuration and ordering requirements established by this experiment

- Preserve the original account namespaces, complete original stream/KV/object/consumer configuration and snapshot content. Keep the old standalone directory separate from the new clustered GRU directory; do not overwrite it to obtain a cluster.
- Form routes and exact metadata quorum before restoring on the GRU placement. An AccountInfo reply alone can arrive while GRU has not yet joined: a restore then fails with `no suitable peers for placement, tags not matched ['region:gru']`.
- All three servers use one named cluster and system account, unique stable server names, and per-node retained file-store directories. A full restart must retain the new cluster's metadata/Raft state and data directories.
- Per-node file-store budget in this test was the actual initial profile budget, 4,144,234,496 bytes (3,875,799,040 reserved profile bytes plus 256 MiB overhead). All stores remain file-backed and finite.
- Public restore of an already existing stream is not an idempotent overwrite contract. A production retry must verify the admitted existing restored state, or resume a missing restoration, without deleting an already restored stream to force a retry.

## Scope

The test has no background application writers during capture and fully stops the old broker before the clustered target becomes usable. It demonstrates the broker/storage mechanism, not a production quiescence or credential-revocation implementation. The actual lifecycle still needs an admitted final snapshot cut, durable fencing/stop receipts, restoration receipts and restart-safe replay under the existing action/host journals. Initial grant expiry and preserved message ages remain applicable; the test completes before its shortest retained record expiry. Transport uses loopback test credentials, so it does not qualify the production TLS/route authorization configuration.

Run the successful content audit with:

```
go test -race -overlay /tmp/ts-nats-promotion-audit/overlay.json ./src/orchestrator/initialcontrol -run '^TestAuditStandaloneToClusterR3/snapshot-content$' -count=1 -v
```

Running all audit branches is expected to fail because the direct restart and strict original-Created branches preserve their negative assertions.

## Frozen evidence

Final successful race command passed in **15.258s** (test body14.17s). Final direct-restart and strict-Created negative command failed as expected in69.58s. The same frozen Go audit source produced both logs. The separate permanent focused test passed under the race detector in13.891s.

Persistent successful evidence directory: `/tmp/ts-nats-promotion-audit/snapshot-content-3858076857`. It contains the untouched original GRU standalone directory, the fresh clustered store directories, and15 snapshot blobs with Config/State sidecars. The original standalone tree digest stayed `5a6ca3d98f65ffd5a52000598e960af3b9a7e808e54cb0f8bbfc77284ba103fa` before and after all cluster operations.

| Artifact | SHA-256 |
|---|---|
| `/tmp/ts-nats-promotion-audit/promotion_test.go` | `72a8ea8a6bd0bf112f3f4601eb5198938b776c89bbb8a62d0c5e1d50ad6811ad` |
| `/tmp/ts-nats-promotion-audit/overlay.json` | `b9cc09fac46616d31b86fd29ce2c51bff692f82c01ba103c462c96980ed60958` |
| `/tmp/ts-nats-promotion-audit/result-content-race.log` | `ea8f8cb3b9e084bac93e4c8c1dd5735ba6f6cb114fbf749929bfbbc70155a425` |
| `/tmp/ts-nats-promotion-audit/result-negative-final.log` | `a8e0a6735c25483461bdd02abfd9ef0580a467e13e808d0a6f038a2dd9c80f9d` |
| `/home/mariogk/Projects/TerraScale/ts-orchestrator/go.mod` | `4c405aad2380db00cb8c5fbde0586cf0bcc288edfaea0051f7124fe5cae70a3e` |
| `/home/mariogk/Projects/TerraScale/ts-orchestrator/go.sum` | `a265f0a42dd23fde686c8860f88bad96ba27280e47fc03d498ceb3975ff4e8cc` |
| `/home/mariogk/Projects/TerraScale/ts-orchestrator/src/orchestrator/initialcontrol/profile.go` | `a1ab6f128df1a669db5697f5bfd6a6663c45af1273cdfbe101a0463d5fec9c8b` |
| `/home/mariogk/Projects/TerraScale/ts-orchestrator/src/orchestrator/initialcontrol/provision.go` | `470b0c00550564960e52b52763cc2a50238230d1e0acfde406ba9f6155ea395a` |

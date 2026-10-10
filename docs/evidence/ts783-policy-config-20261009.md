# TS-783 retired rollout policy fields: live audit

Read-only audit on delta, **2026-10-09 22:02:04–22:02:06 UTC**, using source
`c649ed8264e76a78d64765bd26f5eaf4dde442c3`. Each remote read asserted its
hostname before inspecting files. No cell, process, credential or stored record
was changed.

All six installed `/etc/terrascale-orchestrator/controller.json` files and
their manifest configs omit `controller.rollouts.policy` and `rollout_policy`.
Their installed config and manifest digests match adopted material generation
2. The installed config SHA-256 values are:

| Verified host | Config SHA-256 |
| --- | --- |
| gru-1-ctl-1 | `bf1f38d8098346936ca9f0a9c1ae020de565467b868ad2d9e6358184bc86730c` |
| gru-1-ctl-2 | `6ded450f81379d1e61ade1153e114a33708041545c0cee3312b6fe6ed0c1e792` |
| gru-1-ctl-3 | `0dd9b6889e5b91e003bc5cd21327c76a0fc435148481bcf42b2c9f85e73c182a` |
| ts-sfo-1 | `1c72bdc816f095632a24879ad561cad0389879afbd5fc9870f28a99d6704bdad` |
| ts-sfo-2 | `f35ea4e98d23b5d2669c90c4e76a43dba9f75f63de66161fbf7d81274df31302` |
| ts-sfo-3 | `1aa6e4fcc7b670a9cacc020064effcd7c6999f5799ef9977652dfecf5f27668e` |

Authenticated JetStream reads used each controller's existing JWT and mTLS
credentials locally, requesting only stream info and the last message for
`$KV.TS_SERVICE_SET.current`. Raw stored bytes were decoded before checking
field absence, so typed decoding cannot hide a retired member. Every endpoint
in a region returned the same signed record hash:

| Region | Spec generation / KV revision | Signed wire SHA-256 | Explicit signers |
| --- | --- | --- | --- |
| GRU | 14 / 26 | `6bedaab25c55d19bd1325d9450745981d02f6d52db568b1b3691d669b650039a` | 2 |
| SFO | 10 / 10 | `74ededbe093ec7dc175b7c9c16e5c9d3fae509642b549973e2457a29d803e18e` | 1 |

Both records omit `rollout_policy` throughout their signed bytes and retain
explicit signer restrictions. No signed replacement is needed for this state.
Repeat the reads before installing the new binary if the configuration changes.

This audit establishes field absence, pin consistency and current stored bytes.
It does not establish restart success, complete admission verification or timed
promotion/rollback. GRU's mixed predecessor remains a separate rollout blocker.

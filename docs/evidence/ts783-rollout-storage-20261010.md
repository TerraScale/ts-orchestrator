# TS-783 read-only rollout-store audit

The required digest-member finding is a real deployment hazard. The code fix
retains the original v1 slot and ID-marker format; this audit is evidence of
live state, not a substitute for old-writer/new-reader regression coverage.

## Targets and read boundary

On 2026-10-10 at 02:07:32–02:08:10 UTC (2026-10-09 local), the audit asserted
`gru-1-ctl-1` and `ts-sfo-1` before reading controller configuration or
credentials. Connections used the existing NetBird SSH path, controller-local
JWT authentication and matching mTLS files. Private material remained on each
controller and was neither printed nor saved.

The only JetStream request subjects were:

```text
$JS.API.STREAM.INFO.KV_TS_ROLLOUTS
$JS.API.STREAM.MSG.GET.KV_TS_ROLLOUTS
```

Message reads used `seq` and `next_by_subj=$KV.TS_ROLLOUTS.>` within the stream
sequence bounds captured by the initial information request. The audit
retained the newest observed metadata per key, including raw-value SHA-256,
member names, rollout ID, phase and attempt counts. It created no consumer,
published no KV value, changed no data and started no rollout or restart.
The bounded scan is not an atomic snapshot or independent semantic/signature
validation of every record.

## Observed state

| Region | Stream sequence range / stored messages | Retained history | Distinct observed keys | Current slot |
| --- | --- | --- | --- | --- |
| GRU | 158–844 / 115 | 8 | 24 | `release-g5-controllers`, active |
| SFO | 1–853 / 107 | 8 | 17 | Idle |

GRU's cell value at sequence 809 contains `schema_version`, `cell`,
`active_rollout_id`, `known_bad` and `attempts`, without `active_to_digest`.
Its SHA-256 is
`079b220c1b36c50621e795faf428854ca15f3fbc376519a43ce53df27fb507e1`.
The matching older-format `rollout.release-g5-controllers` value at sequence
844 reports `phase=frozen`, with SHA-256
`03f4c9b500e055724bbee417b0eb0786e2f7ed4dd6d3c31315574bf22dc8f006`.

SFO's idle cell value at sequence 850 contains only `schema_version` and
`cell`, with SHA-256
`2283e5e08b3d5d903dd7620d01508a29cd4f3babc109f3546699341c053d96e8`.
No newest observed JSON value in either scan contained `abandoned_rollout`.
One GRU `host.3ada5f14afaa91c2b511e1f3a8b271cb` value was not JSON; the audit
recorded that fact without exposing its contents. No value was repaired.

Metadata-report SHA-256 values:

- GRU: `e55ee6ef834ed9de10262ae952134c1a2c5e7498517115c5735d74b288bb6072`
- SFO: `558d110585d02d215eea2c227118c98e5cd1264e9d64dcaea9bd3f2360493cbd`

## Deployment limits

The frozen GRU program and mixed predecessor binaries remain unresolved.
Both stores also contain older string-based operational/release keys, such as
`rollout.release-g5-controllers` and `release.gen.1`. Fetched main
`3473c03dd1ff81f280b7836b61211076acecf096` already expects entity IDs in
`CellState.validate`, `Load` and `ReleasePins`. Removing the two TS-783 digest
additions does not convert those older identifiers or make this live state
deployable. No migration, alternate decoder, counter reset, marker deletion
or serving-cell rebuild is included in this slice.

Resolve and verify those existing deployment boundaries before the later
in-place rollout/drill. Preserve known-bad authority, permanent ID exclusion
and retained rollback releases. This audit does not authorize guessing a
refund when the record and matching retained generation are both absent.

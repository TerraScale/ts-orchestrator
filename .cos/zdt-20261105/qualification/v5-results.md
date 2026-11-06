# v5 (plan v3) read-only qualification — HOLD, NOT GO-ready

Blocker: steps 5–7 need root on each worker, and v3 has no path to it. OCI power
actions cover only stop and start. A started worker boots its old ts-orch and agent
state (`worker.Init` restarts assigned tasks). `arm-stopped`, `stage` and `replace`
run locally as root, and FRA's retained owner is ts-fra-2. Run Command has no IAM
grant and no `ocarun` root. Next decision: NEED Q-ZDTWORKEREXEC, in deploy-plan-v2.md.

- `v5-oci-worker-instances.json`: 3 worker instances are RUNNING, each with one
  ATTACHED boot volume and no block volumes. user_data is unchanged.
  Administrators allows power actions by policy (not exercised).
- JetStream meta group and the three R3 KV groups are founders-only, so step 4
  keeps quorum with the workers off (read from the founder `_js_` peers/dirs).
- `v5-founder-backup-real.json`: real live bytes GRU 37.2 MB, SJC 13.9 MB,
  FRA 9.7 MB. Three repeats each, source and destination SHA256 match, hashed and
  discarded on mariogk-dev. Budgets 5/10/9 s against the 150 s reserve.
- No production mutation: no power action, stop, key change, install or publication.

# TS-641 cross-region copies and key proof, 2026-10-08

This continues the [2026-10-07 record](ts-641-replication-20261007.md). It
completes the copy preparation in both directions and proves that a copied
GRU data key unwraps in SFO. No full-cell drill ran; RTO/RPO remain
unmeasured. Serving GRU was not re-founded, restarted or used as a drill
target, and no source object changed.

## Source inventory before apply

Read-only listings at about 11:35 UTC:

| Bucket | Current objects | Bytes | Missing from the mirror |
| --- | ---: | ---: | ---: |
| `gru-1-backup` | 58,726 | about 12.2 GB | 11,778 (2.3 GB, incl. 5 wrapped data keys) |
| `sfo-1-dr-gru-1-backup` (mirror) | 47,018 | about 9.9 GB | |
| `gru-1-head` | 75 | 3,448,972,510 | no policy yet |
| `sfo-1-head` | 17 | 86,688,232 | no policy yet |
| `sfo-1-backup` | 0 | 0 | no policy yet |

No source object had a multipart or missing MD5. A sequential pass at about
3 s per copy would have taken about half a day, so the seed step now skips
objects already identical in the mirror and copies with 16 workers.

## Run 1: binary `588f9bda`

SHA-256 `3d68bc2c4927a7556efc3a6229f6fd70611b7a953ef4d2168078618d670d8ba6`,
11:40:18 to 13:10:56 UTC, exit 1.

| Direction | Result |
| --- | --- |
| GRU Vault replica in us-sanjose-1 | Reused, `CREATED`. |
| `gru-1-backup` | Policy `13d06611-adab-4443-afd0-4a57eaca82f3` active. 11,674 objects seeded and 51,095 found identical in the mirror, each by size and MD5 readback; 104 were already seeded. |
| `gru-1-head` | Created mirror `sfo-1-dr-gru-1-head`, versioned seed `sfo-1-dr-gru-1-head-seed` and policy `5c7f0c59-a1a7-4e8a-a5ed-7610cc481248`; 76 objects seeded. |
| SFO Vault replica in sa-saopaulo-1 | Created. OCI first listed it with an empty status; the poll treated that as fatal and the run stopped. Fixed in `e5d7ff1f`; the replica reached `CREATED` by 13:13 UTC. |

The new IDs are pinned in [the command config](../../deploy/oci-region/disaster-recovery.json).

## Run 2: binary `e5d7ff1f`

SHA-256 `5b72bf4592d9648c99faa4ecac48934019be6d729e4477ba32729e317e311612`,
13:13:34 to 14:20:00 UTC, exit 0. Every object counted below was matched
by size and MD5 readback; objects a previous pass had seeded are not counted.

| Direction | Policy | Result |
| --- | --- | --- |
| `gru-1-backup` → `sfo-1-dr-gru-1-backup{,-seed}` | `13d06611-adab-4443-afd0-4a57eaca82f3`, last sync 14:17:46 | 1 seeded, 55,131 identical in the mirror |
| `gru-1-head` → `sfo-1-dr-gru-1-head{,-seed}` | `5c7f0c59-a1a7-4e8a-a5ed-7610cc481248`, last sync 14:18:03 | 0 seeded, 3 identical in the mirror |
| `sfo-1-backup` → `gru-1-dr-sfo-1-backup{,-seed}` | `facc64ad-2071-497f-97dd-56b76b4554ae` (created) | Buckets created; source is empty because sfo TerraBase backup is not configured yet |
| `sfo-1-head` → `gru-1-dr-sfo-1-head{,-seed}` | `ba0d7d3a-acb4-4711-9dec-8ae8022458ab` (created) | Buckets created; 17 objects seeded |

Both Vault replicas were `CREATED`. A read-only run of the same binary
against the fully pinned config passed at 14:20:30 UTC: all four policies
were bound to their pinned mirrors and `ACTIVE`, and both replicas were
`CREATED`. The SFO→GRU bucket and policy IDs are pinned in the config too.

There are no SFO TerraBase backups or wrapped keys yet, so the reverse
key proof has nothing to unwrap; repeat it once sfo-1 ships backups.

## Copied data key unwraps in SFO

A one-off program (not shipped) refused every connection to a host outside
us-sanjose-1 at dial time, so no GRU endpoint was reachable. It read a
wrapped data key from the SFO seed, called `decrypt` at the GRU Vault's SFO
replica with the original master key
`ocid1.key.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljruhejdps4hz4tqyfmuokgfz3yunzaqnbx6ywr4r24cd2oevmcjacq`
(`gru-1-terrabase-backup`), then derived the object key and authenticated
AES-GCM chunk 0 of a copied backup object from the SFO mirror. It printed
no key material.

| Data key (seed) | Backup object (mirror) | Unwrapped | Chunk 0 |
| --- | --- | --- | --- |
| `v1/keys/_system/01M4BQRCV9X8ADMYW08F7FVZE5` | `v1/_system/snapshots/1791464600986-01M4DSRXCDDR472QB3A2FFCHTD-…` (21,295 B) | 32 bytes | authenticated |
| `v1/keys/01a11059-…/01a11059-a955-…/01M4BQFN0K5E0T3AD2A9N9Z71B` | `…/01a1193d-ae71-…/snapshots/1791429815061-01M4CRK8TTG2S7KJ3F5BFTNH1T-…` (24,700,209 B) | 32 bytes | authenticated |

Checked at 13:12 UTC. All six wrapped data keys are now in SFO: five in the
seed, one in the mirror.

Neither listed replica endpoint resolves. OCI lists them in the source
region's domain, while each region publishes only its own:

| Listed replica endpoint | Resolves | Working form |
| --- | --- | --- |
| `ffvmfu2naagt6-crypto.kms.us-sanjose-1.oraclecloud.com` | no | `….us-sanjose-1.oci.oraclecloud.com` (140.204.58.166), used above |
| `grvmmkplaacx6-crypto.kms.sa-saopaulo-1.oci.oraclecloud.com` | no | `….sa-saopaulo-1.oraclecloud.com` (140.204.12.235) |

## Not done

This proves the copies and keys, not a recovery. Still required before RTO
and RPO can be measured (see the [runbook](../disaster-recovery.md)):

1. TerraBase cold restore of `_system` and every database at one PITR second
   from mirror + seed, through ts-go (TS-743).
2. A ts-orch control-state recovery bundle and destination-authorized import
   into sfo-1, plus sfo rollback.
3. Vault secret replication (bootstrap, role secrets, ts-auth keys, S3 and
   KMS API credentials); key replication does not copy secrets.
4. ts-auth restore, data comparison against the source, then the monthly
   drill with failure alerts.

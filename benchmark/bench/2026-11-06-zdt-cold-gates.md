# Cold-maintenance backup path rehearsal — production HOLD

The installed fleet removal cannot cold-stop the last regional TerraBase writer.
No maintenance window is authorized. Worker SSH, complete six-node backup sizing,
and exact BUILD-green shipped revisions remain prerequisites. No production
service, process, KV record, firewall, workflow or credential was changed.

Three measured repeats per accessible founder use real read-only sizes from
`/var/lib/ts-data/terrabase`, local synthetic files of the same sizes, encrypted
backup/decrypt readback on mariogk-dev, then equivalent incompressible archive bytes
from that production founder over existing root SSH stdout to mariogk-dev. Full
source/destination SHA256 and byte length agree. No serving DB bytes were copied.
The eventual off-host cold archive transfer must use that same route (`ssh` with
compression disabled and privileged `cat` stdout), not a newly selected transport.

| Node | Live file bytes | Files | Total proxy copy + transfer/readback seconds, ×3 | ceil(max ×1.5), seconds |
| --- | ---: | ---: | --- | ---: |
| ts-gru-1 | 26,780,425 | 112 | 2.168 / 1.975 / 2.053 | 4 |
| ts-sjc-1 | 24,134,351 | 61 | 6.980 / 6.934 / 6.904 | 11 |
| ts-fra-1 | 10,896,355 | 76 | 5.659 / 5.548 / 5.539 | 9 |

The local filesystem/encryption portion is a **dev-host proxy**, not measured cold
copy on the serving filesystem. The SSH portion is the actual planned link.
These numbers qualify only the inventoried principal root on the founders;
workers and any additional mounts are **not qualified**. Refresh all six inventories
before GO; if a root exceeds its measured equivalent size, rerun the rehearsal.
Do not extrapolate worker bytes or call three roots a complete cold backup.
The existing 150-second reservation remains a ceiling pending all-six measurements.

Reproduction: `scripts/maintenance/qualify-founder-backup-path.py` through
`ts-heavy-any`; exact source hash, individual source times, archive sizes, copy and
transfer times and received hashes are in
`.cos/zdt-20261105/qualification/v4-founder-backup-path.json`.
The separate full retained-data backup/conditional-KV/firewall/pidfd regression
passes 2/2 after the new gate additions; physical TERM→KILL exit measured20.082s.

The fixed 60-second no-reappearance watches pass **both barriers ×5 =10/10**:
60.0079–60.0146 seconds, 236–238 complete samples each. Real processes appearing
mid-watch and new real shim task directories cause abort receipts. Runtime read
failure and abort/incomplete/wrong-barrier receipts refuse fleet advancement.
The test uses isolated real PID/mount namespaces, proc and task directories;
runtime API replies are contract fixtures. The actual task parser separately
passes read-only checks on all three live founders. This is not a real daemon
restart or worker execution proof. Exact sources/log hashes and durations are in
`.cos/zdt-20261105/qualification/v4-watch-proof.json`.
Earlier qualification attempts exposed fixture executable portability issues
(absent /bin/sleep, then a multicall coreutils argv0 requirement); the final fixture
uses a real Python process with an engine entrypoint argv0 and runs refusal cases
before each full watch. Those failed attempts are not included in the10/10 pass.
Neither rehearsal is a production exit receipt or authorization to deploy.

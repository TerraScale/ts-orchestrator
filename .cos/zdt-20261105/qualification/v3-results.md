# v2 review blockers — local qualification, production HOLD

All five code/driver review items have concrete changes and local proof. This is
**not GO-ready evidence for every production gate**: worker units/control/restart
labels are not read back; complete six-node backup sizing and production transport
rehearsal remain pre-window gates; exact green-main CI is required after approved
shipping. No rollout, process restart, manual CAS, key deletion, workflow enable,
status notification or customer load was performed. Bounded read-only OCI audit
commands stayed ACCEPTED and were canceled.

Engine candidate `1a4775488d0c6662850d08827b0d72cae3ca7047` on fresh main
`a811367bd82e0cbe510cd2340fc93e25f81c2dd0`. Orchestrator candidate
`21e0830db0ebfa6fa91a49b2418a3ab69d15a7d0` on fresh main `2142b1f308b1c1169d25093f93eab3b10c479e1c`.
Both rebases are up to date. Docs-only report commits may follow; exact runtime
and test bytes match the retained source manifests. Nothing is pushed.

## A/C: publication crash and retained metadata

The activated owner CAS now precedes the protocol marker. A healthy restarted
owner reasserts a missing marker before resume/renew; an exact retained Version:0
self-certificate repairs the old marker-first orphan with Previous:null. The
legacy owner remains pinned: no follower can take its files during bootstrap.

Both crash cuts pass ×5. Legacy-marker-first recovery is
6.079, 6.114, 6.079, 5.861, 6.368 s;
owner-first recovery is
6.428, 6.240, 6.225, 6.175, 6.378 s.
Bound: **30 seconds after the retained pinned owner restarts healthy with working
quorum**; restarting that process is the runtime/operator prerequisite. A dead
Version:0 owner is deliberately not reassigned. v2 target failures recover a writer
automatically through TTL/retained phases; observed maximum before target lease
acquisition 12.104 s,
after acquisition 12.596 s,
both below 30 s. These are measured recoveries, not whole test wall times.

Rollback keeps owner value/node/epoch, protocol/prepared records, real leases and
the two reviewed stale-key tombstones. b443 can renew an identical owner by CAS,
so its owner revision may advance; protocol/prepared exact revisions remain fixed.
No valid certificates, owner records, acknowledged rows or JetStream state rewind.

## B: real-b443 rollback on retained files

The new drill runs candidate v2 → actual unmodified b443 Program → candidate v2
on the same primary files. It acknowledges rows at each stage and reconciles all
six exact IDs afterward, retaining owner/epoch and protocol/prepared keys.
Five repeats pass. Real b443 source
`b443b6ea83f519018c0d9f9d8f04e65c3df12724`; x64 Debug DLL SHA256
`2e600b4334843c378acaf42977cd43c82b604078452e05d424c14c3855ea227d`. This is a monorepo dev build, not a qualification
of the production arm64 artifact/container install.

The full retained-controller/Swarm restore set and all-peer anti-entropy hazard
are written in deploy-plan-v2.md, addendum B. Snapshot all six offline Swarm states,
original selected desired candidates/floors and bake/provenance, original binary/
units and release receipts. Restore original b443 desired state on **every peer**
with all publishers held. Preserve latest embedded JetStream stores and real
lease/protocol/prepared state; never restore a whole old mesh directory over it.

## Full engine proof

13 regional Slow drills ×5 = **65/65 PASS, zero failed** on mariogk-dev through
ts-heavy-any. Includes the prior 11 accepted crash/fencing/legacy/follower cases,
plus both publication crash cuts and retained-file rollback. All assertions run
against real native files, real TCP faults and dev NATS; no production data/load.

Affected Fast: **66/66 TerraBase**, 9.224 s test / 12.107 s wrapper;
**4/4 native driver**, 0.767 s test / 7.219 s wrapper. Every Fast test is below10s.
Exact names, five test durations and source/log SHA256 are in v3-engine-proof.json.
Earlier failed assertions/transport attempts remain recorded and are not passes.

## D/E: executable operator barriers

`scripts/maintenance/cold.py` implements a narrow nft gate + exact owned-table
undo, all-namespace restart-label refusal, PID/start/executable-pinned pidfd stop
(TERM20s → KILL5s), cold local/encrypted backup with full readback, complete
paginated native checksum inventory and comparison, and allowlisted revision-
conditional KV DEL with dry run and a fsynced receipt per key. CLI alarms bound
steps; the plan has hard elapsed abort limits through reopen600s/status900s.
`notice.py` prepares/posts the actual authenticated admin form with CSRF and public
readback; only its local form contract was qualified. No notice was published.

Two critical local cases ×5 = **10/10 PASS**. The nft apply/undo runs in a new
network namespace. Actual TERM-ignoring processes exit after KILL in
20.022–20.069 s.
The DEL proof uses real dev JetStream; stale revisions, concurrent update, unsafe
restart labels, symlinks and moved DB revisions refuse advancement. Test receipts
and full source hashes are in v3-maintenance-proof.json.

Three backup/transport repeats each cover **67,108,872 source bytes**, localcopy,
file hashes/metadata, encryption, full decrypt/tar readback, off-host encrypted
copy and exact SHA/size readback. Local time0.676–0.730s; transfer/readback
1.612–1.648s, beta→mariogk-dev, existing authorized transport. All temp copies
removed afterward. This is dev transport, **not** the production link estimate.
Read-only founder sizes: GRU34,110,984B, SJC5,923,235B, FRA18,818,882B at03:34Z;
workers/other mounts remain unmeasured. Do not extrapolate a complete six-node
backup from three roots or reopen if cold and logical inventories disagree.

## Parked orchestrator Fast failures

Fixed public test fixtures that inherited umask077 and protected staging that
traversed unsearchable root-owned parents as an unprivileged user. Explicit public
fixture chmod and privileged symlink/component checks retain the real permission
barriers. A protected-parent symlink escape is still refused. Five affected
package repeats pass. Then full make test-fast passes **892 cases /346 shards**,
zero failed, max shard2.760s; final rerun follows the maintenance qualification.
No production modes were weakened. v3-maintenance-proof.json and raw logs retain
that final full-Fast result.

## Read-only production gates

Founders' live systemd readback passes: Wants containerd without a stop-propagating
dependency; containerd KillMode=process and no socket trigger. Founder ts-orch
stop timeout60s differs from source180s. Exact unit properties are retained.

Workers: **derived, not read back**. No SSH exists and none was added. Existing
authenticated member/edge APIs have no systemd execution capability. All three
OCI Run Command plugins report RUNNING but audit commands remained ACCEPTED,
then cancellation succeeded. Actual OCI launch metadata's decoded unit/runtime
bytes match the provisioning source, and actual image IDs resolve to the expected
AVAILABLE Ubuntu24.04 arm64 build. Archive/binary SHA pins are retained. This
proves provisioning, not current drift or restart-label state. Parent decides
whether this evidence suffices; it does not give us a usable mutation path.

**Remaining pre-GO gates:** independent review/GO; approved usable six-node control
and physical-exit path; parent decision on derived worker units; complete data/
controller inventories and production backup timing; exact post-ship green main.
Recent origin main runs still include failures (TerraBase Slow/Landing and orch
Slow). We did not re-enable workflows or relabel a local pass as green main.
The three live zero-error p99<500ms rollout proofs, bounded429/backlog recovery,
load-account cleanup and acceptance item1 HANDOFF remain held and outstanding.
#1104 is not closed; no NATS-notice durability claim is made.

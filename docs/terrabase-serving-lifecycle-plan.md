# TerraBase serving lifecycle

Status: the health gate, drain and rollback below are implemented and
tested locally against the real C# binary; nothing here has run on OCI.
Sections marked **PROPOSED** are not implemented and are not deployment
authorization. The binary and host contract are in
[TerraBase runtime contract](terrabase-runtime-contract.md); the operator
workflow is in [TerraBase deployment](terrabase-deployment.md).

## What exists now

- **Health gate.** The host reports a member `starting` after launch and
  `running` only while `GET http://127.0.0.1:<admin-port>/healthz` answers
  200 `{"status":"ok"}` and, with a client listener, its TLS `/readyz`
  answers 200 (TS-571). `operator terrabase-release` counts only `running`
  as ready. Until TerraBase TS-561 gates `/readyz` on catch-up, this says
  the member serves, not that it holds current data.
- **Drain.** Stopping or replacing a member sends SIGTERM and waits up to
  45 s for the process to exit before its cgroup is killed. The binary stops
  accepting, drains in-flight requests and exits 0. Session loss and agent
  shutdown still kill at once.
- **Rollout and rollback.** `operator terrabase-release` moves every member
  to one digest at once and waits for every member to report it `running`.
  A release that fails the gate is rolled back automatically to the previous
  digest, which must pass the same gate; the command fails either way.
- **Static membership.** `TERRABASE_PEERS` in the signed workload profile
  names every member. The controller issues a member certificate only to a
  listed host, with that host's name and address. Changing the list needs a
  signed controller config change and a new release.

## What remains open

Each item names its owner where one is assigned.

1. **Replication handshake (TerraBase TS-464).** The binary's
   `terrabase.v1.Replication/Sync` service rejects the handshake with
   `Unimplemented`. Until it is implemented, each member is an independent
   database. TS-464 also re-reads the peer certificate files on the next
   handshake after they change, but not the client listener's; the current
   release binary re-reads neither, so the host checks the certificates a
   member serves and restarts it only when one is about to expire.
2. **N-node membership (TerraBase TS-469).** The binary has no peer-list
   setting. **PROPOSED:** TS-469 adopts a `peers` setting with the
   `name=ip:port` format of `TERRABASE_PEERS`, or the orchestrator renames
   its key to match.
3. **Serving proof and readiness beyond `/healthz`.** The host gates
   `running` on the client `/readyz` too (TS-571), but `/readyz` does not
   yet say a member has caught up with its peers or can accept writes
   under the chosen durability policy. TerraBase TS-561 makes it wait for
   replication catch-up.
4. **Per-member rollout.** **PROPOSED:** with replication and a serving
   signal, `terrabase-release` updates one member at a time and waits for
   it to serve before the next, instead of restarting every member at once.
   [Zero-downtime TerraBase rollouts](terrabase-zero-downtime-rollouts.md)
   (TS-571) is the design.
5. **Durable drain receipt.** SIGTERM and process exit say nothing about
   writes that other members have not received. **PROPOSED:** a drain
   command that stops write admission and returns a receipt naming the
   surviving members that hold every admitted write, required before a
   member is removed.
6. **Scale-in.** Removing a member or its host is not implemented.
   **PROPOSED:** scale-in changes `TERRABASE_PEERS` through a signed config
   change, drains the departing member with a durable receipt, and only
   then withdraws its desired and retires the host. Data under
   `terrabase_root` is not retained when a host is replaced.

## Retired terrabase-rust plan

This document previously described a proposed OpenRaft 0.9.25 managed-Raft
profile for the Rust `tb-server`, with signed genesis, quorum writes,
linearizable reads and a four-to-three voter retirement flow. It was never
implemented, and the Rust binary is retired. Git history keeps its full
text.

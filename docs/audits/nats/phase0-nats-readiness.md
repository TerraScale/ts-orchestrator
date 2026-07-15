# Phase 0 NATS candidate and L0C readiness audit

- Audit date: 2026-07-13
- Status: candidate evidence, not a version selection or N/N-1 policy
- Local evidence: bounded credential-free x86_64 loopback smoke only
- Qualification: full L0C, ARM64, L1–L5, and production qualification are not achieved

## Candidate evidence

The official NATS server release currently identified by this audit is 2.14.3. Its release publishes Linux amd64 and arm64 archives with GitHub-supplied SHA-256 digests. Version 2.12.7 is retained only as a prior-train compatibility candidate; the audit does not assert that 2.14/2.12 is TerraScale's approved N/N-1 window. The 2.12.7 release itself directs operators to its upgrade guide for compatibility notes, which is evidence that release notes and executable mixed-version tests—not SemVer inference—must control the decision. See the official [2.14.3 release](https://github.com/nats-io/nats-server/releases/tag/v2.14.3), [2.12.7 release](https://github.com/nats-io/nats-server/releases/tag/v2.12.7), and [server installation/architecture matrix](https://docs.nats.io/running-a-nats-service/introduction/installation).

The client candidates are `NATS.Net` 3.0.0 and 2.8.2. Version 3.0.0 is a newly published major and is not promoted merely because it is current; its subject-validation/NKeys and other compatibility changes require the same contract suite. Both NuGet packages were downloaded from the official NuGet flat-container endpoints solely to calculate the recorded SHA-256/byte size and inspect their managed target-framework directories, then deleted. The packages are managed IL/AnyCPU candidates, but neither was executed on ARM64. See the official [NATS.Net 3.0.0 release](https://github.com/nats-io/nats.net/releases/tag/v3.0.0) and [NuGet version index](https://api.nuget.org/v3-flatcontainer/nats.net/index.json).

The CLI candidate is 0.4.0 with official Linux amd64 and arm64 asset digests. It is a candidate administrative/test tool, not a production runtime dependency or an accepted pin. See the official [NATS CLI 0.4.0 release](https://github.com/nats-io/natscli/releases/tag/v0.4.0) and [CLI repository](https://github.com/nats-io/natscli).

`testlab/pins/nats-candidates.json` records exact URLs, SHA-256 digests, sizes, architectures, release timestamps, and selection state. Every `selected` field is false, `nMinusOnePolicy` is null, and the candidate pair is unexecuted. The repository still needs internal mirrors/signatures and independent archive verification before any candidate becomes an approved supply-chain pin.

## Capability and security evidence

The 27-row matrix covers every capability at `ORCHESTRATOR.md:465-488`, plus mandatory mTLS, snapshot/peer recovery, and mixed-version behavior. Every row has a precise specification anchor and an official NATS source. The primary references include:

- [JWT/operator security](https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt) for decentralized operators, accounts, users, signing keys, and scoped credentials.
- [TLS configuration](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/tls) for client, route, and gateway transport security.
- [Gateways](https://docs.nats.io/running-a-nats-service/configuration/gateways) for supercluster topology behavior.
- [JetStream clustering administration](https://docs.nats.io/running-a-nats-service/configuration/clustering/jetstream_clustering/administration) for peer and clustered stream administration.
- [KV](https://docs.nats.io/using-nats/developer/develop_jetstream/kv) for revisions, CAS-style update, history, and watch behavior, and [Object Store](https://docs.nats.io/using-nats/developer/develop_jetstream/object) for chunked objects and object metadata/digests.
- [Monitoring](https://docs.nats.io/running-a-nats-service/configuration/monitoring), whose security warning supports the specification's loopback/management-network boundary rather than treating HTTP monitoring as an authenticated application endpoint.

Primary documentation establishes that features exist and describes intended semantics; it does not prove TerraScale's generated permissions, topology, retention, durability, or recovery behavior. Those rows remain unexecuted until exact generated contracts exist.

## Executed local evidence

The installed host binary reported `nats-server: v2.14.3` and SHA-256 `4eb890bba37997898c81ef16c736f2c34cb594f4279b194c0404c7508dad5149`. It is a local Nix-provided x86_64 binary and its digest intentionally differs from the upstream amd64 archive digest. Presence and smoke success do not approve that host path as the production artifact.

`testlab/nats/run_local_l0c_smoke.py` starts one process with JetStream and monitoring on dynamically allocated loopback ports, uses a unique temporary file store, and has a `finally` cleanup boundary that terminates or kills and waits for the process. It proves:

- Core pub/sub.
- Core request/reply.
- Single-server file-backed JetStream stream creation, publish acknowledgement, and direct message retrieval.
- A loopback monitoring health response.
- Process cleanup and temporary-store removal.

The checked report is deterministic and reproducible byte-for-byte. It binds the result to both the observed server binary and the exact repository-relative harness path plus SHA-256; the offline validator recomputes the harness digest so a changed procedure invalidates old booleans. No credentials, VM, systemd unit, container, cloud API, persistent service, or non-loopback listener was used. The result is 3 `passed-local-x64-smoke`, 1 `partial-loopback-health-only`, 22 `not-executed`, and 1 `blocked-owner-policy-unset` capability row.

## Fail-closed gaps

Full L0C remains false. Required gaps include generated JWT operators/accounts/users and least-privilege permissions; separate control/product trust planes; imports/exports; mTLS for client/route/gateway; regional gateway mesh; R3 JetStream; durable consumer acknowledgement/redelivery/backoff; retention/deduplication/expected-sequence behavior; KV CAS/watch; Object Store; `$SYS` and advisories; snapshots/restores; peer loss/removal/replacement; configuration reload/lame-duck rolling behavior; NATS.Net and CLI behavior; and mixed server/client N/N-1 permutations.

ARM64 asset availability is metadata evidence only. No ARM64 archive was downloaded or executed, and real A1 qualification remains L4. No N/N-1 policy may be selected until the owner decision and a matrix covering read/write compatibility, store format/downgrade boundary, JetStream leadership, snapshots, client API/protocol behavior, and rollback is approved and executed.

## Reproduction

```text
python3 testlab/nats/validate_nats_readiness.py
python3 -m unittest discover -s testlab/nats/tests -v
python3 testlab/nats/run_local_l0c_smoke.py > /tmp/nats-smoke.json
cmp /tmp/nats-smoke.json testlab/nats/local-x64-l0c-report.json
rm -f /tmp/nats-smoke.json
python3 -m json.tool testlab/pins/nats-candidates.json
python3 -m json.tool testlab/nats/local-x64-l0c-report.json
git diff --check
```

The validator is offline and deterministic. Eight adversarial fixtures prove rejection of missing ARM64 metadata, non-official provenance, accidental candidate selection, accidental owner-policy selection, a false full-L0C claim, failed process cleanup, semantic drift in the specification's capability matrix, and harness/report digest drift.

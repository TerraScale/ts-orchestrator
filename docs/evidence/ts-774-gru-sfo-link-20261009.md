# TS-774 GRU/SFO link diagnosis — 2026-10-09

## Before: live diagnosis

Targets were verified by hostname, regional private address and controller
slot before inspection. No serving cell was re-founded, rebuilt or reset.

The authenticated dashboard at GRU1 and SFO1 returned HTTP 200 but displayed
`GRU ↔ SFO: unreachable`. GRU1 was rechecked at approximately 20:54 UTC.
The dashboard requests `ts.orch.v1.<peer>.obs.region` through the local
controller's NATS connection with `{"version":1}` and a 1.5-second timeout.
Only a valid response naming the expected region makes the edge `linked`.
This measures a control-plane request/reply, not a socket count or database
replication. Changing the dashboard to infer health from an open socket
would hide this fault.

Transport was healthy at approximately 20:40 UTC:

- DNS resolved the regional NetBird names correctly; all six regional peers
  were connected on the existing operations mesh.
- Each regional NATS cluster had three peers and eight routes. Regions use
  dedicated-account mTLS leafnodes, not a cross-region cluster or gateway.
- Three SFO-to-GRU TCP 7422 connections traversed OCI private peering:
  `10.252.0.11:39006 → 10.251.0.11:7422`,
  `10.252.0.12:54414 → 10.251.0.12:7422`, and
  `10.252.0.13:44950 → 10.251.0.13:7422`. The established authenticated
  sessions demonstrate that routing and the security rules admitted this
  traffic; no network or firewall change was needed.
- SFO's leaf certificate was issued by `TerraScale interregion CA`, valid
  from October 7, 2026 to October 5, 2027, with SAN
  `leaf.sfo.interregion.terrascale.internal`. SFO pinned the GRU peer name
  and tried reviewed private addresses before NetBird addresses.

TerraBase WAN was already exchanging groups independently of the dashboard:
every member observed three remote WAN members, lag 0 and conflicts 0.
Caught-up staleness was approximately 0.18–1.08 seconds. GRU2/3 had pulled
11 SFO groups; SFO1/2 had pulled 11 GRU groups. GRU3 and SFO1 had served 15
groups, SFO2 six. These passive counters show existing WAN traffic, but are
not a fresh bidirectional document canary or post-deployment acceptance.

## Root cause

The signed controller configs omitted `observability`; aggregation therefore
defaulted to false. TS-782 independently reproduced the dashboard's
“Cell-wide aggregation is off; only this member is listed” response in both
regions. This also explains the misleading one-member views.

Both regions' controller JWTs retained the founding regional grant set:

- no `ts.orch.v1.<own-cell>.obs.>` subscription, needed by local snapshots,
  region summaries and decision responders;
- no exact publishes to the configured peer's `obs.region` and
  `obs.decisions` services.

GRU1 still logged these denials at 20:54 UTC, after its current restart:

```text
Permissions Violation for Publish to "ts.orch.v1.sfo.obs.region"
Permissions Violation for Publish to "ts.orch.v1.sfo.obs.decisions"
```

SFO logged the equivalent GRU subject denials. NATS reports permission
errors asynchronously; successful `Subscribe` alone does not prove that a
responder was admitted. The older interregion integration fixture issued
unrestricted users, masking this production grant regression.

## Fix and local evidence

`bootstrap issue-observability-credentials` reissues the existing controller
users with their existing offline cell account seed. It preserves user keys,
inboxes, regional fence grants, bounded replies and expiry. It binds global
publish grants to the reviewed topology home, adds the local telemetry
subscription and the reviewed peers' two exact read services. Seeds stay offline and outputs are new
owner-only files; founding material remains immutable.

The existing signed generation installer accepts those slot-bound credential
pins only with every slot's config and credentials, without online issuers.
After merged TS-796, telemetry is unconditional and pinned v1 configs contain
no aggregation setting. Admission
checks account signature, matching seed, slot identity, credential path,
expiry and restricted peer grants. Successors cannot drop the pins and
revert to founding credentials at reboot. The same version-1 telemetry
request and response contracts are retained.

The regression probe uses production-issued restricted JWTs and a real
two-region mTLS leaf. It reproduces the old local subscription and peer
publish denials, then proves both-direction version-1 summaries and decisions
and three answering local members per region. Remote snapshots, raw
journals, mutations and unconfigured peers remain denied. Separate tests
cover generation shape, missing/tampered/expired/wrong-slot credentials,
arming, crash convergence, restart admission and Vault restoration.

All six live users' current credentials were read after verifying their
targets. The new offline command successfully prepared replacements in an
owner-only local directory. No replacement was published, armed or installed.
The October 9 local config preparation predates merged TS-796. It is superseded
by strict v1 replacement configs with unconditional telemetry; the installed
configs retain their original bytes until the root-signed transaction runs.
TS-774 owns credentials and signed config activation; TS-782 owns dashboard
page completeness checks and the dashboard regression probe.

## Deployment blocker and remaining acceptance

At main revision `d7b1a488`, TS-754 requires canonical ULIDs for deployment,
cluster and trust-scope identities. The serving GRU accepted manifest and
generation chain still identify `ts-550-gru-refound-6`; SFO identifies
`ts-640-sfo-found-1`. Both hold generations 1 and 2. The current CLI rejects
the existing candidate with:

```text
material generation is invalid: identity, schema or chain field
```

The existing installer preserves the accepted identity and requires an
extending chain. Editing IDs or starting a fresh chain would break those
proof bindings. TS-754's conversion also affects release receipt and
delegation scopes, so changing only generation validation cannot establish
safe restart admission. No compatibility bypass, migration, re-found or
serving-state deletion was attempted. Coordinate this trust-contract issue
with TS-754 and the TS-746 rollout owner before arming credentials.

### Recheck after TS-776 merged

PR #354 was rebased cleanly onto `origin/main` revision `6895b1f6`, which
includes TS-776 #355. TS-754 #335 was already in the previous base at
`d7b1a488`; it introduced the canonical ULID requirement, rather than resolving
the existing signed identity conflict.

At 21:54–21:55 UTC, all six live controllers were inspected over the existing
NetBird operations client. Each target's configured cell, slot and accepted
private IP were verified before inspection. All six services were active.

| Region / slots | Accepted deployment and cluster ID | Installed generations | Aggregation |
| --- | --- | --- | --- |
| GRU / A, B, C | `ts-550-gru-refound-6` | 1, 2 | unset |
| SFO / A, B, C | `ts-640-sfo-found-1` | 1, 2 | unset |

The CLI built from the rebased branch at `55c02fb7` rejected the exact
installed generation payload read from each region with
`material generation is invalid: identity, schema or chain field`. It refused
before reading material or signing keys; no generation was signed or published.

**Exact missing piece — `TerraScale/ts-orchestrator`:** a supported in-place
signed trust path that extends and restart-admits these accepted deployment
and cluster identities. `MaterialGeneration.Validate` in
`internal/bootstrap/generation.go` requires both IDs to be canonical ULIDs.
The same requirement exists in `Manifest.Validate` and `BootstrapAnchor.Validate`;
`Scope.validate` and `Capability.validate` in `internal/trust/envelope.go`
also reject their deployment IDs. `AcceptedGenerationTarget` parses the pinned
manifest, and generation-chain verification validates every held generation
and requires the exact accepted identity. Merely signing a new candidate with
a ULID cannot pass those checks. The correction must cover bootstrap material,
baked deployment identity, accepted manifests/anchors, cell specs, signed
release/delegation scopes and restart admission together. No other repository
is needed for this missing path.

TS-754 also changed exact signed scope meanings: root delegation's deployment
scope changed from `root` to `0000000000XXZR988BPPNZ2B32`, binary/image receipt
scopes from the exact source revision to `entityid.Derive("build", revision)`,
and automatic-update delegation's scope from `binary-update` to
`0000000000TA7Q4JYMWMMHHMPQ`. Historical proof verification and delivery by the
serving binary use those exact bindings. Relaxing the generation ID validator
alone cannot repair them.

Activation also requires verifying or applying the trusted operator's
root-signed `can_install_material` grant, checked separately from NATS
permissions. The prepared configs only enable observability and do not add
that authority. The supported cell-spec amendment requires binary level 19 or
later; its deployment identity has the same unresolved ULID requirement.

No live config, credential, trust marker, generation chain or service was
changed during this recheck. Signed rotation and live dashboard/replication
acceptance remain pending this repository-level correction.

After an identity-preserving CI deployment is proven on every controller:
install the signed credential/config successor one slot at a time; require
three-member dashboard views and a `linked` GRU/SFO edge from both regions;
record fresh full revision/CI-run fleet proofs; write and read an identifiable
TerraBase document in each direction with matching content hashes. These
post-deployment checks remain pending; this record does not claim TS-774's
live acceptance is complete.

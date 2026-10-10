# TS-782 live dashboard evidence

Source host: `mariogk-dev`, 2026-10-09 20:54–21:06 UTC. Tokens and session
cookie values are excluded. Serving cells were inspected in place.

## Reproduction with real sessions

Regional tokens were read from OCI Vault into owner-only temporary files.
`curl` posted each token from its file to `/login`, with the dashboard's
matching Origin and Referer, and saved the issued cookie into an owner-only
cookie jar. Subsequent requests used that cookie, without a bearer header,
without proxies, redirects, tunnels or DNS overrides.

```text
gru login HTTP 303 remote fd9c:200:2182:65f2:40ea:3113:8dd9:d9ab
sfo login HTTP 303 remote fd9c:200:2182:65f2:1d12:72a5:647b:8225
```

Every sidebar page returned HTTP 200 from both
`ts-gru-1.nb.ts.internal:9463` and `ts-sfo-1.nb.ts.internal:9463`:

```text
/ /region /insights /decisions /releases /rollouts /ci
/topology /members /nats /terrabase /storage /oci /events
```

The shared T3 browser reached GRU's login page normally. Its five embedded
CSS/JavaScript assets returned HTTP 200 without console errors. Real cookie
requests to `/members/stream` returned HTTP 200 and repeated
`datastar-patch-elements` events in both regions. Each stream was deliberately
closed after four seconds; curl exit 28 is the expected stop of that
long-lived response, not an authentication or stream failure.

The dashboard is therefore not literally empty in this deployment. Local
member history, JetStream state, topology services and decisions render.
The failure is incomplete telemetry: only the local controller is observed,
and the opposite region cannot answer summary queries.

## Response-body evidence

Both authenticated `/members` responses contain this actual HTML:

```html
<a href="/members/controller-a">controller-a</a>
<small>Cell-wide aggregation is off; only this member is listed.</small>
```

GRU's global response reports:

```text
Controllers up 1 / 1 across 1 of 3 regions; 2 not answering
GRU: Quorum 1 / 1 answering, 1 ready
SFO: unreachable
```

SFO's global response reports the same one-controller view with GRU
unreachable. The one-controller denominator does not prove a healthy
three-controller cell.

Read-only NetBird SSH inspection identified the intended nodes and queried
only selected nonsecret fields of
`/etc/terrascale-orchestrator/controller.json`:

```json
{"nats":{"cell":"gru","instance":"controller-a"},"observability":null}
{"nats":{"cell":"sfo","instance":"controller-a"},"observability":null}
```

With no observability block, `cluster_aggregation` defaults to false.
Enabling the dashboard in the cell spec does not enable aggregation. The
primary loopback `/v1/snapshot` on SFO independently returned:

```json
{
  "cell": "sfo",
  "member": "controller-a",
  "role": "controller",
  "build_version": "107e060af74f",
  "ready": true,
  "observed_at": "2026-10-09T20:57:47.999044579Z"
}
```

GRU's rendered member build was `1e57e6c17362`. These deployed builds predate
the checked-out main revision `d7b1a488`.

The NetBird dashboard listener returns 404 for `/v1/snapshot`,
`/v1/cluster` and `/v1/regions`: those diagnostic APIs are mounted on the
primary observability listener. Browser pages read Go providers directly;
they do not call these missing NetBird routes.

## Shared root cause and ownership

TS-774 separately confirmed live controller JWT permission denials on peer
`obs.region` and `obs.decisions` requests, and missing local telemetry
subscriptions. Its NATS leaf and TerraBase WAN transport checks succeeded.
TS-774 owns the credential grant changes and signed rotation. Under the
subsequent zero-configuration instruction it also owns removal of the
aggregation, telemetry listener and dashboard switches; rollout configs
will omit those flags. TS-782 does not repeat that rotation. Individual
`/proc` metrics and storage providers stay
with TS-775, and node naming stays with TS-776.

TS-774 also reproduced a deployment prerequisite: serving signed material
still carries pre-ULID deployment IDs that current main rejects. No serving
identity, trust pin, credential or data store was changed for this evidence.

## Regression probe

The original `ts-orch dashboard check` passed all 24 health/topology requests
on the six controllers despite the missing telemetry above. The strengthened
check reads bounded HTML bodies, checks every sidebar page, requires three
distinct topology nodes, and counts three distinct observed member links in
the actual table. Missing-member placeholders and duplicate links do not
count. Headings alone do not count as rendered page content; explicit empty
resource states remain valid.

Run from an approved operator device with the connected NetBird client:

```sh
nice -n 19 scripts/check-dashboard-access.sh \
  --netbird 'sudo -n podman exec -i ts-netbird-ops netbird' \
  --gru-token-file /path/to/owner-only/gru-token \
  --sfo-token-file /path/to/owner-only/sfo-token \
  --timeout 10s
```

The updated probe exited 1 after all 180 requests: 168 passed, and the twelve
IP/DNS `/members` views failed across all six controllers. It reports a
specific diagnosis:

```text
FAIL dashboard has 1 observed controllers, need at least 3; check telemetry grants and cluster_aggregation http://10.200.87.215:9463/members
FAIL dashboard has 1 observed controllers, need at least 3; check telemetry grants and cluster_aggregation http://ts-gru-1.nb.ts.internal:9463/members
FAIL dashboard has 1 observed controllers, need at least 3; check telemetry grants and cluster_aggregation http://10.200.112.213:9463/members
FAIL dashboard has 1 observed controllers, need at least 3; check telemetry grants and cluster_aggregation http://ts-sfo-1.nb.ts.internal:9463/members
```

Tests render production dashboard templates with one versus three observed
controllers, reject empty/title-only/login bodies and duplicate telemetry,
verify fleet address/authentication/redirect/proxy checks, and exercise curl's
2 MiB response limit.

## Deployment acceptance

Post-CI deployment acceptance remains pending TS-774's signed config and
credential installation and in-place canonical-ULID identity transaction.
PR #356 merged as `39ac46377593c16a9c2954f8ad9976448ba7eced`.
Require the 180-request probe to pass, fresh real-cookie
page and stream responses in GRU and SFO, three observed controllers per
regional view, and reciprocal region summaries. Append the deployed source
revision and after-response evidence here before declaring TS-782 complete.

## Post-merge verification and CI delegation refresh

Read-only checks from `mariogk-dev` at 22:23–22:25 UTC confirmed that the
merge binary was not deployed. [Main CI run 1918](https://git.terrascale.tech/TerraScale/ts-orchestrator/actions/runs/1918)
(native ID 16332) succeeded for exact revision `39ac4637`.
[Deploy run 1923](https://git.terrascale.tech/TerraScale/ts-orchestrator/actions/runs/1923)
(native ID 16345) failed at 22:23:38 UTC with
`trust document is invalid: incomplete or invalid scope`, before reading
the signing key or starting either region's rollout. Primary snapshots
still reported GRU `1e57e6c17362` and SFO `107e060af74f`, both ready, at
22:23:55 and 22:23:58 UTC respectively.

New real-cookie logins returned HTTP 303 in both regions. All 28 sidebar
page requests returned HTTP 200 with content beyond headings. The body
sizes below are bytes; valid empty-resource messages count as content.

| Page | GRU | SFO |
| --- | ---: | ---: |
| `/` | 22507 | 23053 |
| `/region` | 19426 | 20701 |
| `/insights` | 9917 | 9933 |
| `/decisions` | 11342 | 11342 |
| `/releases` | 19561 | 19229 |
| `/rollouts` | 93684 | 49483 |
| `/ci` | 9837 | 9837 |
| `/topology` | 13716 | 15955 |
| `/members` | 18516 | 18527 |
| `/nats` | 55425 | 65513 |
| `/terrabase` | 12993 | 35397 |
| `/storage` | 10930 | 10843 |
| `/oci` | 9313 | 15427 |
| `/events` | 10001 | 11289 |

Actual `/members` table text included fresh local observations:

```text
GRU controller-a controller yes 1e57e6c17362 1h41m follower 8 1 0.62 / 0.65 / 0.88 36.7% 0.00 0ms ago
SFO controller-a controller yes 107e060af74f 1h40m leader   8 1 1.46 / 1.12 / 1.59 30.4% 0.00 0ms ago
```

Each `/members/stream` returned HTTP 200 and two patch events in four
seconds; curl exit 28 was the deliberate timeout. Each member table still
listed only one observed controller with the aggregation-off message;
opposite-region summaries remained unreachable. The fleet probe again
completed all 180 requests with 168 passing and all twelve `/members`
endpoints failing. These are non-empty pages, not completed live acceptance.

The exact rejected CI document was the public repository Actions variable
`TS_RELEASE_UPDATE_DELEGATION`, SHA256
`d5f4bc60b34f910b501231e518a621ac03560876ecc99b5c14be25dce2c4cab7`.
Its six scope fields were:

```json
{"domain":"terrascale.release.binary-update-delegation","deploymentId":"binary-update","cell":"global","environment":"canary","role":"release-signer","slot":"lineage"}
```

Current `Scope.validate` requires a canonical ULID deployment identity.
The root operation reissued the grant with
`deploymentId: "0000000000TA7Q4JYMWMMHHMPQ"`, using the existing root and
leaf pins. A clean helper built from exact main `39ac4637` with Go 1.27.1
performed signing. Production canonical decoding, `trust.VerifyCurrent`
and grant validation passed; stale-signature and wrong-scope checks were
rejected. Repository variable publication returned HTTP 204, and exact
read-back SHA256 was
`a823b2e842ec31656c2160c3e9aa7b89ea21983c626403902b18ce1ba762c3ca`.

The full payload is unchanged: leaf
`sha256:e6e94345986025edf97f07683d592dc2e3aa3e8a4f79123b6a65b525dae02154`,
canary, GRU/SFO, arm64, `TerraScale/ts-orchestrator`, `ci.yml`,
`refs/heads/main`, and lineage base `db0f410451bda2693b32ed0153a2931178600df5`.
The root remains
`sha256:d30051891533bd6e44ac6f5bb37daacf44f0ca622c74be2bcc58d8d2cfae53cd`.
Issuance is `2026-10-09T22:36:17Z`; the original expiry
`2026-11-09T13:42:13Z` was retained. Task-created private signing material
was removed after signing.

Manual deployment is held until TS-774's identity transaction is ready:
the fresh CI delegation alone cannot startup-admit old controller proofs.
TS-774 owns all six controllers' in-place root-signed re-key and the sole
telemetry rotation, preserving NATS/Raft identities and serving stores.
This forward probe diagnostic names missing telemetry grants without
recommending a removed configuration switch.

These post-merge response excerpts, CI/deployment results and grant metadata
were also posted as Ku TS-782 comment
`332fcdbc-3185-4147-bb8f-ad74c97dc2e6` at 22:38:53 UTC.

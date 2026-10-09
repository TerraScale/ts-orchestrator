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
TS-774 owns the credential grant changes, signed rotation and enabling
`cluster_aggregation` in all six signed controller configs. TS-782 does not
repeat that rotation. Individual `/proc` metrics and storage providers stay
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
credential installation, resolution of its deployment-ID prerequisite, and
this PR's merge. Require the 180-request probe to pass, fresh real-cookie
page and stream responses in GRU and SFO, three observed controllers per
regional view, and reciprocal region summaries. Append the deployed source
revision and after-response evidence here before declaring TS-782 complete.

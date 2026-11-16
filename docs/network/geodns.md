# Geo-steering DNS cutover

The OCI zone `edge.terrascale.tech` and TTL 30 steering policies are reconciled
by `ts-orch region apply gru dns`. This command never edits Cloudflare.
`deploy/fleet/fleet.json` is the desired topology. The regional records are
`<label>.api.edge.terrascale.tech`; the global names are dash, auth, api, mcp
and platform under the zone.

Run the following sequence from delta, where `cf` is authenticated, using
the reviewed and pushed branch for operator commands. Keep the before-plan,
apply output, after-plan and a second apply in the PR. The second apply
must report every resource `ok` without a write.

1. Record the OCI nameservers printed by the apply. Query each global name
   directly against a zone nameserver using `dig +subnet=200.160.0.0/16`
   (SA), `dig +subnet=8.8.8.0/24` (NA) and `dig +subnet=80.128.0.0/16`
   (EU). Check the expected region's NLB and TTL 30. A subnet query exercises
   OCI's EDNS location choice; it is not an application latency measurement
   from that continent.
2. Delegate `edge.terrascale.tech` with DNS-only NS records in Cloudflare.
   Existing public A records continue serving traffic during this step.
3. Save each old Cloudflare record including its ID, type, content, TTL and
   proxy status in the PR body, with one exact `cf` restore command per
   record. This includes dash, auth, api, mcp, platform and gru.api, sjc.api,
   fra.api under `terrascale.tech`.
4. Check every public hostname through every NLB using
   `curl --resolve <name>:443:<NLB-IP> https://<name>/<current-path>`.
   Compare TLS, status and response with the current public name. C29's
   released edge fix must pass this check for all names and regions before
   any CNAME changes. If it fails, ship the DNS pass with cutover deferred.
5. From a client in each of SA, NA and EU, collect at least three API
   time-to-first-byte samples before and after cutover. Record the median
   and the first DNS lookup duration including the extra CNAME hop. EDNS
   subnet queries alone cannot supply these latency measurements.
6. Follow the fixed per-name sequence below, starting with MCP. Change only
   one record, run its check, inspect the saved response bodies, and compare
   each continent's samples before moving to the next row. Any new error or p50
   regression greater than 50 ms requires immediate restoration of that
   name's old record before reporting NEED. Keep the rest unchanged.

## C10b per-name execution

C10 stages DNS only. These commands are for C10b after the released readiness
and TLS fixes pass; do not execute a cutover command while either gate is red.
The fixed order starts with MCP, then platform and regional APIs, leaving the
shared API, auth and dashboard until last. Take fresh Cloudflare snapshots
before C10b and verify every record ID and old value below still matches;
stop and update this runbook if the baseline has changed.

Run on delta. The public CNAME TTL is 60 seconds; OCI steering answers retain
TTL 30. The restore commands preserve the original automatic TTL of 1 and
DNS-only status. Each command edits the existing record in place.

Define the following helpers. The first saves old-endpoint and NLB bodies in
a private temporary directory and requires identical HTTP status and content
type, valid TLS, and HTTP 200 for address-Host readiness on every NLB. The
second also verifies the new CNAME at Cloudflare's authority, prints all three
continent answers, and checks the normal public response against the old
endpoint. Neither helper follows redirects or disables TLS verification.

```sh
check_nlb_name() {
  cutover_name="$1"
  cutover_path="$2"
  cutover_previous="$3"
  cutover_state="$(mktemp -d)" || return 1
  cutover_expected="$(curl --silent --show-error --max-time 10 --resolve "$cutover_name:443:$cutover_previous" --output "$cutover_state/before" --write-out '%{http_code} %{content_type}' "https://$cutover_name$cutover_path")" || return 1
  for cutover_ip in 147.15.62.180 146.235.198.117 141.144.224.176; do
    cutover_ready="$(curl --silent --show-error --max-time 10 --output /dev/null --write-out '%{http_code}' "http://$cutover_ip/readyz")" || return 1
    test "$cutover_ready" = 200 || return 1
    cutover_observed="$(curl --silent --show-error --max-time 10 --resolve "$cutover_name:443:$cutover_ip" --output "$cutover_state/$cutover_ip" --write-out '%{http_code} %{content_type}' "https://$cutover_name$cutover_path")" || return 1
    test "$cutover_observed" = "$cutover_expected" || return 1
  done
  printf 'Inspect response bodies in %s; baseline: %s\n' "$cutover_state" "$cutover_expected"
}

check_cutover() {
  cutover_target="$2"
  cutover_cname="$(dig @dina.ns.cloudflare.com "$1" CNAME +short)" || return 1
  test "$cutover_cname" = "$cutover_target." || return 1
  check_nlb_name "$1" "$3" "$4" || return 1
  for cutover_prefix in 200.160.0.0/16 8.8.8.0/24 80.128.0.0/16; do
    dig @ns1.p201.dns.oraclecloud.net "$cutover_target" "+subnet=$cutover_prefix" +noall +answer || return 1
  done
  cutover_observed="$(curl --silent --show-error --max-time 10 --output "$cutover_state/public" --write-out '%{http_code} %{content_type}' "https://$cutover_name$cutover_path")" || return 1
  test "$cutover_observed" = "$cutover_expected" || return 1
  printf 'Inspect public response in %s/public\n' "$cutover_state"
}
```

Before changing any record, require OCI to report all three monitor targets
healthy, and verify unhealthy-region exclusion and recovery. Then run all
eight preflight commands and inspect their saved bodies. Auth /healthz must
return 200; the previously sampled discovery URL returning 404 does not establish that auth works. API and
platform /healthz must return 200, MCP /mcp must retain its unauthenticated
401, and dashboard / must retain its login redirect. These expectations
must match the fresh baseline.

```sh
check_nlb_name mcp.terrascale.tech /mcp 163.176.124.12
check_nlb_name platform.terrascale.tech /healthz 163.176.124.12
check_nlb_name fra.api.terrascale.tech /healthz 130.162.238.198
check_nlb_name sjc.api.terrascale.tech /healthz 163.192.54.17
check_nlb_name gru.api.terrascale.tech /healthz 163.176.124.12
check_nlb_name api.terrascale.tech /healthz 163.176.124.12
check_nlb_name auth.terrascale.tech /healthz 163.176.124.12
check_nlb_name dash.terrascale.tech / 163.176.124.12
```

After each row, proceed only if its check exits zero, the CNAME matches,
and each of the three ECS queries returns exactly one A answer with TTL 30
and the expected address. For global names the SA, NA and EU answers must be GRU, SJC and FRA respectively while
all regions are healthy; a regional API target always answers its own NLB.
Inspect the saved bodies for the same application response contract as the
old endpoint, allowing the intended regional identity in health responses.
A matching status alone is insufficient. Run the three-sample continental
TTFB comparison from step 5 for this row's hostname and path before
advancing; retain the separate API latency measurements required by T7.
A new error, changed response contract, or p50 regression above 50 ms means run that row's restore command
immediately, verify the old A record and response, and report NEED.

| Order | Public name | Cutover command | Check after changing this name | Restore command |
|---|---|---|---|---|
| 1 | `mcp.terrascale.tech` | `cf dns records edit 7c190d17c1fb2a08798d2741ad318389 --zone terrascale.tech --body '{"type":"CNAME","name":"mcp.terrascale.tech","content":"mcp.edge.terrascale.tech","ttl":60,"proxied":false}'` | `check_cutover mcp.terrascale.tech mcp.edge.terrascale.tech /mcp 163.176.124.12` | `cf dns records edit 7c190d17c1fb2a08798d2741ad318389 --zone terrascale.tech --body '{"type":"A","name":"mcp.terrascale.tech","content":"163.176.124.12","ttl":1,"proxied":false}'` |
| 2 | `platform.terrascale.tech` | `cf dns records edit fcd121d998f2b3d3fbc15fd3ff132a75 --zone terrascale.tech --body '{"type":"CNAME","name":"platform.terrascale.tech","content":"platform.edge.terrascale.tech","ttl":60,"proxied":false}'` | `check_cutover platform.terrascale.tech platform.edge.terrascale.tech /healthz 163.176.124.12` | `cf dns records edit fcd121d998f2b3d3fbc15fd3ff132a75 --zone terrascale.tech --body '{"type":"A","name":"platform.terrascale.tech","content":"163.176.124.12","ttl":1,"proxied":false}'` |
| 3 | `fra.api.terrascale.tech` | `cf dns records edit b2a4cf6d1404581ff12f980fc832f517 --zone terrascale.tech --body '{"type":"CNAME","name":"fra.api.terrascale.tech","content":"fra.api.edge.terrascale.tech","ttl":60,"proxied":false}'` | `check_cutover fra.api.terrascale.tech fra.api.edge.terrascale.tech /healthz 130.162.238.198` | `cf dns records edit b2a4cf6d1404581ff12f980fc832f517 --zone terrascale.tech --body '{"type":"A","name":"fra.api.terrascale.tech","content":"130.162.238.198","ttl":1,"proxied":false}'` |
| 4 | `sjc.api.terrascale.tech` | `cf dns records edit def5ec99e092ab5f4b682ac037f6c8ce --zone terrascale.tech --body '{"type":"CNAME","name":"sjc.api.terrascale.tech","content":"sjc.api.edge.terrascale.tech","ttl":60,"proxied":false}'` | `check_cutover sjc.api.terrascale.tech sjc.api.edge.terrascale.tech /healthz 163.192.54.17` | `cf dns records edit def5ec99e092ab5f4b682ac037f6c8ce --zone terrascale.tech --body '{"type":"A","name":"sjc.api.terrascale.tech","content":"163.192.54.17","ttl":1,"proxied":false}'` |
| 5 | `gru.api.terrascale.tech` | `cf dns records edit 578e672bc6e487f3a287de3b318ea4e3 --zone terrascale.tech --body '{"type":"CNAME","name":"gru.api.terrascale.tech","content":"gru.api.edge.terrascale.tech","ttl":60,"proxied":false}'` | `check_cutover gru.api.terrascale.tech gru.api.edge.terrascale.tech /healthz 163.176.124.12` | `cf dns records edit 578e672bc6e487f3a287de3b318ea4e3 --zone terrascale.tech --body '{"type":"A","name":"gru.api.terrascale.tech","content":"163.176.124.12","ttl":1,"proxied":false}'` |
| 6 | `api.terrascale.tech` | `cf dns records edit ca6cb548d99346fc4e5fef10b492069a --zone terrascale.tech --body '{"type":"CNAME","name":"api.terrascale.tech","content":"api.edge.terrascale.tech","ttl":60,"proxied":false}'` | `check_cutover api.terrascale.tech api.edge.terrascale.tech /healthz 163.176.124.12` | `cf dns records edit ca6cb548d99346fc4e5fef10b492069a --zone terrascale.tech --body '{"type":"A","name":"api.terrascale.tech","content":"163.176.124.12","ttl":1,"proxied":false}'` |
| 7 | `auth.terrascale.tech` | `cf dns records edit 0009eae684d826ac79981d4c54fb1ad5 --zone terrascale.tech --body '{"type":"CNAME","name":"auth.terrascale.tech","content":"auth.edge.terrascale.tech","ttl":60,"proxied":false}'` | `check_cutover auth.terrascale.tech auth.edge.terrascale.tech /healthz 163.176.124.12` | `cf dns records edit 0009eae684d826ac79981d4c54fb1ad5 --zone terrascale.tech --body '{"type":"A","name":"auth.terrascale.tech","content":"163.176.124.12","ttl":1,"proxied":false}'` |
| 8 | `dash.terrascale.tech` | `cf dns records edit 31e6166055f63ecd292b7d16ad8690d1 --zone terrascale.tech --body '{"type":"CNAME","name":"dash.terrascale.tech","content":"dash.edge.terrascale.tech","ttl":60,"proxied":false}'` | `check_cutover dash.terrascale.tech dash.edge.terrascale.tech / 163.176.124.12` | `cf dns records edit 31e6166055f63ecd292b7d16ad8690d1 --zone terrascale.tech --body '{"type":"A","name":"dash.terrascale.tech","content":"163.176.124.12","ttl":1,"proxied":false}'` |

Resolvers retain old A answers for their original remaining TTL. Reducing a
TTL at cutover cannot shorten answers already cached. Keep the previous
endpoints serving for at least the greatest recorded old TTL, and preserve
certificates and routing for the public hostnames at both paths. CNAMEs use
the public hostname for HTTP Host and TLS SNI. Reverting a CNAME also takes
its cached TTL to propagate; the 30-second steering TTL does not govern the
Cloudflare CNAME's own cache lifetime.

Unhealthy regions are removed by the shared monitor and steering policies.
When every region is unhealthy OCI retains a nonempty answer, so the name
still resolves even though application availability cannot be promised.
See [ownership and resource undo](../oci-reconcile.md#fleet-dns-pass) before
removing anything from the zone, which can contain records owned by others.

## Staged production state, 2026-11-16

The instance-principal apply created the zone, one monitor, all five policies
and attachments, and three regional A/ownership-TXT pairs. Its second apply
made no changes. Authoritative ECS queries for all five names returned GRU
for SA, SJC for NA and FRA for EU, each with TTL 30.

At verification time every NLB returned HTTP 404 for an address-Host
`:80/readyz`, and OCI reported all three targets unhealthy. The same
queries still returned nonempty answers, proving the all-unhealthy behavior.
Live healthy-region exclusion remains to be verified after the readiness
route is released. Multiple public hostnames also failed TLS through the
NLBs. Public cutover is deferred; all eight existing public Cloudflare A
records remain unchanged. Before/after application latency and the actual
extra CNAME lookup cost require that later cutover and cannot be inferred
from these ECS queries.

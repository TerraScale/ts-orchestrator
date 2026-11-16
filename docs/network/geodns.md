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
6. Move one least-used name at a time to its DNS-only OCI CNAME, check real
   responses, and compare each continent's samples. Any new error or p50
   regression greater than 50 ms requires immediate restoration of that
   name's old record before reporting NEED. Keep the rest unchanged.

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

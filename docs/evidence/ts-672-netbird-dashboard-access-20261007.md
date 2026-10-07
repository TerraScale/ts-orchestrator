# TS-672: private dashboard reachability, 2026-10-07

This is a reachability record, not a completed deployment claim. The
[dashboard runbook](../dashboard/README.md#netbird-access) lists all twelve
GRU/SFO URLs, regional Vault token fetch commands and the live checker.

## Diagnosis and changes

At 20:24Z all six controllers listened on `127.0.0.1:9463` only. Their wt0
INPUT chains already admitted operator TCP 9463 through NetBird's managed
ACL. TS-670 owns deploying the dashboard binary and adopting its cell-spec
section; TS-672 does not change that implementation or re-found a cell.

The actual mariogk-dev overlay is the host-network automation container,
`10.200.35.107`, in `ops-automation`; `10.200.87.10` belongs to delta. The
existing dashboard policies had only `operators` as their source. Scoped
`ts-orch netbird sync --only ... --apply` updated those rules in place.
Sibling controller names were absent from NetBird's policy-filtered peer
map. Same-region ICMP rules provide diagnostic ping and native DNS visibility
without adding any TCP/UDP access.

| Changed NetBird object | ID |
| --- | --- |
| `operators-to-gru-servers-dashboard` | `db3a0fca0rgg00840ig0` |
| `operators-to-sfo-servers-dashboard` | `db3a0fca0rgg00840ihg` |
| `gru-servers-to-gru-servers-ping` | `db3au1ca0rgg00841hvg` |
| `sfo-servers-to-sfo-servers-ping` | `db3au1ca0rgg00841i10` |

Dashboard readback: TCP, port `9463`, one-way, sources `operators` and
`ops-automation`, destination the corresponding regional servers group.
Ping readback: ICMP, no ports, one regional group as both source and
destination. The manager's disabled DNS groups were cleared. No unused FRA
objects, peer identities, server routes or unrelated policies were changed.

Operator DNS was applied through `ts-orch netbird dns`: delta/beta have the
owned `90-ts-orchestrator-dns.json` override and native resolved split DNS;
mariogk-dev has the owned systemd split resolver and refresh timer. Native
queries on all three hosts resolve all six controller names; Tailscale
FQDNs and short names remain usable. The container resolver receives only
`~nb.ts.internal`; the existing Tailscale upstream remains the default.
Owned units live under `/etc/systemd/system.control`; target dependency
readback confirms persistence. No operator host reboot was performed.

Controller DNS uses the changed ts-orch enrollment settings. A detached
`ts-orch netbird-enroll` canary on GRU 1 enabled native wt0 DNS while keeping
OCI's `169.254.169.254` resolver as the primary interface's default. Its
NetBird IP and canonical name stayed unchanged, and all six controller names
resolve after the ICMP policies. The other five controllers were enrolled
one at a time after that canary. Final checks on every controller resolved
all six names (36 successful lookups). Each client reports DNS enabled;
`enp0s6` retains OCI DNS with the default route, while `wt0` uses the peer's
NetBird address with no DNS default route. All six dashboard listeners still
bind only to loopback. The serving ts-orch process was not replaced by this
DNS operation.

## Public exclusion

Read-only live OCI inspection at 20:42Z found no TCP 9463 ingress in any of
the six regional NSGs. All four private/API security lists have empty ingress
rules, and both private subnets prohibit public addresses on VNICs. Overlay
access requires no OCI 9463 rule. No OCI network resource was changed.

| Region | Controller NSG | Private security list |
| --- | --- | --- |
| GRU | `ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaalt5nfmgj43snm7uwhatkudk5n7463vd4mgw7idu52dyfqoawfxba` | `ocid1.securitylist.oc1.sa-saopaulo-1.aaaaaaaa2m2udyy7rrdxgchgplt36tb6z4oao5kkt2eyfcg7xtiufdr6yqha` |
| SFO | `ocid1.networksecuritygroup.oc1.us-sanjose-1.aaaaaaaag5tonppbi5tfofopouoznzlvtci2x5twlb4srjn4ahe3jpw3t6va` | `ocid1.securitylist.oc1.us-sanjose-1.aaaaaaaae7pd7zegkaqgoav2rr3iqxweed4xqlzcbs67k5mwhc7vbjughsna` |

## Live acceptance still pending

The checker requires all six peers and HTTP 200 from the expected address
for `/healthz` and authenticated `/topology`, by both IP and native DNS:
24 requests per originating device. It bypasses proxies, never follows
redirects, and passes tokens to curl on stdin.

Initial checks from delta, beta and mariogk-dev resolve the names but fail
TCP connection establishment while the listeners remain loopback-only.
Those failures are deployment evidence, not a reason to add public ingress.
Repeat after TS-670 announces the NetBird listeners. The laptop peer was
offline; its live acceptance requires connecting it and running the same
checker. The user's connected desktop is already in `operators`.

## Local verification

Build, formatting, vet, shellcheck and the focused NetBird/DNS/checker suites
pass. The complete PR-tier race run finished with three failures; all other
shards passed. The fake-member release gate used this NixOS host's 14 MB
`false` binary, timing out during transfer before any failure could be
classified. TS-653's small deterministic fake fixture was reused; its race
test now passes. The hostile-peer test spent its one-second request deadline
marshalling its 838 KB fixture under load. Preparing the same replies before
the request fixes the fixture; the complete regionview race package passes
with its original timeout and security assertions. The admission fixture's
one-second deadline also expired under load, including in an isolated rerun
after a previous pass. Its retry-ordering test now allows five seconds for
the signed admission checks, keeping the two-attempt and no-premature-effects
assertions. This is not a claim that a complete verification
invocation has passed; required CI must still finish on the final commit.

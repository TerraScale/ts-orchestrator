# New region

A region gets its host with `ts-orch region add CODE`
([adding a region](m1-runbook.md#adding-a-region-ts-orch-region-add)), and
`ts-orch region verify` says whether it serves. `region derive` derives a
region's plan for review; it reads OCI and creates nothing:

```sh
ts-orch region derive fra --out /tmp/fra-1-plan.json
ts-orch region verify fra --plan /var/lib/ts-region/fra-1/bound-plan.json
```

`derive` derives names `<cell>-*` and `ts-<label>-<n>`, the network
`10.<251+catalog index>.0.0/24`, the region's first availability domain and
its service gateway from `--from` (default
`deploy/oci-region/sjc-1-plan.json`); every resource ID is unbound. The
region must be in the catalog,
[`internal/ociregion/catalog`](../internal/ociregion/catalog/catalog.go),
and the tenancy subscribed to it (status `READY`). `verify` exits nonzero
unless every check passes.

## What verify checks

| Check | Passes when |
| --- | --- |
| api | `https://<label>.api.terrascale.tech/healthz` answers 200, `status` `ok`, `region` the cell (`fra-1`) |
| api ping | the same `/healthz` with `Origin: https://dashboard.terrascale.tech` answers 200 with `Access-Control-Allow-Origin: *`, `Timing-Allow-Origin: *` and `Cache-Control: no-store`, so the dashboard can ping the region from the browser |
| auth | `https://<label>.auth.terrascale.tech/terrascale/.well-known/openid-configuration` answers 200 with that issuer |
| load balancer | every backend set (`terrabase`, `ts-auth`, `ts-orch` with orch) has backends, all healthy |

Every GET has a 10-second deadline and follows no redirect. TerraBase's and
ts-auth's `/readyz` are never called: both write
([live verification](live-verification.md)).

## Wall time

sjc-1 by hand, 2026-10-07, from the retained TS-640 and TS-662 timestamps:

| Phase | From | To | Wall time |
| --- | --- | --- | --- |
| Decision and cost estimate | 10:42Z | 10:53Z | 11 min |
| Foundation by hand with `oci`, and removing GRU hard-codes (#270) | 10:53Z | 11:46Z | 53 min |
| Founding attempt, 5 bugs found (#279) | 11:46Z | 13:16Z | 1 h 30 min |
| Host agents, specs by hand; TS-640 closed without an edge | 13:16Z | 14:02Z | 46 min |
| Edge, TerraBase, ts-auth (TS-662) | 14:45Z | 17:14Z | 2 h 29 min |

That is 6 h 32 min from the decision to `region verify sjc` passing.

## Check every host's boot-volume backup

`ts-orch region backups CODE` inventories every live host in the region's control
compartment, including stopped hosts. It prints the host, attached boot-volume
OCID (or `NOT FOUND`), assigned policy name (or `none`), newest available backup
in UTC, and its age. It reads the operator's `~/.oci/config` `DEFAULT` profile;
`operator.json` is not required. The default invocation performs only reads.

```sh
ts-orch region backups gru
ts-orch region backups sjc --check
ts-orch region backups fra --check
```

`--check` exits nonzero with one line per problem for a missing boot volume,
missing policy, missing available backup, or newest available backup older than
8 days. An empty region or failed OCI read also fails the command. Backups still
being created, failed backups, and deleted backups do not count as recovery
points. Terminated and terminating instances are excluded.

After the owner approves the backup cost, `ts-orch region backups CODE --apply`
assigns `ts-boot-weekly-4` to unassigned volumes through the same path as
`region add`, creating the regional policy if absent. Existing assignments are
preserved. `--check` and `--apply` are mutually exclusive. Assignment schedules
future backups; it does not create an immediate recovery point. See
[boot-volume policies and costs](boot-volume-backups.md) before applying.

Daily checks should run for `gru`, `sjc`, and `fra` from an authenticated operator
host. Existing GitHub workflows authenticate to the release listener with OIDC
and have no OCI read credentials, so no scheduled workflow is installed.

# New region

A region comes up with one command, and a second one says whether it
serves (TS-663). Both are `ts-orch region`, package
[`internal/region`](../internal/region).

```sh
export CF_API_TOKEN=...   # gru-1-cloudflare-dns-edit-token
export NB_PAT=...         # gru-1-netbird-admin-pat
ts-orch region create fra eu-frankfurt-1 --state /var/lib/ts-region/fra-1 --attempt-base ~/attempt-base.json \
  --home-plan ~/gru-1-bound-plan.json
ts-orch region verify fra --plan /var/lib/ts-region/fra-1/bound-plan.json
```

`create` prints each step's wall time when it finishes. A failed or
interrupted run resumes: run the same command again. `verify` exits
nonzero unless every check passes. Commit `<state>/plan.json` as
`deploy/oci-region/<cell>-plan.json` and the wall-time table in the
region's evidence PR.

## Before you start

1. The region is in the catalog,
   [`internal/ociregion/catalog`](../internal/ociregion/catalog/catalog.go):
   `gru`, `sfo` and `fra` today. A new label is one reviewed entry (cell,
   OCI region and key, city, country, latitude, longitude). The home region,
   GRU, is founded by [the manual runbook](region-bootstrap.md), never by
   `create`.
2. The tenancy is subscribed to the OCI region (status `READY`).
3. The operator host has:
   - `~/.oci/config` with a `DEFAULT` profile (any region; `create` writes
     the region's own copy);
   - the home region's operator material in `/var/lib/terrascale-operator`
     (`--home-operator`), since Atlas lives in gru-1's cell spec;
   - gru-1's bound plan (`--home-plan`, required), the region's private
     peer;
   - an attempt base: the [attempt](region-bootstrap.md#bootstrap-sequence)
     settings every region shares (`trust`, `tools`, `orchestrator`,
     `image` without `netbird_config`, `terrabase`, `namespace`,
     `validity_days`, `operator_grant`, `operator_signing_key`, ...). It
     must not set `workdir`, `deployment_id`, `prefix`, `base_plan`,
     `oci_config` or `image.netbird_config`: `create` sets them per region.
4. To review the plan before anything is created, derive it alone (reads
   OCI, creates nothing):

   ```sh
   ts-orch region plan fra eu-frankfurt-1 --out /tmp/fra-1-plan.json
   ```

## What create runs

| Step | Effect | Runs |
| --- | --- | --- |
| plan | Derives the plan from `--from` (default `deploy/oci-region/sfo-1-plan.json`): names `<cell>-*` and `ts-<label>-<n>`, the network `10.<251+catalog index>.0.0/24`, the region's first availability domain and its service gateway service; every resource ID unbound | in process |
| foundation | Compartments, VCN, subnets, gateways, NSGs, Vault and key, buckets and IAM, by name; writes `bound-plan.json` | `oci-region foundation --apply` |
| netbird | The region's servers group and SSH policies, a setup key stored as `<cell>-netbird-setup-key`, the image's `netbird.json` | `netbird sync`, `setup-key`, `vault put`, `netbird image-input` |
| ts-auth-secrets | ts-auth's generated Vault secrets | `ts-auth secrets` |
| found | The founding attempt: material, release, image, three nodes, operator material, the TerraBase and ts-auth services and their host grants | `oci-region attempt up` |
| edge-cert | The Origin CA certificate in the Vault | `oci-region public-api cert --apply` |
| edge | The L7 load balancer, its listeners and backend sets; records its IDs in `bound-plan.json` | `oci-region public-api apply` |
| peer | The private DRG/RPC peering with gru-1 ([inter-region private networking](region-bootstrap.md#create-a-pairs-peering-with-ts-orch-oci-region-peer)): TCP 7422 (NATS leafnodes) and 9443 (TerraBase) between the private subnets; after `edge`, so it pins the final bound plan; writes `peer-intent.json` once, pinning both plans, and `peer-bound-intent.json` | `oci-region peer --apply` |
| dns | Full (strict), zone AOP and proxied `<label>.api`, `<label>.auth` and `<label>.orch` | `oci-region dns --apply` |
| atlas | The region in gru-1's `atlas` section, root-signed | `atlas add-region`, `release sign-spec --root`, `apply` |
| verify | `region verify`, retried for `--wait` (30 minutes) | in process |

## What verify checks

| Check | Passes when |
| --- | --- |
| api | `https://<label>.api.terrascale.tech/healthz` answers 200, `status` `ok`, `region` the cell (`fra-1`) |
| auth | `https://<label>.auth.terrascale.tech/terrascale/.well-known/openid-configuration` answers 200 with that issuer |
| load balancer | every backend set (`terrabase`, `ts-auth`, `ts-orch` with orch) has backends, all healthy |
| atlas | `https://atlas.terrascale.tech/v1/discovery` lists the cell with health `ok` |

Every GET has a 10-second deadline and follows no redirect. TerraBase's and
ts-auth's `/readyz` are never called: both write
([live verification](live-verification.md)).

## Not automated yet

ts-auth in a new region needs two inputs that `create` cannot make yet.
Until they exist its replicas wait, `<label>.auth` does not answer and
`verify` fails. Provide both after `dns`, then run `create` again; it
resumes at the step that failed:

1. ts-auth's TerraBase tenant in the region's TerraBase:
   `ts-orch ouroboros bootstrap --plan <state>/bound-plan.json ...`
   ([ts-auth deployment](ts-auth-deployment.md)) stores
   `<cell>-ts-auth-terrascale-{project-id,api-key}`.
2. The SMTP credentials: the Email Delivery relay is shared in
   `sa-saopaulo-1`, but its credentials exist only as
   `gru-1-ts-auth-smtp-{username,password}`. Store the same values as
   `<cell>-ts-auth-smtp-{username,password}` with `ts-orch vault put` in the
   region's Vault.

Also outside `create`: the NATS link to GRU needs the interregion settings
in both regions' signed controller configs (TS-643).

## Wall time

sfo-1 by hand, 2026-10-07, from the TS-640 and TS-662 Ku timestamps:

| Phase | From | To | Wall time |
| --- | --- | --- | --- |
| Decision and cost estimate | 10:42Z | 10:53Z | 11 min |
| Foundation by hand with `oci`, and removing GRU hard-codes (#270) | 10:53Z | 11:46Z | 53 min |
| Founding attempt, 5 bugs found (#279) | 11:46Z | 13:16Z | 1 h 30 min |
| Host agents, specs by hand; TS-640 closed without an edge | 13:16Z | 14:02Z | 46 min |
| Edge, TerraBase, ts-auth, Atlas (TS-662) | 14:45Z | 17:14Z | 2 h 29 min |

That is 6 h 32 min from the decision to `region verify sfo` passing. The next region's
`create` journal gives its numbers; record them here.

# ts-orchestrator deployment pipeline

Part of [TS-768](https://ku.mariogk.com/terrascale/issue/TS-768).

Every successful push to `main`, including documentation changes, retains
qualified binaries and dispatches `deploy.yml`. Dispatch failure fails CI.
The deployment verifies main ancestry, CI success, retained binary digests,
and signed release authority before publishing. No deployment switch exists.

Until the shared ts-orch region-discovery contract lands, the deployment
script always targets GRU and SFO. The current serving inventory is three
ARM64 controllers in each cell, using the `canary` signed trust environment.
The script contains these constants; repository variables cannot disable a
region or override its environment or architecture.

The release leaf remains in OCI Vault. Required variables are
`TS_OBJECT_NAMESPACE`, `TS_RELEASE_VAULT_ID`, `TS_RELEASE_LEAF_SECRET`,
`TS_RELEASE_UPDATE_DELEGATION`, `TS_DEPLOY_OCI_USER`,
`TS_DEPLOY_OCI_TENANCY`, and `TS_DEPLOY_OCI_FINGERPRINT`. Required secrets
are `TS_DEPLOY_OCI_KEY` and `TS_DEPLOY_READ_TOKEN`. Delegation and regional
IAM must cover both head buckets; missing authority fails visibly.

Controllers retain their quorum, drain, health and rollback gates. An active
deployment is never cancelled. See [continuous delivery](continuous-delivery.md#automatic-fleet-deployment-ts-557-part-1)
for signing, publication and completion checks. Independent regional rollout,
dynamic region discovery, and the 30-minute lag alert follow in TS-768's
shared pipeline PR.

# GitHub migration status

## Deployment boundary

CI publishes qualified, attested main binaries; regional leaders discover and
pull them in fixed order after predecessor completion and bake. Application
release jobs publish signed selections of existing image digests. Hosts verify
the selection and build provenance before rollout. CI reads authenticated
HTTPS observations; it never connects to NATS 4222.

Webhooks may provide notification hints, never release authority. Consumers
verify channels locally and poll to recover missed hints. No new webhook
endpoint or provider storage adapter is implemented. The `run_number` channel
field still carries a CI counter: preserving monotonic ordering across
producers is required, and provider-independent sequence allocation remains
unresolved.

OCI is the current storage implementation. OCI versus Tigris cost and storage
research remains pending; this change does not select a new backend or claim
that OCI is cheapest.

## Repository changes

The Go module is `github.com/TerraScale/ts-orchestrator`. The SDK replacement
fetches the same reviewed commit from `github.com/TerraScale/ts-go`.
All active workflows live under `.github/workflows/` on GitHub-hosted Ubuntu
runners, with commit-pinned checkout/toolchain/artifact actions. The custom
Forgejo client, its build/patch/cache and token profiles are removed.

Consumers compare run ID, run number, source
SHA, workflow, required jobs, and exact retained-manifest log markers.
GitHub run numbers must never be passed as run IDs. Retained run proofs require
main-branch push, schedule or workflow-dispatch events. An image dispatch may
check out an older qualified main revision: its exact source is bound through
the manifest/log marker, while the workflow revision is recorded separately in
the promotion receipt. Binary and service qualifications still require the
exact source SHA in run metadata.

Same-run publication retries verify existing release tags/assets and finish
partial uploads without overwriting different bytes. Release retention uses
publication time, so newly published older revisions receive the retention window.

Production runtime credentials remain OCI Vault responsibilities. This source
cleanup neither creates nor copies secrets, changes IAM, provisions capacity,
nor deploys a fleet.
The ci.yml release-publish job signs artifacts with GitHub OIDC and publishes
them for host discovery. The receiver and producer contracts and merge order
are documented in [delivery pipeline](delivery-pipeline.md).

## Producer, infrastructure and verification gaps

1. Run GitHub CI on the migration PR and address current check/review findings.
2. Resolve service source and artifact ownership for the legacy producer/image/E2E paths;
   these are not signed-bundle application prerequisites. The GitHub API returns 404
   from `TerraScale/terrabase`, `TerraScale/ts-auth`, `TerraScale/ts-libs`, and the
   old pinned `ts-builder` policy. These retired standalone repositories have no
   GitHub copies. Current service source lives in `TerraScale/terrascale`, but its monorepo
   output cannot be silently substituted for reviewed standalone contracts.
   The policy guard is vendored locally; service pins remain exact and reject
   absent or mismatched inputs. Image qualification fixtures must be produced
   for hosted runners before image publication can succeed; missing fixtures
   remain failures, never skipped successful qualifications.
3. Requalify the preserved image/base/archive and E2E pins on GitHub. Existing
   release tags/run IDs were issued by another provider. The source digest
   includes repository URL framing: fresh GitHub source identities must have
   fresh digests. The fixed CI #1004 audit reproducer deliberately retains its
   historical URL framing; it makes no provider requests and issues no fresh
   release qualification. Historical source receipts remain audit records.
4. Preserve the release-publish workflow identity, signed selection and authenticated HTTPS observation boundaries.
   Legacy OCI producer adapters need their own qualified Vault authentication
   path before reuse. No credential or permission is installed by this cleanup.
   Public source/releases need no manually copied provider token for operators;
   CI uses the repository's scoped `GITHUB_TOKEN` for GitHub API operations.
5. Implement and exercise the independent GRU A1 NetBird foundation and the
   four-VM GRU/SJC/FRA connectivity milestone in `REFACTOR.md`.

## Retained infrastructure and historical evidence

Legacy OCI plans retain exact inventory/resource IDs for the existing operations
host, shared network and buckets. Plans now use `existing_operations_host` in
place of `existing_forgejo`; external plan files need the same key migration.
This changes plan hashes: capture fresh inventory and obtain any required plan
approval before applying one. Historical signed plans are not rewritten.
Their presence prevents accidental deletion or
cost undercounting; no running Forgejo service is a deployment prerequisite.
NetBird's compiled desired state contains no Forgejo or operations-host access
policy. Its manager bundle includes only NetBird Caddy routes, firewall rules
and SQLite backups. Legacy reset fixtures/readbacks still record old policy and
peer names. This source cleanup does not install, uninstall or redeploy the
live NetBird manager, or delete shared OCI resources.

Historical evidence, signed manifests and measured results retain their original
provider identity. Live links to retired repositories without GitHub copies are
plain references. The old ts-ops NetBird runbook is marked
legacy; it is not the desired dedicated-manager installation contract.

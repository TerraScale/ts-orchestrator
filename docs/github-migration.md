# GitHub migration status

## Repository changes

The Go module is `github.com/TerraScale/ts-orchestrator`. The SDK replacement
fetches the same reviewed commit from `github.com/TerraScale/ts-go`.
All seven workflows live under `.github/workflows/` on GitHub-hosted Ubuntu
runners, with commit-pinned checkout/toolchain/artifact actions. The custom
Forgejo client, its build/patch/cache and token profiles are removed.

Publication, promotion, service sync, deployment, pruning and local image tools
use native `gh`. `ts-orch release run-detail --repository OWNER/REPO --run-id ID`
normalizes GitHub's completed/conclusion fields and reads paginated jobs from the
observed run attempt. Consumers separately compare run ID, run number, source
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

Production runtime credentials remain OCI Vault responsibilities. The workflows
retain the existing OCI authentication inputs; this change neither creates nor
copies secrets, changes IAM, provisions capacity, nor deploys a fleet.
Production jobs name the GitHub `production` environment. Its reviewer/branch
rules and existing credentials must be configured and verified before activation;
merely naming an environment does not establish protection.

## Gates still open

1. Run GitHub CI on the migration PR and address current check/review findings.
2. Resolve service source and artifact ownership. The current account gets 404
   from `TerraScale/terrabase`, `TerraScale/ts-auth`, `TerraScale/ts-libs`, and the
   old pinned `ts-builder` policy. `TerraScale/terrascale` exists, but its monorepo
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
4. Verify GitHub environment protection and scoped OCI CI authentication with the
   operator before production activation. No new credential or permission is
   installed by this migration. Public source/releases need no manually copied
   provider token for operators; CI uses the repository's scoped `GITHUB_TOKEN`.
5. Implement and exercise the independent GRU A1 NetBird foundation and the
   four-VM GRU/SFO/FRA connectivity milestone in `REFACTOR.md`.

## Retained infrastructure and historical evidence

Legacy OCI plans retain exact inventory/resource IDs for the existing operations
host, shared network and buckets. Plans now use `existing_operations_host` in
place of `existing_forgejo`; external plan files need the same key migration.
This changes plan hashes: capture fresh inventory and obtain any required plan
approval before applying one. Historical signed plans are not rewritten.
Their presence prevents accidental deletion or
cost undercounting; no running Forgejo service is a deployment prerequisite.
NetBird retains legacy object names only as rename aliases so reconciliation can
migrate existing policies without duplicates. Its generic operations-host policy
no longer opens Git SSH port 22.

Historical evidence, signed manifests, measured results and service issue links
retain their original provider identity. The old ts-ops NetBird runbook is marked
legacy; it is not the desired dedicated-manager installation contract.

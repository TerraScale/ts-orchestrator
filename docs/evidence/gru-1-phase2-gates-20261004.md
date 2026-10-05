# TS-470 gru-1 phase-2 gate check — 2026-10-04

Phase 1 is merged in [ts-orchestrator #154](https://git.terrascale.tech/TerraScale/ts-orchestrator/pulls/154).
This branch starts from main revision
`3d9205edf0233ca1425eb538ee1211cf1f0e8cb8`. The approved foundation's
[bound plan](gru-1-phase1-completion-20261004/bound-plan.json) remains the
source of live resource identities. This check made no cloud mutations:
no image import, compute, disk, load balancer, certificate or DNS create.

## Artifact readbacks

Read-only Forgejo release and Actions metadata were captured at
`2026-10-05 00:42:51 UTC` (2026-10-04 in America/Sao_Paulo) in
[artifact-readback.json](gru-1-phase2-gates-20261004/artifact-readback.json).
The current main CI run
[981 / 13337](https://git.terrascale.tech/TerraScale/ts-orchestrator/actions/runs/981)
succeeded and published both orchestrator architectures. Its image run
[982 / 13343](https://git.terrascale.tech/TerraScale/ts-orchestrator/actions/runs/982)
failed at `2026-10-05T00:38:53Z`; no qualified image release for this main
revision is present in the captured latest releases.

Job `29407` verified the base image, then failed at `00:38:48.5862549Z`
with `Error: not found: The target couldn't be found.`
(`src/release.rs:644:5`). The next download in
`deploy/image/build-image.sh` is the legacy TerraScale/TerraBase
`qualification.json` asset from
`ci-d2017ca9668a650ec490dff3f79bd51b75bb6466-run-11696`, followed by
`tb-server-linux-arm64`. Main still pins that retired Rust release.
TS-484 owns the reviewed replacement of this image path; do not replace
its inputs or bypass qualification in this rebuild branch.

The latest published qualified image is still
`image-d30f42663eb4c5ba9e5f0917fd8bb5df98dbe309-run-13042-attempt-1`
(release `1284`). Its previously downloaded
[qualification receipt](gru-1-phase1-completion-20261004/stale-image-qualification.json)
pins enrollment SHA
`3534acc1a3c678f83879051692cd7644a51029ccc7189f98b066776e31ffa61b`
and Rust TerraBase revision `d2017ca9668a650ec490dff3f79bd51b75bb6466`.
Fresh enrollment requires SHA
`20a6ab257cb119e2ab3c7d5576e7f8f41108bc704b37d7a556bca736f1e95573`.
That old image cannot satisfy the fresh cell's inputs and was not imported.

The newest non-draft C# TerraBase release is
`ci-bc9c447c52c506f40a1ea8278d613bef4aa4a07a-run-13339`
(release `1301`, the merged region-announcement revision). Its assets are
only `terrabase-linux-amd64` and `terrabase-linux-amd64.sha256`.
There is still no ARM64 asset in that release.

## Required region profile

`deploy/oci-region/terrabase-gru-1-profile.json` now sets
`TERRABASE_REGION=gru-1`, required outside Development by
[TerraBase #18](https://git.terrascale.tech/TerraScale/terrabase/pulls/18).
The existing regional-plan regression asserts that exact value and still
checks both static members against their NetBird addresses. The deployment
example uses the same two-member profile. Use the same JSON in the signed
controller workload and operator `--profile`; the native host path preserves
the profile environment when adding host-owned paths.

## Local validation

The focused `TestGRURebuildPlanKeepsFreshBindingsAndCSharpPeers` regression
passed. `TS_TEST_TIER=pr make verify shellcheck build GO=go GOFMT=gofmt`
also passed: formatting/generated-source checks, vet, race suites,
NetBird backup self-check, shell lint and the local binary build. All local
build/test/lint commands used `nice -n 19` and umask 022. These are offline
profile and CLI checks; they do not establish live phase-2 readiness.

## Remaining approved stage gates

| Stage, in order | Exact approved names | Hold at this main revision |
|---|---|---|
| Image | `gru-1-arm64` | No qualified current image; TS-484 image path and fresh matching enrollment receipt required. |
| Controllers | `gru-1-ctl-1..3` | Image must read back clean first; use merged TS-484 CA/profile/render/bring-up commands. |
| Databases and disks | `gru-1-db-1..2`, `gru-1-db-N-data` | Controller readbacks first; TS-484 native host provisioning and TS-485 native volumes. |
| TerraBase deployment | C# members on both database hosts | ARM64 binary/checksum from TerraBase TS-483; use the merged TS-467 release command and the region profile above. |
| Public edge and auth | Flexible L7 LB `gru-1-api`, Cloudflare Origin CA cert, proxied `gru.api.terrascale.tech` and `auth.terrascale.tech` | Database readbacks first; TS-486 reviewed edge/cost commands and TS-487 ts-auth deployment. |

COS will announce the TS-484/485/486/487 merges. Stage approval persists;
each live stage still needs fresh native inventory and `preview admit`
below USD 200/month, with independent clean readbacks before proceeding.
The last USD 91.16/month phase-1 admission has expired and excludes L7 LB
charges. No admission was refreshed for an unavailable artifact, and no
expired admission was used. Include the reviewed flexible LB bandwidth and
charges before the edge stage. Stop on the first create or readback error;
do not substitute names, shapes or artifacts.

The final edge decision has no `gru-1-gw-1`, Caddy, Let's Encrypt or NLB.
OpenBao remains unchanged. Old teardown apply still awaits COS's explicit
request after the approved October 11 purge window. Deletes and terminations
remain outside the phase-2 create approval.

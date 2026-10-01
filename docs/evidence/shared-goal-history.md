# Shared goal ledger history

This file keeps the superseded sections of the
[shared-goal acceptance ledger](shared-goal-acceptance-20260926.md). S0 moved
them here verbatim from ts-orchestrator `8ea61a7d` on 2026-10-01 so that no
evidence is lost. Every statement keeps its original date and scope: read
"current", "below" and "above" as of the date in each section, not as of
today. Do not edit or extend this file. Current status is in the index and in
the [gate](gates/) and [pipeline](pipeline/) files.

## Pre-handoff ts-infra record

**Later `ts-infra` ownership update:** The inventory, plan, PR, and cost details
below are from the 2026-09-27 pre-handoff snapshot. `ts-infra` main commit
`e347f13a313ebb2b9d0a0b631ba0aed56af65126` later removed the regional
Terraform definitions and workflow after the state-only handoff. Current
`ts-infra` manages four Email Delivery resources only. Regional networking,
IAM, bootstrap inputs, and controller A are operator-managed; after handoff,
`ts-orchestrator` forms B/C and manages ARM workload hosts and TerraBase. This
source update does not prove regional health or a live controller; see the
[manual regional bootstrap runbook](../region-bootstrap.md)
for the current procedure.

### Historical preliminary cost and inventory evidence (pre-handoff)

These figures and workflow artifacts record the earlier proposed regional
estate. They predate `ts-infra` main commit `e347f13a`, which removed the
regional source and workflow after the state-only handoff. They are retained
for provenance; do not use them as the current regional plan, admission, or
instructions for applying regional infrastructure.

A read-only inventory captured at 2026-09-27 03:40:23 UTC found 9 existing
resources and 2 buckets, with no preview compartments. Its file
`/tmp/ts-infra-live-inventory-20260927.json` has SHA-256
`fea2d10567d77f6cf6c7f60f177f70c25cf2e7b1f43802c06e95d3053bef58da`; this
supersedes the earlier 00:37:39 UTC inventory
[`oci-preview-20260926.json`](oci-preview-20260926.json), SHA-256
`23952bb7fb347ee03e62889df6fc6aa0acfa78e28b2a7534c9d0eec319842bd3`.
The provisional estimate is **US$89.55/month**, leaving **US$10.45** under
the combined US$100/month testing-plus-preview cap. It covers five preview
instances at 1 OCPU / 6 GB plus the existing Forgejo VM (7 OCPU / 34 GB total),
450 GB block volumes (200 GB free allowance deducted), a 72-hour 1/6 GB
replacement and 100 GB of volumes, 10 GB Object Storage, 1 million extra
requests, 100 GB egress, a provisional 350 GB snapshot reserve, existing
Forgejo Object Storage, and a US$5 miscellaneous reserve. It uses the lower
Always Free documentation values (1,500 A1 OCPU-hours and 9,000 GB-hours); the
2026-09-23 price catalog lists higher values (3,000 and 18,000), while the
tenancy reports `is-free-tier: null`. The lower values still fit the estimate;
the $5 reserve and snapshot price are estimates, not verified line items. The
assumptions come from Oracle's [Always Free resources page](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
and [price list catalog](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/)
(SKUs B93297/98, B91961/62, B91628/27 and B93455); their A1 free-hour values
conflict, so the lower published allowance was used. A separate full-month
1/6 GB stress host with 100 GB volumes would exceed the remaining margin.
The estimate conservatively includes unrelated Forgejo object costs.

The provisional sanitized foundation plan is
[`ts-infra-foundation-plan-20260926.json`](ts-infra-foundation-plan-20260926.json),
SHA-256 `566700706440b8aa2141a9fd221525246aa563b8ec4c865d4ba1a85599cda3fc`;
it contains 24 creates, 0 updates/deletes, and no compute or data resources.
Its effects digest is `77b397dd5828b3957668e08d4b1e6631089830a516574736823eb8438dc27518`.
The then-current cost plan was `/tmp/ts-infra-gru-preview/scripts/oci-preview/plan.json`
(SHA-256 `33e4cf3c782f8092e5bedbdd0e3c9c5aaf66aa23f1a76b9d61784251e53ff9c4`);
the reviewed approval manifest is
`/tmp/ts-infra-gru-preview/docs/evidence/oci-apply-approval.json` (SHA-256
`dfa20959dc784a8bc6b681579d2553fb2493e82ef14106058da18cbf60ff3465`). The
corrected apply workflow SHA-256 is
`17f6b751c646d0fb8af689bdd64e8dfc47d12536b34a94f24018d23be01b3c6a`; guard
test SHA-256 is
`c61f4ef8154530db30fc2e34524171709d23e580dfcbcbeb41436f19ceb6bb14`; guard
implementation SHA-256 is
`5ff65a58037ad659768592d6073f0c45638dc9bf5329a41d60365e467001f28d`.
Earlier local workflow guard checks ran 7 tests and parsed both workflow YAML
files on their then-current source hashes; no retained test log is available.
At this pre-handoff snapshot, PR #20 candidate
`c1cb2057fb0968bca2a8ddce3df77725c55e8b2e` was Draft/Pending and isolated-runner
task #55 was running. Its then-fresh informational admission has SHA-256
`c90f3db14e2792dbbd0a89c02f73c25727bcee5a8bfb97a106d79063328a4eee`, estimates
$89.55/month with $10.45 headroom, and expires at `2026-09-27T03:55:39Z`; refresh
inventory/admission before any effect. The preview owner reports no OCI
apply/effects. This plan and inventory are evidence only, not a deployed
preview or current permission to create resources.

This pre-handoff inventory and estimate do not authorize resource creation.
Current `ts-infra` automation is restricted to Email Delivery and cannot create
regional foundation or seed resources. Regional networking, IAM, bootstrap
inputs, and controller A are operator-managed under the
[manual regional bootstrap runbook](../region-bootstrap.md). No live regional
deployment is verified by this historical preflight.

## Historical checkpoint — 2026-09-29 02:54 UTC (superseded observations)

The current root [`GOAL.md`](../../../GOAL.md) is the sole goal authority for
this refresh (SHA-256
`99de61cbd4bd49a678d2d48b5cbc92297d93849746773229a80594ba7533d0a6`).
The source identities and acceptance rows below retain their dated historical
scope; this checkpoint supersedes their *progress observations*, not their
receipts or stable IDs. Current OCI and CI progress below is attributed to
the named owners; the ledger refresh did not independently rerun it. **M0 and
D01–D15 remain unverified: 0/16 (0%).**

**Current cost authority is US$200/month combined for qualification and preview.** At the last R3 owner estimate of $90.27/month under its historical $100 plan, arithmetic headroom against the current ceiling is $109.73. Prior $100-plan admissions and dated $100 receipts retain their historical scope. Go main `db0231f1f2ee85cda8c087c8f9cb384147a7662d` publishes the active $200 plan and Python/Go preview caps; `scripts/oci-preview/plan.json` remains $100 because its exact bytes are bound to historical admission evidence. Above $100 still requires a fresh signed active plan, inventory and admission for the selected fixture; no guest-image rebuild follows solely from the budget change. GRU and the A-only runbook handoff remain unchanged.

**Latest owner receipts.** TerraBase main `d2017ca9668a650ec490dff3f79bd51b75bb6466` passed CI #1012/run 11696: Fast 138 passed, 0 failed, 2 ignored, release and publish; [qualification](/home/mariogk/Projects/TerraScale/.qualification/terrabase-ci1012-d2017ca/qualification.json) SHA-256 `69ef5119a78ec1692d49f12447f66cdeb72ca09d8e42f135c05e779ef0e992e9` binds the retained binaries. This is source and CI evidence, not OCI acceptance. Go main `db0231f1f2ee85cda8c087c8f9cb384147a7662d` CI #696/job 25225 failed test fixtures ([log](/tmp/ts-orchestrator-run-696.log) SHA-256 `e9b52655d56aa1aebaf030aadac18eef459fbc0346ab2c5ba17f3fce0a402cfa`); the seven-path test-only correction (patch SHA-256 `da675fa56748faa4179636824c8796a50963443b9889d62ea32e52c5fc7ccc39`) passed independent review, and the repository-wide race command passed locally against this base plus patch ([log](/tmp/ts-orch-ci696-full-race-r2.log) SHA-256 `6d6637ba4a2b53aa0ef5613f42e1588042b7fa2164dcdf0711d651fc28ea8c41`). Corrected main and matching Forgejo CI qualification are pending. R3 A and its boot volume are **TERMINATED**. The R3 attempt-1 intent was signed at 02:12:51.372 UTC and stored at 02:17:45.656 UTC, beyond its 61-second publication window; no HEAD exists, so that attempt cannot be recovered by the current API. Root selected fresh R4 `ts-preview-gru-20260929-r4` with StorageDomain prefix `r4-20260929`; signed R4 artifacts and rebaked image remain pending. The image builder requires the next corrected Go main SHA/tree with matching successful CI; Go37 is historical image evidence and cannot be rebaked from its tag. There are no live controllers or admitted workloads. M0 create-only passed, while both bounded `conmon` placement probes held and cleaned up exactly; no guest ran. D10 Complete implementation remains active. These owner-reported advances leave every formal gate open.

| Stable ID | Current owner and bounded evidence | Next qualifying result |
| --- | --- | --- |
| M0 | The independently accepted pinned Go `350a457588ced97ce47ed0cad58c77926357bde6` / TerraBase `1909dcd36c1f0e09189756d976891127312a2d19` source freeze remains [SHA-256](/tmp/ts-m0-repin-freeze-20260928.json) `fd391769e62ca533970fb3cdba501b05f6a75c1692e155c2d57152f1bff77902`; CI binary, kernel and 2 GiB rootfs provenance are pinned, but its wrapper has not built a fresh host test, packet or guest. `workspace_recovery` measured a read-only six-root cache union of 5,315,399,680 B across 83,648 unique inodes at 23:13 UTC, excluding 4,342 hardlink aliases. At that 23:13 UTC snapshot, 21,514,817,536 B `user.slice` usage needed 9,703,657,472 B reclaimed; even all union pages would leave a 4,388,257,792 B shortfall. A later read-only scan at 23:42 UTC found 0 resident bytes among 44 M0 image/output files totaling 82,597,537,016 logical bytes, with no detected readers. `user.slice` had fallen to 19,129,581,568 B, still 7,318,421,504 B above the 11,811,160,064 B admission threshold. Per-file dirty status remains unavailable; no cache advice or reclaim ran. An isolated M0v3 service-adapter/source candidate stages an 18 GiB child cap with +3 GiB reserve admission and 1 Hz actual reserve-floor monitoring; it has no frozen full receipt or live service/container/VM. V3r7 create-only passed ([cleanup](/tmp/ts-m0-runtime-ecbbe4b971b94a6f/no-guest-cleanup.json) SHA-256 `3e44410f14673ae12f33bbd3ece0f93d1a81addfda3c78e7349be6028c5bfb46`). Placement then held when `conmon` escaped the helper with cgroups enabled ([cleanup](/tmp/ts-m0-runtime-50522b610698404d/no-guest-cleanup.json) SHA-256 `e2a353cf0a760c0018c4f1874509001f7b5ddb25fab7caeafac1509a6a37bdeb`) and again with `--cgroups=no-conmon` ([cleanup](/tmp/ts-m0-runtime-31a56979cc124bf6/no-guest-cleanup.json) SHA-256 `1a292a262e97490ece18ec1e90c3649be71438488d4e74c6ea6e9e4f6e80de19`). Both cleanup receipts report no retained container, volume, service cgroup or guest; no joined write/read receipt exists. | Finish read-only Podman 5.8.7 diagnosis and independent review, then one bounded no-guest placement retry. Full M0 guest work remains held pending placement and safe admission. |
| D01 | `deployment_ops` launched corrected r2 controller A `ocid1.instance.oc1.sa-saopaulo-1.antxeljrppuhpdqcycak7v3vtgwhvwzb5onwu74yfq77hit5azulwoaz77ma`, `RUNNING` at `10.251.0.11` ([OCI GET](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r2-deployment/controller-a-before-replacement-instance-get.json) SHA-256 `31f108f31ad4a959e4f859d68b0aad11439694070128428f5061a487a6cf3eb6`). Qualified image/default UEFI/paravirtualized boot, signed NSGs, full Linux/cloud-init ([console](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r2-deployment/controller-a-relaunch-console-history2-full.txt) SHA-256 `c680c6f6c189d634192df8b477e7c32e7a7fb1a4ace679244ab7169d3e2506af`) and [signed seed completion](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r2-deployment/seed-completion-r2.json) SHA-256 `d88c4a394c761fddc6e79d08798dacb1e89d170abd4cf026baa031164dc97617` are recorded. The required 41-byte `terrascale-bootstrap` IMDS slot descriptor was initially absent; an approved metadata-only addition was read back with unchanged user data (IMDS probe SHA-256 `bd04972cf3e18b2e82e47a9d990acec24f3c17c63a2212a08d3a31ad1233aa8e`), and installer then finished ([stdout](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r2-deployment/controller-a-install-postmetadata.stdout) SHA-256 `bee65d9d6b87c38b71ab2dbcec2cb45ae2d45f39674bae2d461ce06b5c9095b5`). The r2 A's first proven admission blocker was exact ordered NSG comparison although OCI returned the same set reversed ([sanitized diagnostic](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r2-deployment/controller-a-admission-order-diagnostic.json) SHA-256 `434d00b0918b69fabe8bd05956604081a522b839217e4b6b7041672053668dc9`); later gates remain unknown. Go main `8a6ceb94a6b66307655ee93ae64300c0e6e370f5` changed only `docs/region-bootstrap.md` to pin the tested seed-launch request and metadata/firmware/observer gates; it does not contain the uncommitted locally integrated five-file NSG-set/IMDS correction ([source identity](/tmp/ts-r2-nsg-imds-source-identity-20260928.txt) SHA-256 `c751f445f497e4934465a3002bf6ce5b96b30d49e91f853a55ecf1a0ab0a5c40`); focused bootstrapstart/hostenroll tests passed (log SHA-256 `a23439c39a3c9558223e10e7177ef14a3fe1510c1cba293217fb1aceaa0cf654`) and independent narrow source review accepted. No corrected binary was deployed to r2 A. Bootstrap/controller were held under temporary `Restart=no` before r2 A and its boot volume were **TERMINATED** ([instance](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/r2-a-terminated-get.json) SHA-256 `90974cea62d9304a4b21847a1f1f332afe991dcf28d8876c5a4b23959cb2c6d9`; [boot](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/r2-a-boot-postterminate.json) SHA-256 `10718ddbf07de99769ef8b7ced6bcec6e28312d0d9043c7800f771239ac4a96f`). Prelaunch readback found `10.251.0.11` free and A1 capacity AVAILABLE in FD-1 ([IP](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/subnet-private-ips-r3-prelaunch.json) SHA-256 `cd6a282e5c402db796f8d44b72d031afa7a805c5d09776f962d9589c2ad5c9e8`; [capacity](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/a1-capacity-r3-prelaunch.json) SHA-256 `064562662766f93a3e11204afdffcedca52612955c2b3060a1ff5dc03b0d1ff3`). There is no accepted marker, A handoff, B/C or workload. Postlaunch cost receipt SHA-256 `e7b2890a757be3d1f2cd30fbf3e0484f998906906afd42520083b8d8f05bb519` estimated $90.23/month and is historical. Root chose a fresh `ts-preview-gru-20260928-r3` namespace; r2 signed records remain immutable and r3 empty-prefix prep SHA-256 `aa135a0aeefa94f45a7694682f8dd3406de3bae97a2558650fe2ba745789a443` was followed by fresh prepublication collision readback SHA-256 `ad20d16e6aacbae4acc67270aca23d386eb73fe7bfd1aa0d9d5ecbbad5a86805`. R3 controller material SHA-256 `f1db079bc2350cd560132f2c581ae2a22519c164d8685b13d018219e375441f4` and signed anchor SHA-256 `d3e553c2cd8ad75bc70d88630ea2e6e842b0f6d9c10c0e2fdaa672d4bc8a7432` are prepared; independent exact-version Vault readback passed 25/25 ([receipt](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-vault-exact-version-readback-r3.json) SHA-256 `a68c1b41cd0d3f0bedeb1e3777490d75ee99fc12908ae8bc27e9cf4d27068e83`). R3 controller A `ocid1.instance.oc1.sa-saopaulo-1.antxeljrppuhpdqc5wxlo2uugb544px56fjab64utbkkvd3oslydzpdkfe6q` launch was accepted at 01:12:31 UTC as `PROVISIONING` ([submit](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-launch-submit-r3.json) SHA-256 `297a76e1090f0f64b610b703e692e37af568c9ab46f9c64ade3d0a4fed2e9ab5`); it reached `RUNNING` ([poll](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-running-poll1-r3.json) SHA-256 `4a9990f82ec62c7b1b908aabb38a58159be1d846ac3b970aefd2812b8d81168d`) with primary `10.251.0.11`, exact two NSGs and no public IP ([VNIC](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-vnic-r3.json) SHA-256 `72d7f4fc72be0dac297f2e432845ea113ad9362db78a38596b3feecad1226d05`), and 50 GiB boot volume AVAILABLE (SHA-256 `e8af88e0d9a17302ab33dba37df5d32f3a1f0ccddd6a73badb3a5987b9ae515d`). This does not prove installer or bootstrap admission. Reviewed NSG/IMDS fixes are committed/pushed as Go `37cec40938bd9cac8e34168dde222c7739ccf125` / tree `a774e39d3c3fa7472e17c06bd38bcf8d1449464e`; CI #694 succeeded at run 11667/job 25159 attempt 1 ([qualification](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-go-release/qualification.json) SHA-256 `63a9667b291885d8198b6e916f4d059149eed3e44c9bafb0abc52578c8a1525d`); retained ARM64 binary SHA-256 `a65e48c5c739823443d28b809199fdbe1bc9d227e6d5ac03814fe125991ea760`. Signed delegation SHA-256 `c9300be63404ce9418aabc43e91a0d97d7424d8f58149dcaaada3345ad6a12c1` and binary receipt SHA-256 `662083fbe69e5e515d4cba9405cfa4e7fef10d0eec8eb2cd54d542032c4e5512` were attached to the exact CI prerelease and read back. Nine r3 image inputs were published and byte-read back (manifest SHA-256 `61b5357b0f84e1ce046540d07ad0a7d108d2f5b8d5b29ca2d85c02a97bd4d9ea`). Image CI #695 succeeded at run 11670/job 25163 attempt 1; OCI image is **AVAILABLE** ([readback](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/image-readback-available-r3.json) SHA-256 `24427b90e588f94a0406222431adb3010f2c3b6a719be5d45def61c1b135bcff`) with [signed receipt](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/image-receipt.signed.json) SHA-256 `1e6d041c0c96cf4533a4d7a193c4cc19d1a480223ae32f3a2b9e654e86baad57`. Signed founder plan SHA-256 `8ae544e71f2b496cded4a545a83fe9549e3178809c331669cf7fb6c2032680fe` and selection SHA-256 `70beab9c3cbd3eafd9843778065d1b2678ff8714bcb83f6e822eadf82cbcd880` were among six published versions with exact byte readback SHA-256 `a11b4f06561c4f190a05694e9000e7478047321c6846ccae37ff362ab59d8368`. Postimport cost admission SHA-256 `521079662ce7745c3bdd899e0a45f24895dc0db90536e91c89c2b0d1ddbc9995` is historical. Historical prelaunch [cost admission](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/cost-admission-r3-prelaunch.json) SHA-256 `8372d888cc4b669a8281f960245bc876a64cc84366a7461a13e476969521a3ec` estimated $90.27/month with $9.73 headroom and expired 01:25:23 UTC; fresh foundation PASS SHA-256 `b1a9d4d846d6d3e067c878c464a9990270289872a7e9f24b35da44621eef2349`. A [launch request](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-launch-request-r3.json) SHA-256 `7c2ba31ea5a2d16a6dfbfee27b57d4a2e8a7bdc024593daf14cc4ba954c1514e` passed independent source/input preflight with no concrete blocker; reviewed seed plan PASS SHA-256 `4a3f296c2574f362a1d9210ccb608447c0504bece6641f0698d8b0868b83e209`. OCI accepted r3 A launch with exact Go37 image, UEFI_64, 41-byte descriptor and cloud-init byte equality; The installer/admission child entered **HOLD** on missing signed slot ledger ([private stderr hash](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-admission-child-r3.private.stderr) SHA-256 `d3666561cd1b92da3a7258204af3bf1e49d87e18bda4ae652945f2cff624e964`); accepted marker is absent. After 93 bootstrap restarts, Ops stopped it with temporary `Restart=no`; a reservation refresh was attempted. Postlaunch cost [admission](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/cost-admission-r3-postlaunch.json) SHA-256 `471afba94df88b72ecd43c834adb03d5864a79b9cb2274037f1a9a7eeaf860dd` remained $90.27/month under the historical $100 plan (expiry 01:41:38 UTC); foundation PASS SHA-256 `eebd218b70099e6d4921829f84847d8934063ab0ed8aba6e092392c8589fced9`. The attempt-1 intent [readback](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-intent-readback-after-error-r3.json) SHA-256 `65c2778bbd79d4ee2323e31f18ef599a78e6fd96d886b4ebfd6f3ff0891034b6` was signed 02:12:51.372 UTC and stored 02:17:45.656 UTC, beyond its 61-second publication window. The slot [ledger list](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-slot-ledger-after-publish-error-r3.json) SHA-256 `92565a9fb53960168555b9a484131917535ff674f6c2f4385bd167f70203d4c0` exists, but the [HEAD list](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-slot-head-after-publish-error-r3.json) SHA-256 `c198a9b3141a234314e3f8434da8bedcae3cb597be653d0c1d083ed0e93372a7` is empty; the current API cannot recover that attempt. Ops terminated R3 A ([GET](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-termination-poll1-r3.json) SHA-256 `c57bdb5d71c98fceb4ffd3031c1e50f3d40ca91c3d19322523f2f8d8477e2690`) and boot volume ([GET](/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928/r3-deployment/controller-a-boot-after-terminate-r3.json) SHA-256 `3df1fa59f6a0c0a74aec554ce5df0d67035ab8e64bb1d7629bc29b6e3b6d0f75`). Go main `db0231f1f2ee85cda8c087c8f9cb384147a7662d` includes the active $200 caps, but CI #696 failed fixtures. Its seven-path test-only correction passed independent review and the repository-wide race run passed locally; corrected main and matching Forgejo CI qualification are pending. Root selected fresh R4 `ts-preview-gru-20260929-r4`, StorageDomain prefix `r4-20260929`; authority and an image from the next corrected, CI-qualified Go main remain to be produced; Go37 is historical image evidence. No live controller, accepted marker, A admission, B/C or workload exists. | Complete Go CI fixture corrections and qualify corrected main, then build R4 signed authority/image and current admission; prove A bootstrap/controller and signed handoff before founder-created B/C, two ARM hosts and external client. |
| D02–D05 | Local document, auth, replication and RustFS checks plus native OCI provider probes remain component evidence. No managed pair has served an external client, replicated under a live fault, or recovered ordinary data through native OCI object tier. | Run the declared CRUD/retry/auth, peer partition/frontier, and cache-loss/object-tier scenarios against the exact deployed pair. |
| D06 | The accepted [M1 fresh-fixture decision](/tmp/ts-m1-d06-fresh-fixture-decision-20260928.md) SHA-256 `15c94cb7b89c489f9267f53b8bd6ebc23e54546eb272055e48c1ce36f9253dee` chooses a newly qualified GRU fixture after Go `37cec40938bd9cac8e34168dde222c7739ccf125` R3/NATS diagnostic feedback: bootstrap A through the runbook, hand off B/C and two hosts to the orchestrator, then deploy first and distinct second TerraBase artifacts through signed desired state **within that same fixture**. D06 must prove data/member/volume continuity, failed-candidate health rejection and qualified rollback or forward recovery there. The old Go350 [management-binary bridge decision](/tmp/ts-go350-d06-management-upgrade-decision-20260928.md) SHA-256 `996b1b96167c87bea9b5875cb0be2222d02a2c62ce81b981c57b4fc33b733399` is a separate unimplemented self-update path, not an M1/D06 prerequisite; broader repeatable host-update remains open. The frozen D06 [source review](/tmp/ts-d06-managed-rollout-source-review-20260928.md) SHA-256 `0be87a0114ff7ac64c045078117e58337c789c6b6bf1711f39296aa8202771ff` is **HOLD**: committed R3 Held may fail seat CAS and never repair after restart; missing/stale/timed-out canary proof lacks a durable Held outcome. A superseding D06 correction [patch](/tmp/ts-d06-managed-rollout-correction-superseding-20260928.patch) SHA-256 `a47b9992409154b7334fd985364848d90a32c4c1c42d4e06a2109219c511706d` addresses both Held cases and passed independent narrow source review; the old HOLD remains historical. The combined D06+D10 candidate still needs trusted app/R3 regression, final integrated review and real rollout. R3 is terminated and fresh R4 is selected but not yet qualified. Diagnostic r2/r3 receipts, resource-owner cleanup and cost overlap remain distinct; no continuity across fixture replacement is claimed. | Complete trusted D06+D10 app/R3 tests, final integrated review and backup exclusion, then qualify a fresh ARM fixture, then run two signed TerraBase artifacts with data/identity continuity and failure/recovery evidence. |
| D07–D08 | The selected initial OCI workload artifact remains TerraBase `1909dcd36c1f0e09189756d976891127312a2d19`, CI #1004/run 11644, with the local Go material → musl Rust → `psql` TLS/replication/reopen receipt SHA-256 `62c288980baf8583d486081a22098b6a1425e2ed70bfc4876cfd971da2eea788`; no deployed SQL/query result exists. Later main `817c63ca228f42fd4eaa593ef159de48fe5f553e` passed CI #1006. TerraBase main `646c68d55899640ef887e8baca3e74bf1163a79f` / tree `f9cd0f04099573c46175ea363c3ac033912f66a2` passed CI #1007 Fast, release and publish per `fj` owner readback; no retained #1007 manifest/log hash was supplied. The accepted 13-file D08 HTTPS candidate remains frozen at manifest SHA-256 `757275d9fd07f045b7fd45d42445dd79a3420064c6a4963d674e96a4e06997de` on an isolated 646 worktree. Its first Fast invocation exited before Cargo because Turso was uninitialized; the candidate-only submodule is now pinned to exact gitlink `64b8ef5742fc18937f9c89806c81e3f6475dc7a3`, and the Fast retry exited 2 during compilation before tests: AWS-LC `hmac::Key::new` requires `Algorithm` by value, while the candidate passed a reference; unused imports also warned ([log](/tmp/d08-test-fast-646c68d5-20260928-rerun.log) SHA-256 `2b2ad78a1c35184e5184168a7630d04510762022c20f14dd6130af956eb65c1a`). The owner corrected only the cursor module, SHA-256 `f6adefb887a10970573f1a2957355bdc35efd99f0757767a80992a86347b5389` ([revised manifest](/tmp/ts-d08-on-d11-646c68d5-compilefix-manifest-20260928.sha256) SHA-256 `32de9c9e264a4bd0f3fa6df4174f697fa4cc50cbc37b66264f70d276a2c66ed1`); independent narrow source review accepted that correction. Its warmed Fast retry still exited 2 before tests: four test requests call `RequestBuilder::json`, unavailable in this build ([log](/tmp/d08-test-fast-646c68d5-compilefix-20260928.log) SHA-256 `d4b60444910372c431d460842d8082b18bf4ca736c93121738fa5a7b31794117`). A subsequent three-file cursor/test correction is staged at [manifest](/tmp/ts-d08-on-d11-646c68d5-compilefix2-manifest-20260928.sha256) SHA-256 `577489e8536c7935541ff71c6ae97e66fda0382e1429bbc53bcf393b53f3c5b7`; independent narrow source review accepted all 13 hashes and confirmed only import order plus equivalent explicit JSON test requests changed. Its build/test result is pending. The final D08 test correction reached [manifest](/tmp/ts-d08-on-d11-646c68d5-compilefix3-manifest-20260928.sha256) SHA-256 `8435af683623cc2f30669c51a9224f8e2963649f54bd5b50862aa63045a3abc3` and independent source ACCEPT. Integrated TerraBase main `9cf90fb58e4eaec1a4a381b4217d99f199bd6dec` / tree `6ce783b56c41ddcfaedf01b8b234bc0e7b6d3e02` passed local full Fast (135 passed/0 failed/2 ignored, plus host S3 1 passed; [log](/tmp/ts-d10-on-d08-d11-fast-final-r8-20260928.log) SHA-256 `7bedaa20d5f3e27a9b8de53ba140ca09f1ac7dd16554aeb56c922b2afc2b8467`), locked Clippy SHA-256 `a4d7107879048e101c1dacec7808d33d6ad1deab06ddda054fec9f24564abb3c`, and Scalar query fixture `[401,200]` SHA-256 `fe9f84b3901ef37d3e9b196b6ce8ad11b705ee0f86563994786c453b7080a459`. CI #1008 release passed; Fast job 25183/run 11677 attempt 1 **failed** after 13m04 (111 passed/25 failed/2 ignored; [log](/tmp/terrabase-ci-1008-fj-logs-20260928.txt) SHA-256 `782507dd37e29daa562d099076d3fdb4bb16415d365294137ab2de6cdf66c90f`) and publish was skipped. The owner is diagnosing process readiness/timeouts and runner CPU pressure; no single cause is proven. New TerraBase main `619df86d044d3ec2a3d020333556eaa46516beca` / tree `f2a21db384270364dceb8c63ba2d94b6bf186579` includes the reviewed D09/CI correction composition (patch SHA-256 `492e7cfb83d1f1597a49b09d0847901c9742d4f4c0ed9fb4380899f991dd4311`); CI #1011 run 11684 release job 25200 passed, but Fast job 25199 failed (134 passed/3 failed/2 ignored, all three distributed-client 20-second readiness cases) and publish job 25201 was skipped. CPU quota was unlimited with no throttling and memory stayed below 4 GiB; the owner is diagnosing the failures. TerraBase main `d2017ca9668a650ec490dff3f79bd51b75bb6466` passed CI #1012/run 11696 Fast 138/0/2, release and publish (qualification SHA-256 `69ef5119a78ec1692d49f12447f66cdeb72ca09d8e42f135c05e779ef0e992e9`). Full schema/relationship/index lifecycle and deployed HTTPS remain open. | Qualify the selected released artifact against scoped deployed SQL and query real clients, including schema/index lifecycle and incomplete-index fallback. |
| D09 | Corrected bounded document-core/HTTPS write fence remains on TerraBase main `817c63ca228f42fd4eaa593ef159de48fe5f553e`, CI #1006/run 11651 Fast 120 passed/2 ignored plus release/publish. The accepted [D09 HTTP subscription integration brief](/tmp/ts-d09-http-subscription-integration-brief-20260928.md) SHA-256 `dbf1e6a66264f2bfc06a4cb969ea304c97da47c3a17f69dd3a30c37e82a67a28` fixes the intended cursor/public error/whole-group contract and real caller checks; a D09-only ten-file HTTP candidate is frozen as [patch](/tmp/d09-http-subscription-source-20260928.patch) SHA-256 `eeb197eb48e7a968f24b3a56e28c70f41864e070861a629472a4b9982b888fa9` and [manifest](/tmp/d09-http-subscription-source-20260928.sha256) SHA-256 `d42d79d7e6ff8c9027d2b5307c31a1b78f5460f18a0ebbd33ec3de52833775c6`. Independent review accepted its production source and Scalar pagination correction; an isolated D09-on-9cf 12-file candidate ([patch](/tmp/d09-on-9cf-integration-20260928.patch) SHA-256 `08e146f335c9c735634d3380e84b2b5c0a08acdd360baf73b0909b5864e5ba37`; [manifest](/tmp/d09-on-9cf-integration-20260928.sha256) SHA-256 `8381285c1aa481dbb9380c2246498f0d6c83b8ae4814b1cbbaeb8ccce21e156e`) includes four bounded D08/D10 overlap resolutions. The owner reports final local Fast **136 passed/0 failed/2 ignored plus S3 host pass** with pinned `psql`; Clippy passed before its final test-only correction. Independent source review accepted all 12 file hashes; the local Scalar fixture subsequently passed per owner. The source-reviewed candidate is now integrated in TerraBase main `619df86d044d3ec2a3d020333556eaa46516beca` with a two-file CI readiness/CPU correction; composed signed-backup focused tests 6/6, standard Clippy and formatting passed. CI #1011 Fast failed 134/3/2 and publish was skipped; later TerraBase main `d2017ca9668a650ec490dff3f79bd51b75bb6466` passed CI #1012 Fast 138/0/2, release and publish (qualification SHA-256 `69ef5119a78ec1692d49f12447f66cdeb72ca09d8e42f135c05e779ef0e992e9`). The independent two-member cursor test remains a follow-on candidate; no packaged-process D10 hold composition or deployed two-member receipt exists. | Run real scoped snapshot/tail/resume, retention reset, slow-consumer and revoked-key cases through HTTPS on the deployed pair. |
| D10 | The independently accepted Go operation v3 [23-file patch](/tmp/ts-orch-d10-backup-operation-v3-20260928.patch) SHA-256 `e42c80b86907a40d319028eb5e8222342bf23cb0a31ecd6c33661e5f300eb3b8` has focused host tests and [review receipt](/tmp/ts-orch-d10-operation-independent-review-v3-20260928.md) SHA-256 `15d271e1978e7f7e5eadc039e9ae142ed7f4cad09d75a15cd600d0b32a505cda`; full Agent, process runner, mounted-volume and Rust held-restart guest remain open. Rust final [30-file manifest](/tmp/ts-d10-final-v3-30-file-manifest-20260928.json) SHA-256 `445071d271f58f968faa39fdafd2a532339d7976ce08d3a3d98c01e7d69538a4` and [evidence](/tmp/ts-d10-rust-v3-evidence-20260928.md) SHA-256 `16652f6bb5113c71434f2a85daf9591908bd5c5f9663607f16fefccff4e6f035` bind strict Clippy/build, signed process 3/3 serial and 3/3 parallel, closure 1/1 and separate owner/peer UIDs with peer credential read denial; independent source review accepted. These local slices do not prove Complete/publication, full Go Agent path, SQL/catalog equivalence, clean restore or PITR; native source frontier still qualifies only two roots/one remote inbox, not >2. The combined 646+D08+D10 40-file overlay patch SHA-256 `5b3c4a24c78beae4dac3d47fde3c17bcdbd9a14db5a2203d89b8a3b409a28360` received independent **source ACCEPT** ([review](/tmp/ts-d10-on-d08-d11-independent-source-review-20260928.md) SHA-256 `63960a2be30d28d4b9601c8780dcd7239c310dacccfcf6ea853affe61071bb88`). A final 43-file TerraBase integration [patch](/tmp/ts-d10-on-d08-d11-integration-final-20260928.patch) SHA-256 `1a599a8c1337885fdae9b0d9c2f3aaf900e5936975fe61f4018f18b735fdaa98` independently passed source review, local full Fast, locked Clippy and Scalar on main `9cf90fb58e4eaec1a4a381b4217d99f199bd6dec`; CI #1008 release passed but Fast failed 111/25/2 and publish was skipped; cause remains under diagnosis. TerraBase main `619df86d044d3ec2a3d020333556eaa46516beca` carries the reviewed D10 source plus D09/CI correction; composed focused signed-backup tests passed 6/6, while CI #1011 Fast later failed 134/3/2 and publish was skipped. The Go bridge predates the mandatory-verifier caller change, and no full Agent/Complete/restore runtime pass exists. The accepted [owner-only Complete proof decision](/tmp/ts-alpha-d10-complete-owner-proof-decision-20260928.md) SHA-256 `c23c5ec8c88be7f2b8157b2662a3a28acf0cec1936515937e093eced3a02cae0` requires owner catalog CAS/readback plus a leaf-signed publication receipt, with peer source-cut verification. The final [Complete implementation brief](/tmp/ts-alpha-d10-complete-publication-implementation-brief-20260928.md) SHA-256 `212f9e6d8bfc0fca9c30b2b7904dcf7de0081fe3121e5db0207d6d849e88a14d` and [decision note](/tmp/ts-alpha-d10-complete-publication-decisions-20260928.md) SHA-256 `7a52325a594a6dee3ac856edf9d7315fc216a3d13eddbf3f0e6914d2fd024ba7` passed independent source review. Replay requires a fully durable journal-linked candidate data file and signed envelope; otherwise recovery reports `capture_uncertain`, does not recapture, and uses a pre-publishing fenced all-member Abort. Implementation, publication wire, real caller, restore and PITR remain unproved. | Review/build integrated producer and consumer, run real packaged host/Agent backup and durable Complete/catalog with restart/partial-roster replay; then clean restore, post-restore write and PITR. |
| D11–D13 | D11 Go crossed-seat/incarnation fix source SHA-256 `068bcabd613056e513810e63db59ddaf1d594bb3fccb2f6924707c39d858de6d` passed focused tests/source review and was integrated by its owner. Rust final codec patch SHA-256 `bf95a656c5047bdc6ea77afb41ee16b6a6cc92df71b0c084d3caa7baeffb07b9` passed required Clippy and reported post-lint focused Fast 6/6; independent final codec review was pending at owner cutoff. TerraBase main `646c68d55899640ef887e8baca3e74bf1163a79f` then passed CI #1007 Fast/release/publish; newer main `9cf90fb58e4eaec1a4a381b4217d99f199bd6dec` passed local full Fast/Clippy while CI #1008 release passed, Fast failed 111/25/2 and publish was skipped. None proves bilateral freeze/import, named-survivor drain, Go/native all-peer runtime or live OCI add/retire; production drain/writer-stop callbacks remain open. D12 still needs separately authorized second region/paired private DRG; D13 has no provider exhaustion/cleanup pass. | Complete D11 reviewed producer/consumer and real provider lifecycle, then D12 regional and D13 exhaustion cases under their distinct authorization and caller prerequisites. |
| D14 | Scalar/OpenAPI source checks exist. The private [first-1909 browser runner](/tmp/ts-first1909-client-runner-20260928/README.md) SHA-256 `690d47cd368609964f5c115b12b445a61231837264eaed3ee106186f7f31052f` uses a Bastion forward and temporary browser/Node CA and hostname scope. Its local Chromium/Playwright fixture reached the correct hostname and rejected unknown CA and wrong host; independent review accepted the prepared runner. TerraBase 9cf local Scalar query fixture passed `[401,200]` (log SHA-256 `fe9f84b3901ef37d3e9b196b6ce8ad11b705ee0f86563994786c453b7080a459`). No deployed member listener, signed customer material, TLS-valid browser origin or live Scalar route result exists. | After managed pair and signed CA/client scope, admit exact runner script hashes and execute deployed `/docs`, `/openapi.json` and direct browser API examples with success/error responses and route/spec coverage. |
| D15 | The older same-guest harness finding is superseded by `ts-orchestrator` commit `1758532e`: `qualify.py`, `pressure.py`, `alpha_adapter.py`, `alpha_runner.py`, README, and `test_pressure.py` now distinguish dedicated controller and workload hosts. Existing tests cover role routing, distinct controller pin, controller probe without a host unit, and role-bound samples. The read-only [r2 ARM readiness packet](/tmp/ts-alpha-d15-r2-arm-runtime-readiness-20260928.md) SHA-256 `61bd2bb10c610ab7480c64cb6cc91e552ebb91ba2b6ac9c2c134f83ae661ba17` maps Go350/image #690 to configured management normal priority, weights, memory floors and role caps plus the exact after-handoff probe and bounded pressure sequence. The qualified Go37 r3 image remains historical and AVAILABLE, while R3 A and boot are TERMINATED. R4 image rebake is pending. The packet contains source policy, not effective guest settings; A/B/C and hosts have no runtime or pressure evidence yet. A truthful management hold is permitted, but it cannot turn a failed serving-path check into PASS. | Reuse the source-pinned role-aware probe on each exact qualified fresh-fixture controller/host guest after handoff, then run bounded CPU/memory/I/O, OOM and restart scenarios with before/during/after cgroup and data-path evidence. |

### Full remaining scope mapped to the existing IDs

This is the open-work map from root `GOAL.md:119-205,210-249,271-337`,
not another gate count. Every group below remains **OPEN**; source, offline,
or CI preparation above does not verify the real caller and required
environment. Existing detailed rows and TerraBase child IDs carry the
individual executable checks and evidence references.

| Milestone and existing IDs | Remaining acceptance scope (all open) |
| --- | --- |
| **M0 — M0-01–M0-06** | Pin the Go/Rust/Turso source pair, effective Turso patch, lockfiles, runtime config, contract and artifact digests. Through the real host caller prove placement/tenant/database/shard/member/incarnation/authority identity; volume and mount identity, args and credential provisioning/reload; selected ACK profile, catch-up, admission and exact serving predicate; signed host observations versus native serving proof, rejecting stale reports; and safe stop/update with admitted and uncertain write outcomes. A clean checkout must build that pair and run automated `Controller.ApplyDesired` → `Agent.Run` → `processRunner` → authenticated Rust document write/read. |
| **M1 — D01–D06, D14, D15** | Under the **US$200/month combined ceiling**, run the GRU five-A1 layout: assistant runbook through A and explicit identity/authority handoff, then orchestrator B/C plus two distinct enrolled, mounted ARM hosts through journaled OCI and signed desired state (**D01**). Through external TLS prove document mutation/read, scoped auth, wrong tenant, invalid input and retry (**D02–D03**); selected leaderless ACK/visibility profile, conflicts, partition/rejoin, durable and applied frontiers (**D04**); Turso-backed ordinary SSD/S3 cold read and disposable cache loss on the native provider, plus safe interrupted publication (**D05**). Separately qualify local RustFS and native OCI. Prove member/controller restart, catch-up, truthful serving, second changed artifact, health gate and failed rollout with compatible rollback or qualified recovery (**D01, D04–D06**). Retain logs, readiness, Prometheus, runbook and real ARM execution; use the deployed Scalar browser and direct API requests (**D14**); measure exact-image management reservations, workload CPU/memory/I/O caps and OOM/restart behavior under concurrent pressure (**D15**). |
| **M2 — D02–D03, D07-SQL-01–10, D08–D09, D14** | Complete supported document CRUD/upsert/transactions with invalid, unauthorized, retry, uncertain, restart and replica cases (**D02–D03**); indexed filters, projection, order and pagination, database/collection/schema/relationship provisioning, integrity and delete policy, including index lifecycle (**D08**). Real scoped `psql` must prove TLS, grants, isolated sessions, supported reads/DML/commit/rollback, atomic capture, replicated application and rejection of unsupported SQL before effects (**D07-SQL-01–10**). Reactive clients must prove snapshot/tail/resume, retention resync, bounded consumers and revocation (**D09**). Exercise administrative/lifecycle interfaces and consistent request/response shapes, auth, rotation/revocation and tenant isolation across the supported APIs (**D03, D07–D09**). Keep complete executable Scalar examples, direct browser requests and route/spec CI current for every exposed HTTP method/path (**D14**). |
| **M3 — D06, D10–D13** | Prove regional cell formation, enrollment, first boot, replacement, credential rotation, persistent control recovery and self-update (**D06, D11–D12**). Add/catch up members with signed authority and stale-writer fence; require named-survivor durable drain before scale-in/detach/retire, with automatic scale-in disabled until qualified (**D11**). Exercise bounded load scaling, hysteresis, cooldown and interrupted actions; retain deployed/rollback artifacts and clean abandoned uploads (**D11, D13**). Prove independently retained backup, clean restore and PITR with metadata and post-restore writes (**D10**). Form a separately authorized second independent region and verify cross-region behavior through paired DRG private peer/control routes, application mTLS and signed identity, failing closed on route loss (**D12**). Qualify live OCI uncertain-operation replay, resource ownership and cleanup, supported host architectures, durability/recovery and exhaustion matrix (**D11–D13**). |
| **Across M0–M3 — M0-01/M0-06, D01, D06, D10–D15** | Keep one repository-held runnable HTTPS client walkthrough that provisions, checks and removes its data; repeatable setup/build/deploy/smoke/diagnose/cleanup commands; truthful inspectable asynchronous operation IDs, states and retries. Promote immutable tested bytes through verified release admission, canary and health checks, with complete cache keys, safe CI concurrency/cancellation, first-class ARM artifacts and exact artifact-bound milestone receipts. Maintain this stable-ID checklist with owner, producer/consumer, supported config, expected result, executable check and evidence; record current inventory, recurring cost and cleanup. Performance tuning, model advice, and regional Raft remain explicit deferrals, not erased requirements. |

The eventual evidence owner should extend **this ledger's existing IDs** with
the root goal's owner, producer/consumer, supported configuration, expected
result, executable check and evidence reference. The
[TerraBase evidence ledger](../../../terrabase/docs/evidence-ledger.md)
already holds TerraBase requirement IDs; link its applicable entries instead
of creating a second checklist. The joined A-handoff/first-smoke receipt,
repository-held runnable HTTPS walkthrough, D14 browser operator, and D15 live
pressure operator still need explicit ownership after the signed A handoff.
The prepared smoke client remains under `/tmp` and is not that repository
walkthrough. Later section details are dated source evidence; none advances a
formal gate from this checkpoint.

## Source identity

The workspace root has no Git revision (`git rev-parse` fails because it is
not a repository). The source snapshot used for this ledger is:

| Source | Revision or SHA-256 | Worktree |
| --- | --- | --- |
| Workspace [`GOAL.md`](../../../GOAL.md) | `c9933171fba8c997a91ed48e4fae62f6d9f8932ee7d3b62aa6abd8c0c820291b` | Frozen by doc owner for this evidence snapshot |
| Root [`AGENTS.md`](../../../AGENTS.md) | `6d0e45ba183117ef522ab321831b28971d5b1a45575cab45314acdef2909653a` | Human-owned; unchanged |
| `ts-orchestrator` | HEAD `c845e6ca2c04f5cd435c9c3039d731f8a453ebfa` | Dirty |
| `terrabase` | HEAD `7930f774552034cbb5d5ad1cae2d1bd28d254ccd` | Dirty |
| `terrabase/crates/turso` | submodule `64b8ef5742fc18937f9c89806c81e3f6475dc7a3` | Dirty patch/worktree |
| M1 Go verification | commit `429edc2d51380f333aa6521bfd7d6b1fa23af574`, tree `38ce47f2c8e5f1def7f5c54339c23d6b53b019d9` | inventory SHA-256 `492696dd6d97236fb8954104b3f72e28b5a9dcf8b7eb1a4514af562dd3705285`; `make verify` result and log hashes are recorded in the M1 evidence refresh |
| Final Go candidate with authorized deletions | `.qualification/final-go-candidate/source-checkpoint-098a0df/checkpoint.json` SHA-256 `889ae53f4aaf872b2d51bb7b5bbd2769909cab119f7386f796b9a3d260bc95bb`; commit `098a0dfa38771c752f545ac3d2f09662da4c76a7`, tree `bbfab724a19b5f0d1753971d17e482694acb8190` | Inventory SHA-256 `29cf7e61d0d0370c8c4dd59dd489bdfe7580feea8f9a9e978f012ea26e83bcec`; exact authorized-deletion manifest SHA-256 `43af9b8fef1d2bca87d1a29e46860268fe2dfa2bf567a500b9ea48d1389b23cb`; all 396 paths absent; build/tests pending |
| M3 security UUID source | `.qualification/m3-material-security/source-checkpoint-fc3354a/checkpoint.json` SHA-256 `dc7e586a27a83ef77d081c3bf2f0a2ae0a5334cca813d7fb93d35704d48426be`; commit `fc3354a883613e0f9ba1a8ddcbe7b67a116a4378`, tree `a825fdd47e9c0bfa2b753c5e7e322d7bda044229` | Inventory SHA-256 `1e3d8a44daf588a62af573ae0209e28d2911da8c0c3610349861ea332becb968`; selective UUID compile fix; compile/tests and reviewed-boundary follow-up pending |

The gate-specific rows of this table moved to their gate and pipeline files:
M0 candidate, lock, cgroup-attempt and diagnostic-packet rows to
[M0](gates/m0.md); material provenance correction B and the M1 Go
diagnostic-test pin to [D03](gates/d03.md); the M1 corrected TerraBase source
inventory to [D04](gates/d04.md); crash-test source history, the M1 Rust
process-test pin and the Clippy PR #144 correction to [D05](gates/d05.md);
the D07, D08, D09, D10, D11 and D14 rows to their gate files; and the builder
PR #11 and published builder rows to [P4](pipeline/p4.md).

Relevant document hashes at the latest source refresh: `ts-orchestrator/docs/production-readiness-plan.md`
`5f6555fa95155d69958bb7032c34a31e367f4b1fb8ef9eb72510069df3e7a578`;
`ts-orchestrator/docs/qualification-status-20260926.md`
`fcb3e92413c93affe04f490505f95cfcee5c10f8f4ea3bd2143168056cd79403`;
`ts-orchestrator/docs/terrabase-runtime-contract.md`
`3284fd423a5b2ab79763f30a6cf4fa1fea215968f55448167fd1ef0ef2c06da3`;
`terrabase/docs/acceptance.md`
`601d9b3e74fdc3bac3bce0955d68bbfe6bbba585f7833e59d932fb6c5247b77e`;
`terrabase/docs/evidence-ledger.md`
`4808ad6f6deaf37d5dda1c384e41ce7f2104d086f190c21004275ae7deb5d4fa`;
read-only OCI inventory [`oci-preview-20260926.json`](oci-preview-20260926.json)
`23952bb7fb347ee03e62889df6fc6aa0acfa78e28b2a7534c9d0eec319842bd3`
(captured 2026-09-27 00:37:39 UTC). Sanitized foundation plan
[`ts-infra-foundation-plan-20260926.json`](ts-infra-foundation-plan-20260926.json)
has SHA-256 `566700706440b8aa2141a9fd221525246aa563b8ec4c865d4ba1a85599cda3fc`;
it is provisional review evidence, not an apply receipt.

Selected source hashes: `ts-orchestrator/internal/placement/controller.go`
`9023fe51715c00493e53f673022c01604db81c6fc26d8e46ee650e1236753a8f`;
`internal/placement/terrabase.go`
`f0684f92379dd2db42b2f6a87f617df8c5bb4962787de28aa8392a6da09bfa00`;
`internal/host/managed_runtime.go`
`290123f5d14e94f31ea71b40a18c7b5e4c3115720cdfc6edb6320b383471c17a`;
`internal/app/controller.go`
`1e98c2213d8d216a4944873895c6480b860fda92cf8026b18d1c2162eafbadae`;
`internal/oci/fleet.go`
`6eb941c42d49d6fe957693ea9e5f67678a816a38a33616256f1c9756a1e2be0b`;
`tests/firecracker/managedmember/qualify.py`
`a7c99c49dafaf862b12c99cd96e47574c0455525bffbfc5adc59299cfa92446e`;
`terrabase/crates/tb-server/src/client_http.rs`
`1309674bea92dfd460302ff20ad99746c2aae069cf750e2604e2f2228c117fb2`;
`client_reference.rs` `e9b0815e5a7b0fba190e800e91e262fa0cb661726e06eb7a9babadf7741ab878`;
`http.rs` `f20f5130f2d523f5048ae1777214443da7e0b4b74a27b0fd6f91cca1d763acd1`;
`s3_runtime.rs` `fc90f88cd60dbc0dd673de9d433164cc99947413726c045e2b2877ca6e33760b`;
`member_control.rs` `9f2121ca9adf0367e34d7c10330ff9e237985c37de8d7d453fe6cb0595d91d72`;
`replication_sender.rs` `268f34a0edd695802691c8250a702a34299d09ed4e6a86f92832923a58d1b058`;
`main.rs` `fc055c880067e91819058e5311b869d7ea7ddd9bec322bc44061e1155ad1de52`;
`assets/client-openapi.json` `3ec4f15998b042b7f7bf8e37bc7ecfaf4505f4a2fac7c95fee220fd9acfdaca3`;
`assets/admin-openapi.json`
`161135c737f5392867e7de6063565d831261e126628c5415e8d90b4ac2364b20`;
`tests/client_process.rs` `947587237e5290ffa3b0bad5133b69472fd66e1ea3d198524db70cba14bdd714`;
`tests/replication_process.rs` `d6139c6383cc7fb88a5bc0e4d36ecff64c9a346f5f8ce6bf6b1cd502bc6b8cb3`.

The D15 input hashes that followed here moved to [D15](gates/d15.md).

These selected hashes identify individual working-tree files from the earlier
source snapshot; they are not a substitute for the locked M0 pair above. The M0 source pair and local artifacts are locked, but runtime, Forgejo-published TerraBase ARM release artifacts, and OCI bindings remain pending. The `ts-builder` runner image has since been published separately; see the M0 evidence refresh below. The lock-bound TerraBase
runtime evidence is SHA-256
`0fdd980f51e18a593c345a778f37b840ce2a3e7466d7890aba7736b34f445b65`. An
appended copy is preserved separately at
`.qualification/shared-m0/evidence/runtime-evidence-d9d11e1-appended-20260926.txt`
(SHA-256 `fe355dc6d076ad671d2f34d434768cdf3d40b6baa3cdce93a0450b77cbcc9d53`);
the repair record is
`.qualification/shared-m0/evidence/runtime-evidence-d9d11e1-repair-20260926.txt`
(SHA-256 `791d7581d461bf945ed84a2ff49e509123623d9a73eb06b5dbf76d5f9d649ef4`).
The build operator confirmed the appended content was source-inventory
confirmation, restored the original lock-bound bytes, and left the candidate
lock and running packet unchanged. Current M1 corrected source at `a30a6c6`
has no fresh compile or runtime receipt; the earlier `9d80e7f` compile check
is pre-correction. Any later source or configuration change invalidates only
evidence bound to those changed inputs; refresh those identities before use.
During preparation the operational docs changed to add the $100 cap, D15, the
five-instance R3 ARM topology, and the fixed 16-gate reporting denominator;
the root Goal and qualification status were rehashed after those edits.
Historical cleanup was confirmed intentional. No historical files were
restored. No build, test, deployment, or external mutation was run as part of
this ledger refresh; independent gate results are recorded under M0-02 and
D15.

## Status rules and milestone snapshot

The status rules and the 16-gate denominator from this section are in the
[index](shared-goal-acceptance-20260926.md). The dated milestone snapshot and
critical path were:

| Milestone | Status | Current gate |
| --- | --- | --- |
| M0 — reproducible integration candidate | **IN PROGRESS** | M0 remains active and unverified. Every completed two-VM attempt failed before authenticated database write/read/ACK evidence. Packet-003 now binds a built static `internal-host.test` binary to a checked signed manifest; its reviewed launcher, attempt admission and VM run remain pending. Diagnostic run-002 stopped on member A after `managed cycle is not active`; B has no final report, the SIGKILL cause is unknown, and cleanup completed without errors. Forgejo-published TerraBase ARM release artifacts and OCI bindings remain unbound. |
| M1 — deployed preview | **BLOCKED** | No current OCI deployment or live API result. Exact production object-storage profile/provider, qualified artifacts, host image/preparation, and executable deployment command are still open. |
| M2 — complete supported APIs | **IN PROGRESS** | Source checkpoints are frozen for D07 V2 SQL (`d1d3be9`), D08 indexed query/schema/relationship work plus restart correction (`e16db2e`), and D09 reactive delivery/reset-cursor correction (`fd4154b`). D07/D09 Cargo and process runs remain pending; D08 retains startup-cost risk and has no Cargo/Fast run. No M2 top-level gate is verified. |
| M3 — operation and regional automation | **IN PROGRESS** | D10 has a fresh-clone design and partial source, but capture/restore, 2–8-member backup-barrier coverage and runtime checks remain open. D11 pins Rust bounded-ancestry/V4 source and Go lifecycle source separately; their schema versions do not yet match, and review/build/process evidence is pending. There is no live OCI lifecycle acceptance. Regional replication and live OCI exhaustion/cleanup remain unverified. |

The single ordered critical path is: freeze candidate and signed fixture;
verify release admission and retained artifacts; settle and implement the
selected two-member S3 acknowledgment/serving contract; qualify the ARM host
image and exact R3 five-instance cost/inventory; then run D01–D06, D14, and D15
on those artifacts. M2/M3 work remains recorded below and must not silently
become an M1 prerequisite.

## M1 Go verification refresh

**M1 Go verification refresh (2026-09-27).** On source `429edc2d51380f333aa6521bfd7d6b1fa23af574` / tree `38ce47f2c8e5f1def7f5c54339c23d6b53b019d9` (inventory SHA-256 `492696dd6d97236fb8954104b3f72e28b5a9dcf8b7eb1a4514af562dd3705285`), `make verify` passed ordinary Go tests, vet, race checks, and three Firecracker-related Python suites. `.qualification/m1-go-checkpoint-429edc2/verification-result.txt` SHA-256 is `03e9612bc10ee93ca89a0fd750adb2b8aec31262d78d812a355ff7414a0240dc`; `.qualification/m1-go-checkpoint-429edc2/verify-capped-4g.log` SHA-256 is `018a9ba6637df12b01cda3474d106d13cbe4974d75d43909592a6ac1d2bde438`. Two sudo-dependent checks were skipped. These Python fixtures are not an actual Firecracker VM run; this local verification is not OCI or M1 runtime acceptance.

## M2 — supported API backlog

TerraBase is the workspace GOAL's database producer. The canonical detailed
database requirement/decision tracking remains
[`terrabase/docs/evidence-ledger.md`](../../../terrabase/docs/evidence-ledger.md);
this shared ledger maps product acceptance to real callers. API names below are
stable ledger IDs; their source and verification state is recorded in each row.

The D07, D08 and D09 rows of this section moved to [D07](gates/d07.md),
[D08](gates/d08.md) and [D09](gates/d09.md).

## Verification commands and evidence policy

No build, test, Git, Forgejo, deployment, or external action was run for this
ledger refresh. Its local Markdown link and table-shape check passed with seven
local link targets and no missing targets; `sha256sum` verified the recorded
source and evidence identities. Known repository entrypoints for the later
candidate are:

```bash
cd ts-orchestrator && make test
cd terrabase && make fmt-check
cd terrabase && make test-fast
cd terrabase && make test-slow
```

TerraBase keeps exactly Fast and Slow integration suites; Fast is release
critical and Slow remains independent. Use `fj` for Forgejo status/logs as
required by the repository. The commands above alone do not satisfy OCI or
browser gates. No reproducible M1 deploy command has yet been identified. The
M1 browser check must use the live preview, and resource-pressure evidence must
name the exact ARM image, service/cgroup settings, load profile, outcomes and
recovery receipts. Retain raw reports by immutable candidate digest; refresh
file hashes and relevant ledger rows whenever the shared worktree changes.

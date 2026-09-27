# Shared goal acceptance ledger — 2026-09-26

**Overall: IN PROGRESS.** No milestone is complete. This ledger records the
workspace goal against the current shared worktrees; it does not qualify a
deployed candidate. Historical reports and component tests retain only their
stated scope.

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

**Acceptance completion: 0/16 gates verified (0%).** The fixed denominator is
the M0 exit gate plus D01–D15. A gate counts only when every required child
check passes on the required environment and immutable artifacts. This is
verified acceptance, not effort or source completion.

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
| Locked M0 orchestrator candidate | commit `66db84ae0c2b91256b48581d2f09a3059cc6d767`, tree `386e98cb5304bfa35d0cd30e2d1680dcd9255d5d` | Source inventory SHA-256 `d173531f3f2eee2a75a1bbe944032ae6aca4e5fc266c7abf2bf6b1decc505d2a` |
| Locked M0 TerraBase candidate | commit `d9d11e1a2281c511f9909ed8ff6f49b12abb7bfe`, tree `d02744f10137f8bb75a3540735d14aa7e0fb95e5` | Source inventory SHA-256 `f50c7de5a81b7d0fa55a93b72cb64993642ae03821f20c4788d179514b2502f9`; Turso gitlink `64b8ef5742fc18937f9c89806c81e3f6475dc7a3` and effective patch SHA-256 `3860cb7bb959179a6e651e1b00ca17f647787d2f4c35d2974ecd23274fe7c55b` |
| M0 pair lock | `.qualification/shared-m0/source-pair-d9d11e1-66db84ae/candidate.lock.json` | SHA-256 `383f9db7e21347ac577d2e80d0155d054911db1f9b2e52d8d6e74fc0f70f325b`; its pending bindings still include the later-exported signed packet, the failed two-VM receipt, Forgejo CI/published ARM artifacts, and OCI preview |
| M0 corrected-cgroup attempt | Source pair TerraBase `d9d11e1`; orchestrator `2d6761db8c7fa5893ceed38e1f354754e9`, tree `16c5d596221220e46ebf3bfdee9f0b1fff6a260b` | Lock `.qualification/shared-m0/source-pair-d9d11e1-cgroup-rootfix/candidate.lock.json` SHA-256 `030763c25487dc7c157a09341c957fb5f0207aaf37d60a610c6607d80444234e`; retained run failed after guests started, with no successful application receipt |
| M0 diagnostic-only packet | Orchestrator source `9815fe3b3bb695a8065f45e05f9b7bf050233389`, tree `b263bd6965b6804bd26bf0ff0cd28e88d702bc3c`; inventory SHA-256 `0771f30d25b26d962ca777a83c9bb0d00a65926b88c6184e942d935dc82effb4` | Lock SHA-256 `989f1621791e058e37a19da31aa92753653f529e684e7e70c74f9528e4327518`; diagnostic test `managed_member_firecracker_test.go` SHA-256 `ee4792bc906017917161fa4a864e0c1fce4e84f558f7fa2fa75de746a13b1269`; run-002 failed before member B had a final report. Summary SHA-256 `51896cb2fa53f64fa529d9d899bac1cf24da4df13e443e01322f7338d717895b`, runtime receipt SHA-256 `35abdf10ca8d8bf369d7838240510eb731bc667839f4cbf00baac314af6a8618`, extraction addendum SHA-256 `d4896399b80d69825174db39556d99a586097c868693a4539dbab40419b3ad6b`; cause remains unknown and sampled OOM counters were zero |
| M0 diagnostic packet-003 source | `.qualification/shared-m0/diagnostic/source-checkpoint-b3e97cd/checkpoint.json` SHA-256 `1eb74f480e837ad5b5bd48827a6b9bbc26e1e1c23ca2393f714d5f686918802e`; commit `b3e97cd7104184c3ae33609caf5d094d4650e9bd`, tree `d0e339259828fc8a7fc349c1c139ad0a7bd0c398` | Inventory SHA-256 `245790c212c049f4eab7392d9d14de5f1241312e58ca559bbe3dccb6c7112b3a`; callback-race source review passed. Test binary build, packet export, and check passed; no VM launch is recorded. |
| M0 packet-003 build and packet | `.qualification/operator-builds/m0-b3e97cd/evidence/build-result.json` SHA-256 `617d45cbab9e350c0f407b9a79aa0bc9628a395e35881552e4978d0c6c39de25`; source inventory as above | `internal-host.test` SHA-256 `9f557e072d581e6fe9785e42daf6f09d52aeb620355a28b0682752b054ae5df5`; packet manifest SHA-256 `68198eb265a6b7f1275b177865a0260a80e886b7e483b23bb1196d1333683607`; candidate packet lock SHA-256 `3e5e8d15ba21e089600d925aaa2469a36515451b93b12368975dc434c7940de8` |
| M1 Go verification | commit `429edc2d51380f333aa6521bfd7d6b1fa23af574`, tree `38ce47f2c8e5f1def7f5c54339c23d6b53b019d9` | inventory SHA-256 `492696dd6d97236fb8954104b3f72e28b5a9dcf8b7eb1a4514af562dd3705285`; `make verify` result and log hashes are recorded in the M1 evidence refresh |
| M1 crash-test source history | Earlier TerraBase source `a454119eb3b74e832bb975a6c1baf91ab4f1f837`; corrected source `b3fe7b6df2d96c7b32e039a7c6a2b144d364407d`, tree `8cf5bcc3ced7df24745f0eeebcc526941945d227` | Earlier source inventory SHA-256 `dd04e8269c001ca5ffafde2b66fd43ac030a40583da78ab3b99f8cdb66e26eee`; corrected inventory SHA-256 `914b08d99c14be3e1dfa416390b3807d18364fed1e0a790c4369a9ad550dbbe4`; corrected-source Fast rerun failed and the test fixture correction remains unrun (details below) |
| M1 material provenance correction B | Isolated `.qualification/m1-material-security/ts-orchestrator`, source `bacafff92d443a745b43b3c3d6d766ff170a3d45`, tree `8a6f7a8607b46667290536c285195e7cd939e2c7` | Inventory `.qualification/m1-material-security/revision-b.inventory.sha256` SHA-256 `5c18ca4f5b7924cec78361ca1e5c364e8960dba51aca5c0a7b36d4ca1e035eaf`; source review passed. Focused Go authoritative v2 result `.qualification/m1-material-security/evidence/m1-material-security-go-focused-b-20260927-result-v2.txt` SHA-256 `a6ae96f7d7c119f26f531f91725378c28bc1b9cedd1b79e38e673e1af2e73532`: `managedmaterial` passed; app-controller-loss failed, and IAM/KMS deployment evidence remains open |
| D07 V2 SQL source | `.qualification/m2-sql/source-checkpoint-d1d3be9/checkpoint.json` SHA-256 `8ab2836e60c65e10d870a302964ba5d26e25cb5b566071e5a894501bfd885079`; commit `d1d3be994fb43c39f6df19362477d19016624e61`, tree `0596f13d2f5189e60b9525a22a5366da000c4890` | Inventory SHA-256 `c1198dd0cd5151f4ff73dc036b69f1dab52147013e817bc7f59e5f576c605241`; adds hostile-wire test and supersedes `733c3d8` as the current V2 candidate; compile/process verification pending |
| D08 indexed query/schema source | `.qualification/m2-schema/source-checkpoint-54289a1/checkpoint.json` SHA-256 `9c6b21010b1bb37e7c60e432a38a4caad86ea401d47c899f53168af646eb4e3a`; commit `54289a1fedaddbe6bedc7e853bb6a799f74f331c`, tree `76bfff32158f7d3242f1f6b346240dd5c23e9602` | Inventory SHA-256 `030e489f564eadcb0a834dc7aee9dbb27f1280328a1c6b3567349290b0aaea9f`; this earlier checkpoint has a restart blocker corrected in the later `e16db2e` checkpoint below |
| D08 indexed-write restart correction | `.qualification/m2-schema/source-checkpoint-e16db2e/checkpoint.json` SHA-256 `d49cefb6ecc6da7e9b4ea7430e18f16b7c303f27fceeb69100449f7ce05a79f7`; commit `e16db2efa8ed0b19b6ca16b0200033eb639e2b75`, tree `2647b695741cfddef8dcc013863deeb092f1020b` | Inventory SHA-256 `78e557b159029eb6e08f599146cb041c95acfe22622d563913c02cd400ee0111`; exact two-file correction; restart/history findings reviewed as closed, startup-cost risk remains; Cargo/Fast unrun |
| D09 reactive source | `.qualification/m2-reactive/source-checkpoint-fd4154b/checkpoint.json` SHA-256 `9d2127cff1698c1b30af2ee7b96215659e3af529a7ad6c27c1445aab47f7e575`; commit `fd4154b3663f214e19f7b9a3b709cfb199ae240a`, tree `0eeca40b489f27fd52fe93b1a877c72dc1ffcd11` | Inventory SHA-256 `f1a4b8b4ba4a904cbcd22abda25cf47414f1af81d9cdd587929d50823709d42a`; six-path reset/cursor correction independently reviewed with no blocking issue; Cargo/process verification pending |
| D14 selective API documentation | `.qualification/m2-api/source-checkpoint-e72fecb/checkpoint.json` SHA-256 `0ea4d5b2a58c0348957b7c75c55d37d81be1e834842d3876cdfdd74de5128775`; commit `e72fecbca664ea745f875245a0c35a8249acd4b9`, tree `fb7088c924b52bef7791b665a5943464b81c9986` | Inventory SHA-256 `c7095a9a6f4628f758b34b40953c40c70dc81bcb053dd351bc3e1fc4fdc6d3ba`; combined D09 process check pending; no deployed browser result |
| D14 Scalar CDN source | `.qualification/m2-api/source-checkpoint-55ab3bf/checkpoint.json` SHA-256 `205b4f4f59322657f203e04f05e6aed5c102f08c78edbdf084b4edb5dc1cbcfd`; commit `55ab3bf8b118bdf5f89d7302d90f9f76bec27888`, tree `495cb92ca4677d03834658bc99ab228a47fe4de8` | Inventory SHA-256 `4b990680e3347e3cb83ba5c83001be4f973c6dd8bdf0bdca684ee3a2ac965dff`; exact bundle removals plus Rustfmt/Node/diff and source-page browser fixture passed. Fixture fetched CDN script 200 with SRI, rendered 7 operations and observed direct API 401/200. Cargo/process and deployed HTTPS browser validation remain pending. |
| D10 partial backup source | `.qualification/m3-backup/source-checkpoint-90ac7f2/checkpoint.json` SHA-256 `ba65bd5da9e2433a0960a13d9d72df4745e1c0ec8216323de35ac8739a34a748`; commit `90ac7f217f8ad8e2433883d00a81813bcee5ad12`, tree `c71fe3aec54de8ab073ab11e109d0eda6a6d59c1` | Inventory SHA-256 `5fe5993082bfa7f0a5110aaceab491611ca929ebc7e35b48e0683c0762fe2bf3`; partial source only, independent capture caller unfinished, Cargo/process pending |
| D11 topology bounded-ancestry source | `.qualification/m3-topology/source-checkpoint-61a90ca/checkpoint.json` SHA-256 `7a5c533dd195a3046c49279ab2a4dede2c7f32fb0b2013407e68df892adfef85`; commit `61a90ca4f663f162d11a16d055f2cda291dba0ba`, tree `18005ef6c1d14eb6c7bc2416da95ffbbf5355f83` | Inventory SHA-256 `d1d4b239cdf6696385b23d7eae7c6705889d2b6e1efc37ce12ce78c5d8779eeb`; fixes activation-anchor and post-publication retry findings; formatting/diff passed, rereview/Cargo/Fast pending |
| D11 Go M3 lifecycle source | `.qualification/m3-go/source-checkpoint-b9dcb3a/checkpoint.json` SHA-256 `9f041ef58272c80898bfe4aba910a8fccf9735c938655017c84a639f3cb26c3c` | Commit `b9dcb3a8d03489b19cd85711f1c9582c305d4fde`, tree `90dc14e53a81fddb6f09c4fde17590a9a2fda185`; inventory SHA-256 `aee72ed8d0686d0bf64d38418a8cf7b096aa4087861bd2369c8056553acd78d8`; compile/process pending; its schema producer emits `TBSCH002`, while D11 Rust source currently checks `TBSCH001` |
| D11 successor process-test pin | `.qualification/m3-topology/source-checkpoint-c3553fc/checkpoint.json` SHA-256 `7ee3c16394b2264cec4ae74cb3f7dee1077a8bb850bf65e8149edd72fc5fbd64`; commit `c3553fcf8482169e6a115c4e97b53ef7706db590`, tree `df750ee7783a0b63370de2bc6bd1927d42f7fe53` | Inventory SHA-256 `d0172d0d58f8ee149c15a68fb72f801a7592b378084d60d2455b0ab6c4d063ef`; local successor process test remains unrun and is not live OCI evidence |
| D10 clone-selection source delta | `.qualification/m3-backup/terrabase` base commit `90ac7f217f8ad8e2433883d00a81813bcee5ad12`, base tree `c71fe3aec54de8ab073ab11e109d0eda6a6d59c1` | 12-path inventory SHA-256 `6cd01ed4491c377ef3e30e2ae3ad96c1639ab28dc45d52b1b205d36ba496e7c9`; tracked-diff SHA-256 `3478f6e978582fac36df0479d6a821d9c5dcaaaecaf3f0c9b3006fbdefd76a2c`; `backup_clone.rs` SHA-256 `0edec3711446bdac5fa2df8a6cd3ddbf666f5e67c3d6b0a97bcbbfe3db0853e6`; design/source foundation only, review/compile/runtime pending |
| Final Go candidate with authorized deletions | `.qualification/final-go-candidate/source-checkpoint-098a0df/checkpoint.json` SHA-256 `889ae53f4aaf872b2d51bb7b5bbd2769909cab119f7386f796b9a3d260bc95bb`; commit `098a0dfa38771c752f545ac3d2f09662da4c76a7`, tree `bbfab724a19b5f0d1753971d17e482694acb8190` | Inventory SHA-256 `29cf7e61d0d0370c8c4dd59dd489bdfe7580feea8f9a9e978f012ea26e83bcec`; exact authorized-deletion manifest SHA-256 `43af9b8fef1d2bca87d1a29e46860268fe2dfa2bf567a500b9ea48d1389b23cb`; all 396 paths absent; build/tests pending |
| M1 Rust process-test pin | `.qualification/m1-object-durable/source-checkpoint-d741a61/checkpoint.json` SHA-256 `cc135bf675e3c1a60c2d19bdfd42ecff1141d50f59ade6406c4bbf172dfa10b2`; commit `d741a61cf4d95ae8b433f8c031d459f48df65139`, tree `f7114759c43599e4bc952e20835527ca15132f74` | Inventory SHA-256 `782ba875f58f7195c7b3e94838447b202fda3617c6b7b2887eeb4db82597b649`; independent API review passed; Cargo/Fast pending |
| M1 Go diagnostic-test pin | `.qualification/m1-material-security/source-checkpoint-ef5b6a9/checkpoint.json` SHA-256 `6919d6bbee6218fa77587339e7e2656f302487a329962b9906e8231625f8726c`; commit `ef5b6a9c2ce23c7ad2f748863b99c512bce736f3`, tree `77daf4d6a2f065102043352e76f0e2df96d70e1e` | Inventory SHA-256 `a09f2d76341bef78d858b81e2999331f8f3fb4118970e4a7b4ef608cdb20ca7c`; TLS review passed; focused test pending |
| M3 security UUID source | `.qualification/m3-material-security/source-checkpoint-fc3354a/checkpoint.json` SHA-256 `dc7e586a27a83ef77d081c3bf2f0a2ae0a5334cca813d7fb93d35704d48426be`; commit `fc3354a883613e0f9ba1a8ddcbe7b67a116a4378`, tree `a825fdd47e9c0bfa2b753c5e7e322d7bda044229` | Inventory SHA-256 `1e3d8a44daf588a62af573ae0209e28d2911da8c0c3610349861ea332becb968`; selective UUID compile fix; compile/tests and reviewed-boundary follow-up pending |
| Builder psql PR #11 source | `.qualification/builder-psql/source-checkpoint-71dce0b/checkpoint.json` SHA-256 `5bff8e8692bcbd9563d2987add4a0be952293f46f158467219a2f9afb0cb7861`; commit `71dce0b82c501120cc1836bbeec3e26a6eb23238`, tree `ec79ff90592650037f8dbf16cc39b4f952fea0e0` | Inventory SHA-256 `1aa0453f58b97d87bd6d7f9f28671dd60866bb8d697bafeea2f3fab0b5932f7b`; PR and main checks passed, published digest `sha256:f86332c27fe1babab87b8b59e5892a370a458da62e9d82fbb77b91b457a69fd8`; exact-head review was not present before owner merge |
| Clippy PR #144 local correction | `.qualification/pr143-clippy/source-checkpoint-c9e061f/checkpoint.json` SHA-256 `99f11ed48372920ed263a9968c70272602b1d70c435c7d478125a2b263f7e2d1`; commit `c9e061f40ffac519cd888fa47763418a534771b5`, tree `a11df6cd50e660c76c45c0db0693628c2c72b559` | Inventory SHA-256 `fcb5ef81305163545ed0b8584c6243fe414fdb2f10cd017ffecc746a59011c76`; one-file documentation correction reviewed and diff-checked; not run in Cargo/Clippy CI |
| Published builder runner | Main commit `4dea25f366e1e5a8b125ad2292c10ec2efd91f8f` | Main run #63/API 11083 passed lint and build/verify/publish; published `ts-builder:latest` digest `sha256:f86332c27fe1babab87b8b59e5892a370a458da62e9d82fbb77b91b457a69fd8`; four PostgreSQL 17.11 tools were checked in a disposable container. This is a build-runner image, not a TerraBase release artifact. |
| M1 corrected TerraBase source inventory | `.qualification/m1-object-durable/evidence/terrabase-source-a30a6c6.json` | SHA-256 `d5e96d07c27d6390a45b17249a4fdb446190f107a98302d5351a522ce137aac7`; source commit `a30a6c6daecb9c1c4c8e3b0a889d2295f4a9f85b`, tree `30c14eb85ad43cb1d68290738fd04ab63b94b6ab`, 187 tracked entries, Turso patch SHA-256 `3860cb7bb959179a6e651e1b00ca17f647787d2f4c35d2974ecd23274fe7c55b` |

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

D15 inputs were refreshed after memory-profile rendering was wired into the
offline image builder: controller unit
`4426205d4c814980f5bc87a9e6d9848ceb0aec1b08312f07360ddb42d5238766`, host
unit `e241c56282f4e30cca4eb6b5010640856a7be70244a50ddfe49816c3706da39d`,
`internal/host/native_boundary.go`
`261f5b7959e10d1453cb7a93ad23afe0e23f8ce2d89aab2464504bcfb3c8a969`,
`native_exec.go` `844bbd53ca6785166489b5cd1104157c6483c33f8116a2d9d444bed53d4a7587`,
`runner.go` `6e28fb1cdf32024e10550f19dd17dc29c6ee8fabe4386a1355064d04549731fb`,
`tests/runtime_priority/qualify.py`
`82a21c42114b9b79dea788c9027c9a3235fd374d55ed2822fb606b3889de616d`;
`internal/host/native_boundary_test.go`
`e932b9b257707037a28be864ea16368971d35d15c33ea1a2262581e4e3883d66`;
`tests/runtime_priority/README.md`
`b2e45714e7db5e3cfbe947457b7430c7063eb7f0558e3cb7ae03120c50093f97`; and
`deploy/image/build-offline.sh`
`df0a980775b3a68b5e67717af362fc33a2100858589b60dddde6ead879902a79`.

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

Use only **NOT STARTED**, **IN PROGRESS**, **BLOCKED**, or **VERIFIED**. A
`VERIFIED` entry requires the real caller, identified immutable artifacts and
configuration, required environment, reproducible command, and retained
behavioral evidence. None of the M1 scenarios below currently meets that bar.

| Milestone | Status | Current gate |
| --- | --- | --- |
| M0 — reproducible integration candidate | **IN PROGRESS** | M0 remains active and unverified. Every completed two-VM attempt failed before authenticated database write/read/ACK evidence. Packet-003 now binds a built static `internal-host.test` binary to a checked signed manifest; its reviewed launcher, attempt admission and VM run remain pending. Diagnostic run-002 stopped on member A after `managed cycle is not active`; B has no final report, the SIGKILL cause is unknown, and cleanup completed without errors. Forgejo-published TerraBase ARM release artifacts and OCI bindings remain unbound. |
| M1 — deployed preview | **BLOCKED** | No current OCI deployment or live API result. Exact production object-storage profile/provider, qualified artifacts, host image/preparation, and executable deployment command are still open. |
| M2 — complete supported APIs | **IN PROGRESS** | Source checkpoints are frozen for D07 V2 SQL (`d1d3be9`), D08 indexed query/schema/relationship work plus restart correction (`e16db2e`), and D09 reactive delivery/reset-cursor correction (`fd4154b`). D07/D09 Cargo and process runs remain pending; D08 retains startup-cost risk and has no Cargo/Fast run. No M2 top-level gate is verified. |
| M3 — operation and regional automation | **IN PROGRESS** | D10 has a fresh-clone design and partial source, but capture/restore, 2–8-member backup-barrier coverage and runtime checks remain open. D11 pins Rust bounded-ancestry/V4 source and Go lifecycle source separately; their schema versions do not yet match, and review/build/process evidence is pending. There is no live OCI lifecycle acceptance. Regional replication and live OCI exhaustion/cleanup remain unverified. |

The 16-gate acceptance denominator is `{M0 exit, D01, D02, …, D15}`.
**Completed: none. Remaining:** M0 exit; D01 fresh deployment; D02 document
lifecycle/retry; D03 authorization/isolation; D04 replication; D05
persistence/S3 recovery; D06 update/failed rollout; D07 SQL; D08
queries/schemas/relationships; D09 reactive delivery; D10 backup/restore; D11
member lifecycle; D12 regional formation; D13 exhaustion/cleanup; D14 Scalar;
D15 management resource protection. M0 has no passing real-caller receipt,
and there is no immutable M1 candidate deployed to the required OCI ARM
environment. Recalculate only
when a whole top-level gate closes; source edits, component-suite passes,
historical receipts, and partial subchecks do not increase the numerator.

The single ordered critical path is: freeze candidate and signed fixture;
verify release admission and retained artifacts; settle and implement the
selected two-member S3 acknowledgment/serving contract; qualify the ARM host
image and exact R3 five-instance cost/inventory; then run D01–D06, D14, and D15
on those artifacts. M2/M3 work remains recorded below and must not silently
become an M1 prerequisite.

## M0 — integration candidate boundaries

| ID | Producer / consumer and acceptance | Status | Evidence and blocker / next check |
| --- | --- | --- | --- |
| M0-01 | Candidate lock: pin both repositories, Turso source and patch, toolchain/lockfiles, runtime configuration, artifact digests, and contract versions. | **BLOCKED** | The original pair remains recorded in `.qualification/shared-m0/source-pair-d9d11e1-66db84ae/candidate.lock.json` (SHA-256 `383f9db7e21347ac577d2e80d0155d054911db1f9b2e52d8d6e74fc0f70f325b`): orchestrator `66db84a` and TerraBase `d9d11e1`. Packet-003 has its own diagnostic source, artifacts, and manifest bindings, but does not complete the original release/OCI lock: its candidate lock still lists the VM receipt, Forgejo CI/published ARM artifacts, and OCI preview as pending. |
| M0-02 | Go host → packaged TerraBase: launch two managed members from signed, identity-bound material and complete authenticated document write/read through the real host path. | **BLOCKED** | The earlier locked pair binds TerraBase Fast evidence `78 passed, 0 failed, 1 ignored, 1 filtered`, packaged S3 process suite `1 passed`, an explicitly invoked Go authority decoder test, orchestrator `make verify`, and focused 6 GiB fixtures (prior log hashes remain recorded with that pair). Signed packet-001 and all completed two-VM attempts are historical failures before authenticated database write/read/ACK. Packet-003 separately binds the compile-only Go host test binary to a signed manifest; its local build, export, and read-only check passed, but there is no VM run. See the packet-003 refresh below. |
| M0-03 | Go placement/runtime ↔ TerraBase: preserve tenant/database/shard/member identity, incarnation, authority generation, volume/mount layout, process args, config and credential digest through the actual caller. | **IN PROGRESS** | Relevant fields flow through `internal/placement/terrabase.go`, `internal/placement/controller.go`, `internal/host/managed_runtime.go`, and TerraBase `main.rs`. This is source evidence only; candidate packet and process acceptance are absent. |
| M0-04 | TerraBase serving evidence → Go placement: selected durability profile, client admission, catch-up, exact serving predicate; distinguish signed host observation from database-owned serving proof; reject stale/mismatched reports. | **BLOCKED** | `crates/tb-server/src/member_control.rs` still reports serving/drain unavailable, and routes return 501. Existing Go controller holds at `awaiting-healthy`; no TerraBase-owned signed serving receipt or peer-ACK packet is evidenced. Select the two-member acknowledgment/failure-domain contract and connect its actual receipt consumer. |
| M0-05 | Go/TerraBase update boundary: safe stop/update, admitted and uncertain write outcomes, authority fencing, restart recovery. | **BLOCKED** | No deployed changed-artifact or interrupted-operation scenario exists. There is no evidenced operation that binds the stop/update result to a durable member receipt and recovers uncertainty through restart. Define the exact behavior in the selected contract and exercise it through the real caller. |
| M0-06 | Forgejo → release admission → deployment: required checks qualify and retain exact immutable artifacts; admission rejects anything unqualified. | **IN PROGRESS** | `make release-linux` passed on frozen orchestrator commit `66db84ae0c2b91256b48581d2f09a3059cc6d767`, tree `386e98cb5304bfa35d0cd30e2d1680dcd9255d5d`. Verified local static linux binaries: amd64 SHA-256 `80737fd726f26b986c4e626f6305ed9d70d47267da30633dffbe5bf87ce2db9c`; arm64 SHA-256 `5f2985e0984f08c0eaa25820a6f89fd093079e403ab2de89bcd065a5a7db4c3b`. Build log SHA-256 `9bfeebdb8d82448f3594b14efa2d82e15b0c8947745a33727fcf3e78751b30c3`; artifact verification log SHA-256 `9c0413f63733eac5522c23300f9b1f06b85adde8d4127cdcd1e784424624de33`; manifest SHA-256 `dfb7d3391886c2a3790e0b4f548a3b61ccc47fa41882e7cf1df65d63ca5d4a13`. The binaries passed architecture, static-link, Go-version, target, and exact `vcs.revision`/`vcs.modified=false` checks. These Go binaries are local artifacts only: no Forgejo-published TerraBase release artifact or deployed digest exists for them. Preview workflow/guard corrections passed local tests and YAML parsing; CI and fresh admission remain pending. |

**M0 evidence refresh (2026-09-27).** The corrected-cgroup two-VM attempt is bound to `.qualification/shared-m0/source-pair-d9d11e1-cgroup-rootfix/candidate.lock.json` (SHA-256 `030763c25487dc7c157a09341c957fb5f0207aaf37d60a610c6607d80444234e`), orchestrator source `2d6761db8c7fa5893ceed38e1f354754e9` / tree `16c5d596221220e46ebf3bfdee9f0b1fff6a260b`, with TerraBase still at `d9d11e1`. Its `two-vm-run-001/summary.json` (SHA-256 `97e72366008fa324107df3d5a3e9c87a285df9e6fa79fc398c472dda1415a7ba`) failed with `a: native evidence timeout: HTTP 503: accepted managed report changed identity or lost readiness`; cleanup errors were empty. Both guests reached running, but later processes were `signal:killed`; the cause is unknown, no OOM signature or persistent memory-event evidence was retained, and no database write/read/ACK succeeded. This corrected the earlier host-cgroup precondition failure; it did not qualify M0.

A separate diagnostic-only packet is locked at `.qualification/shared-m0/diagnostic/candidate.lock.json` (SHA-256 `989f1621791e058e37a19da31aa92753653f529e684e7e70c74f9528e4327518`). Its signed manifest is SHA-256 `84c11ace98add2758373736317f335c27da831d038d6907102f0d0b8193f338d`; packet and lock checks passed (log SHA-256 `e227a4e4ddbc9a41d7128f461883ed61120b12d8f4f9b88acc9429ca94466473` and `43717325dfb3a906ccfe6d3fd2a7e13143316f95c4ea3208f56aa89f355192d8`). Its source is `9815fe3b3bb695a8065f45e05f9b7bf050233389` / tree `b263bd6965b6804bd26bf0ff0cd28e88d702bc3c`. Diagnostic run-002 failed: member A's first rejected report was `State=failed` (`failure_code=unclassified`), whose digest maps to `managed cycle is not active`; qualification stopped before a final member B report. Both TerraBase guest processes ended with `SIGKILL`, but the sender is unknown; sampled host and role-cgroup OOM counters were zero. Cleanup errors were empty and no run remains active. Summary, runtime receipt, and read-only extraction addendum hashes are recorded in the source-identity table above. The post-run shared diagnostic checkout later showed `internal/host/managed_member_firecracker_test.go` at SHA-256 `c700cbae51f4f4e4182ac621574490c06cfbb895ecf0f77865c7777271fc092f`; this later uncommitted state was not the tested source, and its actor/time are unknown. The run remains bound to the locked test hash `ee4792bc906017917161fa4a864e0c1fce4e84f558f7fa2fa75de746a13b1269`. The three Firecracker-related Python suites in Go `make verify` are fixtures, not actual VM qualification. The diagnostic Go test and those fixtures do not replace the failed two-VM behavior receipt.

**M0 packet-003 evidence refresh (2026-09-27).** The callback-race correction is pinned at orchestrator `b3e97cd7104184c3ae33609caf5d094d4650e9bd` / tree `d0e339259828fc8a7fc349c1c139ad0a7bd0c398`; checkpoint `.qualification/shared-m0/diagnostic/source-checkpoint-b3e97cd/checkpoint.json` SHA-256 `1eb74f480e837ad5b5bd48827a6b9bbc26e1e1c23ca2393f714d5f686918802e`, inventory SHA-256 `245790c212c049f4eab7392d9d14de5f1241312e58ca559bbe3dccb6c7112b3a`. Independent callback-race source review passed. `go test -p=2 -c -o <artifact> ./internal/host` built a static Linux/amd64 test binary on Go 1.27.1 with exit 0; this was compilation only, not a test run. Build result SHA-256 is `617d45cbab9e350c0f407b9a79aa0bc9628a395e35852e4978d0c6c39de25` and provenance SHA-256 is `4cddecbe5c4118a8246ae87a62fe5cc1860198355732df7a9ec045eca09e4025`; artifact SHA-256 is `9f557e072d581e6fe9785e42daf6f09d52aeb620355a28b0682752b054ae5df5`. Packet-003 export exited 0 and its read-only integrity check returned `CHECK_PASS`: signed manifest SHA-256 `68198eb265a6b7f1275b177865a0260a80e886b7e483b23bb1196d1333683607`, export log SHA-256 `916b027d8cc32ef03ca5c6877d4f60d075cc98b402b4bbf33826096a9e229fd7`, check log SHA-256 `4ad3661b0c34a2c51bab5fcace946875e7173cbe8e211e80bf838d7f4af53f20`. Candidate lock `.qualification/shared-m0/diagnostic/candidate-packet-003.lock.json` SHA-256 `3e5e8d15ba21e089600d925aaa2469a36515451b93b12368975dc434c7940de8` labels this `diagnostic_only` and still lists the two-VM receipt, Forgejo CI/published ARM artifacts, and OCI preview as pending. The checkpoint-verification record SHA-256 `77a74d71ebfa4ca8cffdfcc921770661775c5562e5e55bba04ba748acaecb31d` leaves reviewed launcher, attempt-specific admission, slot release, and end-to-end caller run pending. **No VM was launched and M0 remains unverified.**

The builder runner is now published. PR #10 source commit `1d1bccd13985a347a4e0fdba6918a723d83a5a0b` used `nix/default.nix` SHA-256 `cec4232393adf975cf50ea2798118fae0f2b914dc9cc6412d774c93ce79032d9` and `verify.sh` SHA-256 `a7e2e4736efbb1030c6633d3da245367e50665ab4877d3d4665728deee7fee40`; PR CI run 11068 jobs 24321/24322 passed. Main head `9bc76d880fdbe6ab80852f9c19a8ee329865b3a5` then passed run 11069 jobs 24323/24324 and published `ts-builder:latest` at `sha256:1853fcde8248363e09ab0c706da85c1e27eead6ecc218fb5fefc1dc737cbd32a` (image ID `sha256:d2bbee9c06061251043ae95eb15c80754d944fc8b5ee655b830dd67f2c6ca37d`). The run outcomes are owner-reported; no standalone CI or publication log path/hash was supplied. This is the CI builder image, not a TerraBase release artifact or deployed product.


Known M0 driver command shape (the signed packet manifest exists at
`.qualification/shared-m0/real-caller-66db84ae/packet-001/managed-member-serving-manifest.json`;
the first two-VM run is the retained failed attempt recorded above. Resolve
the host cgroup precondition before any new run, and use a new evidence dir):

```bash
cd ts-orchestrator
go test -c -o <absolute-path>/host.test ./internal/host
python3 tests/firecracker/managedmember/qualify.py check --manifest <exporter-manifest>
python3 tests/firecracker/managedmember/qualify.py run --manifest <exporter-manifest> --run-dir <new-absolute-evidence-dir>
```

M0 exit evidence must come from a clean pinned pair and the orchestrator's real
host launch path, not from a manually started Rust process or a fixture that
does not bind the actual binary digests.

## M1 — deployed preview and operational protection

Root GOAL §5 selects one GRU (`sa-saopaulo-1`) R3 regional cell: three
`VM.Standard.A1.Flex` controller instances and two separate orchestrator-managed
A1 TerraBase hosts, each initially planned at 1 OCPU / 6 GB, subject to the
combined budget and capacity gates. The database has two fixed members. The
control-plane claim is controller restart and recovery; it is not continuous
management through loss of a controller. JetStream quorum and database-member
replication are independent facts.

| ID | Acceptance and real caller | Status | Current evidence, exact gap, and completion check |
| --- | --- | --- | --- |
| D01 / M1 | One-time bootstrap of the initial controller/foundation and credentials, followed by identity/authority handoff; `ts-orchestrator` creates the two remaining controller peers and two DB hosts, provisions/enrolls hosts, creates/attaches volumes, verifies mounts, and deploys TerraBase through signed desired state; external authenticated write/read and idempotent setup. | **BLOCKED** | At the 2026-09-27 03:40:23 UTC pre-handoff snapshot, inventory found 9 existing resources and 2 buckets but no preview compartments; `/tmp/ts-infra-live-inventory-20260927.json` SHA-256 `fea2d10567d77f6cf6c7f60f177f70c25cf2e7b1f43802c06e95d3053bef58da`. The then-proposed plan had 24 creates, 0 updates/deletes and no compute/data resources; effects digest `77b397dd5828b3957668e08d4b1e6631089830a516574736823eb8438dc27518`. At that cutoff, PR #20's candidate `c1cb2057fb0968bca2a8ddce3df77725c55e8b2e` / tree `e0e2e938c8a468b38f3b9e589a4c59dce8b14510` was Draft/Pending; its PR-body SHA-256 was `25b930c2738196db147459e86fdde8c5d720d0c34c17b836f77d200034e64500`. The then-fresh read-only admission SHA-256 `c90f3db14e2792dbbd0a89c02f73c25727bcee5a8bfb97a106d79063328a4eee` estimated $89.55/month and $10.45 headroom and expired at `2026-09-27T03:55:39Z`. These are historical planning artifacts, not the current regional deployment procedure or authorization. The later `ts-infra` state-only handoff and source cleanup do not prove OCI resource health, a seed launch, or controller identity/authority handoff. D01 remains blocked on qualified ARM image, bootstrap IAM/network/materials, managed production member material, deployed-client evidence, and live end-to-end acceptance. |
| D02 / M1 | Document lifecycle and retry: create/read/update/delete and supported upsert/transactions, expected values/errors, idempotent replay and identity-mismatch rejection. | **IN PROGRESS** | Current client route exposes `readDocument` and `commitDocuments`; mutations/tombstones share the transaction path. Local and signed-distributed process cases exist in `tests/client_process.rs` and `tests/distributed_client_process.rs`, but the recorded Fast/Slow aggregate is from an older 153-input packet and no current OCI artifact was exercised. Run the current checks, then the same walkthrough against deployed artifacts with retry and restart evidence. |
| D03 / M1 | TLS/scoped-key auth, tenant isolation, denied missing/invalid/revoked/wrong-scope requests, private control listeners, and secret-free errors/logs. | **IN PROGRESS** | `client_auth.rs` checks tenant/database/shard, permission, and collection; the request path authorizes before body parsing and at the worker boundary. Current process coverage includes malformed credentials, but managed key rotation/provisioning has no production writer/restart path; NATS bridge ACL and signing-key installation provenance lack live OCI evidence. Isolated correction B at `.qualification/m1-material-security/ts-orchestrator` (inventory SHA-256 `5c18ca4f5b7924cec78361ca1e5c364e8960dba51aca5c0a7b36d4ca1e035eaf`) checks deterministic-object first-writer authority by controller signature over the full bundle/spec/logical locator and OCI namespace/bucket/KMS, binds the customer-envelope digest into the R3 receipt, and verifies the trusted receipt/spec/envelope before CLI output. `operator material-prepare` now requires configured `operator.controller_public_key` (base64 Ed25519 response-verification key). Key changed-source hashes are `config.go` `e016e1af7e31828e06005b3729c05e465a021dd944bae9362c1c4a74e40c253e`, `repository.go` `238d03f28d91e97f4b842dd279017a6c7d05503326d8249f0e5e88eaf5e31393`, `prepare.go` `d74b5ccfe34540c0fffbd4d1734ff84aa1b2ceb9d5ac3ad1a6b401bf331a5d51`, `producer.go` `ab2951303fe68a8ef1761837ce91ef20a16b7279c06416fbacfd43892794d3bd`, `receipt.go` `fe268523b56546e6bf3222d6e677177cc9725980885652055be1ff06928de4be`, and `app/material_preparation.go` `3829ddc707fae625cd023481c53dd953173666efe1a19402da955989d3d1a0ac`. The requested source review passed. A focused Go run later passed `managedmaterial` and failed the controller-loss application test; its result and diagnosis are recorded below. Existing tests cover locator substitution and tampered replies/specs/pins/signer keys. Those reply tests exercise a verifier helper, not the full request path's guarantee that failed verification leaves output empty. Production IAM/KMS policy remains unverified. This correction does not close D03 or M0. Complete on the deployed path, including rotated/revoked material and listener reachability. |
| D04 / M1 | Two real members replicate writes/deletes through declared visibility frontier, survive disconnect/reconnect/repeated delivery, converge supported concurrent writes, and report received/durable/applied progress correctly. | **BLOCKED** | Corrected M1 TerraBase source is inventoried at commit `a30a6c6` / tree `30c14eb8` (manifest SHA-256 `d5e96d07c27d6390a45b17249a4fdb446190f107a98302d5351a522ce137aac7`). The earlier `cargo check -p tb-server --lib --bins --locked` passed only on pre-correction `9d80e7f` (log SHA-256 `f77b7850276f57948fa7d850868b76f51ab2b565524e0ad620032223685ee2d1`); no fresh compile on `a30a6c6` is recorded. Source changes provide no candidate-bound two-member OCI acknowledgment/profile receipt, disconnect/reconnect result, or durable/applied frontiers. Keep D04 open pending current-source verification and deployed two-member evidence. |
| D05 / M1 | Acknowledged writes survive restart under selected profile; interrupted publish is atomic; cold reads/cache loss recover from the actual production object tier and independently checked bytes. | **BLOCKED** | Current M1 source includes distributed object-cut/S3 recovery work; `crates/tb-server/src/s3_runtime.rs` in the qualified source inventory is SHA-256 `ebf01e59dd62ca395432ba3360b7c87a73f166c4ba43458391cd88f3ddeac54b`. The source is `a30a6c6`, but no fresh compile or process evidence exists for that corrected snapshot. Contract `docs/m1-signed-v2-object-durable-contract.md` is SHA-256 `a82ff34edadfbfd10df931845dfdbde052507c7b92447a17ae40b06aeb775dbd`. No candidate-bound production-provider two-member cold-open/cache-loss receipt, interrupted-publish recovery, or independently checked object bytes exists. |
**M1 Go verification refresh (2026-09-27).** On source `429edc2d51380f333aa6521bfd7d6b1fa23af574` / tree `38ce47f2c8e5f1def7f5c54339c23d6b53b019d9` (inventory SHA-256 `492696dd6d97236fb8954104b3f72e28b5a9dcf8b7eb1a4514af562dd3705285`), `make verify` passed ordinary Go tests, vet, race checks, and three Firecracker-related Python suites. `.qualification/m1-go-checkpoint-429edc2/verification-result.txt` SHA-256 is `03e9612bc10ee93ca89a0fd750adb2b8aec31262d78d812a355ff7414a0240dc`; `.qualification/m1-go-checkpoint-429edc2/verify-capped-4g.log` SHA-256 is `018a9ba6637df12b01cda3474d106d13cbe4974d75d43909592a6ac1d2bde438`. Two sudo-dependent checks were skipped. These Python fixtures are not an actual Firecracker VM run; this local verification is not OCI or M1 runtime acceptance.

**M1 managed-material focused Go refresh (2026-09-27).** On isolated source `bacafff92d443a745b43b3c3d6d766ff170a3d45` / tree `8a6f7a8607b46667290536c285195e7cd939e2c7`, inventory file `.qualification/m1-material-security/revision-b.inventory.sha256` SHA-256 `5c18ca4f5b7924cec78361ca1e5c364e8960dba51aca5c0a7b36d4ca1e035eaf` (all 11 listed source hashes passed before and after the run). Command `go test ./internal/managedmaterial ./internal/app -count=1` passed `managedmaterial` and failed `TestAuthenticatedOperatorToHostDeliveryWithControllerLoss` after 172.437 seconds with `nats: no response from stream`; exit status was 1. The authoritative versioned result `.qualification/m1-material-security/evidence/m1-material-security-go-focused-b-20260927-result-v2.txt` has SHA-256 `a6ae96f7d7c119f26f531f91725378c28bc1b9cedd1b79e38e673e1af2e73532`, and the full log `.qualification/m1-material-security/evidence/m1-material-security-go-focused-b-20260927.log` has SHA-256 `1f39afcc66d912400f5e267444b029686f2669f636aec28aaefd3a4c33dc8fc6`. The test scope became inactive after the run and recorded a 1,147,129,856-byte memory peak. Read-only diagnosis `.qualification/m1-material-security/evidence/controller-loss-diagnosis.txt` SHA-256 `7891ab4f9f59db4474ea154016767ab4f406e0aaa1b4277ddb840b95ac1d05ce` found the failure consistent with a missing or delayed `TS_DELIVERY_INTENTS` stream leader after peer1 loss; exact stream quorum at the failure was not sampled, so the cause remains unconfirmed. The full test log is `1f39afcc66d912400f5e267444b029686f2669f636aec28aaefd3a4c33dc8fc6`; peer logs are `3c52cabd1cea53915c8c6bf9b6fdd0e4e74bf671060602caf4867071a692e380`, `4b54cb8397192365a3457db1750f5a60e0c695351411fcaa4663e20c830732bc`, and `97e906452902c3652dfd968e8f21eefa6f779f37f42be72723d66c0fb7784472`. The supersession record `.qualification/m1-material-security/evidence/receipt-supersession-001.txt` SHA-256 `94f0e613e7ff1d2f75f56f1b4aa679600c452219bd9927f29d4010b230f35f90` states that the earlier published hash `fbbd420d5f95ee6263c5c04c8a81efb860fdb6b10f7325ecc47aae8d4c013cf0` is not recoverable; the versioned v2 receipt is authoritative. This remains partial local test evidence, not a pass for the focused package set or deployed IAM/KMS behavior.

**CI priority source audit (2026-09-27).** A source audit of 22 active workflow roots found no active workflow directly lowers scheduling priority. TerraBase and benchmark CI set `CI=true`, which guards their local-priority Makefile behavior. `ts-rust/scripts/qualification/run.sh` contains an unguarded `nice -n 19`, but its active workflow does not invoke that wrapper; old benchmark snapshots are not active workflows. This was a source audit, not a CI run. Audited source identities:

| File | SHA-256 |
| --- | --- |
| `terrabase/.forgejo/workflows/fast.yml` | `89dfa68d4775bee42d79dc45bfbc7fc1386a8a7ec256b2571898fa38e6c5c105` |
| `terrabase/.forgejo/workflows/slow.yml` | `4f07a3d8323c9df7665950a366ac634c69975dd49f7b882d88d00692eba7a182` |
| `terrabase/Makefile` | `824b19133731d94b4592bc8f9262901c6ac845a32a67e93e38805a5d71d6dba4` |
| `terrabase/scripts/ci/run-suite.sh` | `5c54d0c8319e4b2a6e6bb6bf55a04fcb9914062288670a8a4528f366519e7123` |
| `terrabase/scripts/ci/slow-job.sh` | `f86c38213d273db51c06847cab937b8b03713b58a94da0877a1684533937eaeb` |
| `ts-benchmark/.forgejo/workflows/ci.yml` | `2cf1876ad68173c552ef604944c911e2c4b7daaba16bd28204373e2227498008` |
| `ts-benchmark/Makefile` | `e71f04521854169f2d7797fd33a000d62d553fcaaa9877d24ddec1f7564f4ecd` |
| `ts-benchmark/terra-rust/Makefile` | `daaa12c57879c668070b4bd1be83395b1ebae996d8796250638401c8e8b69dbe` |
| `ts-benchmark/https-document/Makefile` | `8125f05fce06929b6778aab1334e828999cb6ed20ad475d34280efdc2e484ac0` |
| `ts-rust/.forgejo/workflows/ci.yml` | `1cee9a4038c348d9d1649a35912c008a812cc58724ce25b0b54da1f3bc5d6e61` |
| `ts-rust/scripts/qualification/run.sh` | `c4c31fa1994228e6988b372917149e4bf6249986b157af265af30f8dd7d5eebb` |

**CI and pull-request refresh (2026-09-27).** Builder PR #11's source `71dce0b82c501120cc1836bbeec3e26a6eb23238` / tree `ec79ff90592650037f8dbf16cc39b4f952fea0e0` passed PR run #62: lint job 24337 and image build/verify job 24338 succeeded. Its build/verify log `/tmp/ts-builder-pr11-job24338.log` SHA-256 is `bdfc6b8c93cb53f4ebd4195b8c6fa08a8da9a111bf431dae7fc429e84334ed97` and contains `verify: ALL CHECKS PASSED`. The owner merged it as main commit `4dea25f366e1e5a8b125ad2292c10ec2efd91f8f`. Main run #63/API 11083 then passed lint job 24340 and build/verify/publish job 24341. Its retained log `/tmp/ts-builder-main-job24341.log` SHA-256 is `e918e2228d985d1502782b4a0a6b091ed4e0079b7bfb986c712632659951eb55` and contains `verify: ALL CHECKS PASSED`. The published `ts-builder:latest` digest is `sha256:f86332c27fe1babab87b8b59e5892a370a458da62e9d82fbb77b91b457a69fd8`; a disposable container pulled by that digest reported all four PostgreSQL 17.11 utilities (`psql`, `pg_isready`, `pg_dump`, `pg_restore`). The exact-head reviewer PASS was absent before the owner merge (the visible prior review was stale). This qualifies the builder image publication only, not the TerraBase release or M0.

TerraBase PR #144 head `8bb6bb6ba6d888c7cbfdf3aa5438e43bff44cc2d` (inventory SHA-256 `1769f89aad564e501c6a26b2365b1d210e02fcea72167c9cb853eec8cf156233`) passed source review, but Fast #924/#925 failed in Clippy before the suite: `tb-storage` passed; `tb-object` reported 121 diagnostics and `tb-document` 6. Logs `/tmp/terrabase-pr144-job24335.log` and `job24336.log` SHA-256s are `bd5b04b3c21a16a4a70dfac9d15f0d684a23ded78bda7adf39273c47899bbc16` and `2d0e936496e0f230503b5370d9bcf6bea663d0492b114f91ddaf13bac09a5b03`. The local one-file documentation correction at `c9e061f40ffac519cd888fa47763418a534771b5` was independently reviewed and diff-checked; it has no Cargo/Clippy run and is not a PR CI pass. The current object corrections also have no passing CI receipt. Do not count either PR as published/release-qualified.

**M1 crash-test evidence refresh (2026-09-27).** The focused Slow crash scenario passed 1/1 on earlier TerraBase source `a454119eb3b74e832bb975a6c1baf91ab4f1f837` (inventory SHA-256 `dd04e8269c001ca5ffafde2b66fd43ac030a40583da78ab3b99f8cdb66e26eee`; `.qualification/operator-builds/m1-a454119/evidence/m1-focused-slow-a454119-20260926.log` SHA-256 `931adb2fd397943d9f59de62d8434f248cb97dc01d503054d5b0ff1b188bfd8e`). A Fast attempt on that source failed at startup with `ENOENT` before assertions (log SHA-256 `c5ab76a0e4d73ec2d579eeb395822004974b823dba1a0795bd53968a2aec2f06`). Corrected source `b3fe7b6df2d96c7b32e039a7c6a2b144d364407d` / tree `8cf5bcc3ced7df24745f0eeebcc526941945d227` has inventory SHA-256 `914b08d99c14be3e1dfa416390b3807d18364fed1e0a790c4369a9ad550dbbe4` and checkpoint SHA-256 `ce8da3b056d4cb7e3b927f10548affce18be031b1183b6e8ab912171d32b977f`; its corrected test source SHA-256 is `8931379280a419b2e672ffc1ce9f60cac62c34c2fa4ec07636746715cda2a6fc`. The earlier Slow pass is limited to its source revision and does not qualify the corrected source or D05.

The corrected-source Fast run now has a retained result. On `b3fe7b6df2d96c7b32e039a7c6a2b144d364407d` / tree `8cf5bcc3ced7df24745f0eeebcc526941945d227`, command `nice -n 19 ionice -c 3 env TB_TEST_FILTER=distributed_object_process::signed_v2_object_durable_ack_gates_peer_and_survives_warm_restart make test-fast` failed its single selected test. Log `.qualification/operator-builds/m1-b3fe7b6/evidence/m1-focused-fast-b3fe7b6-20260927.log` SHA-256 is `a40d000adff8eb3f098dc452cc2b19ff74e6d796c95511412792c35b906af1e2`. The test failed after the member exited following publication failure; subsequent source review determined that fail-stop behavior is compatible with the contract, so this run remains a test failure pending fixture correction. Correction `5f0ba1ad` is under independent review and has not been run. The earlier Slow pass does not qualify this source or D05.

| D06 / M1 | Deploy a second changed artifact; preserve data/identity; pass health gates; inject failure and recover without unsafe format rollback. | **NOT STARTED** | No first deployment or changed-artifact OCI rollout is evidenced. Completion requires two retained artifact digests, update operation identity, failure injection, health-gate rejection, and observed qualified rollback/recovery. |
| D14 / M1 onward | Deployed `/docs` and `/openapi.json` load in a real browser; expected operations, scoped auth, examples, live success/error responses, correct TLS/CORS/server URL, and CI path coverage. | **IN PROGRESS** | The current immutable source pin is `55ab3bf8b118bdf5f89d7302d90f9f76bec27888` / tree `495cb92ca4677d03834658bc99ab228a47fe4de8`, inventory SHA-256 `4b990680e3347e3cb83ba5c83001be4f973c6dd8bdf0bdca684ee3a2ac965dff`. Scalar 1.72.1 loads from the version-pinned HTTPS CDN script with matching SRI; `/docs` and `/openapi.json` stay on the intended API origin, browser API requests go directly to that origin, and the page contains no embedded credentials or third-party request proxy. Its source-page browser fixture fetched the CDN script, rendered the seven current operations, and observed unauthorized/authorized API responses 401/200. This fixture is not a server-process or deployed HTTPS result. Cargo/process and OCI preview browser runs remain pending; Unix-socket/root-only member routes remain outside the browser reference. |
| D15 / M1 | On the exact qualified ARM64 image, prove management CPU/memory reservations, workload CPU/memory caps, I/O weights and OOM policy; use highest configured normal scheduler priority (no RT); apply concurrent CPU/memory/I/O pressure; verify management still reconciles or reports a truthful hold and verify process/OOM restart recovery. Record effective systemd/cgroup values. | **BLOCKED** | Controller/host units set normal scheduling (`CPUSchedulingPolicy=other`), `Nice=-20`, `CPUWeight=10000`, `IOWeight=10000`, best-effort I/O priority 0, `OOMScoreAdjust=-1000`, `ManagedOOMPreference=omit`, and restart-on-failure. `ManagedOOMPreference=omit` marks only the unit cgroup; it is nonrecursive. `internal/host/native_boundary.go` explicitly sets and reads back `user.oomd_omit=1` on the host `supervisor` subgroup, clears OOM preference from the native runner and workload roles, and `tests/runtime_priority/qualify.py` checks protected unit/supervisor cgroups against runner/role eligibility. This is source-level policy evidence plus local packaging checks: `python3 -m unittest discover -s tests/deploy -p 'test_build_offline.py'` passed 20/20, and isolated `systemd-analyze verify` returned 0; no verification log was retained. Native supervisor cgroups get CPU/I/O weight 10000 vs 1000 for workload; workload roles receive `cpu.max` derived at 75% of effective ancestor/affinity CPU, leaving one quarter for the manager, and per-role `memory.max`. The 25% CPU headroom is a source policy choice without a measured management CPU need or pressure qualification. The host unit says an image/profile drop-in supplies `MemoryMin/MemoryLow`; `tests/runtime_priority/qualify.py render-drop-ins` can render profile-bound drop-ins into a staging root, and `deploy/image/build-offline.sh` invokes it and packages the generated profile-bound drop-ins. Native Apply requires `0 < MemoryMin <= MemoryLow <=` the signed reserve and ancestor propagation, so absent drop-in/profile values cause a fail-closed launch. The signed memory profile is operator-supplied; source validation requires process memory >=4 GiB, headroom >=max(1 GiB, 25% of process memory), cgroup cap between process memory and allocatable memory, and reserve plus allocatable <= nominal compute memory. No accepted memory values/RSS basis, OCI image systemd version, pressure/OOM exercise, or process/OOM recovery receipt exists. A prior isolated guest passed only a cgroup-accounting/status boundary check (2 vCPU/6 GiB, no guest NIC), which does not qualify D15. The image build runs `render-drop-ins` and packages the profile-bound files; then run `python3 tests/runtime_priority/qualify.py qualify ...` twice on the booted guest (before and after TerraBase launch), with artifact/config/profile, memory-profile and evidence-directory arguments from `tests/runtime_priority/README.md`. The remaining acceptance work is exact ARM image qualification, bounded concurrent CPU/memory/I/O pressure, and process/OOM restart cases with retained effective systemd/cgroup values. |

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

## M2 — supported API backlog

TerraBase is the workspace GOAL's database producer. The canonical detailed
database requirement/decision tracking remains
[`terrabase/docs/evidence-ledger.md`](../../../terrabase/docs/evidence-ledger.md);
this shared ledger maps product acceptance to real callers. API names below are
stable ledger IDs; their source and verification state is recorded in each row.

| ID | Required caller behavior | Status | Source-backed boundary and completion evidence |
| --- | --- | --- | --- |
| D07 / M2 | Secured PostgreSQL protocol used by real `psql`: documented TLS/credentials, scoped grants/session isolation, reads and supported DML, transaction commit/rollback, retry identity, atomic capture/outbox, replicated application, fail-closed unsupported SQL. | **IN PROGRESS** | Current V2 candidate `d1d3be994fb43c39f6df19362477d19016624e61` / tree `0596f13d2f5189e60b9525a22a5366da000c4890` adds a hostile-wire test and supersedes `733c3d8`; compile and process verification remain pending. There is no passing real-psql or paired-member receipt. `DEC-011` selects auth design; `DEC-010` leaves exact DML/effect/constraint semantics open. Keep this M2; do not make it an M1 prerequisite. |
| D07-SQL-01 | TLS PostgreSQL listener and documented `psql` connection string. | **BLOCKED** | The current V2 candidate includes the PostgreSQL listener, but Cargo has not verified it and no retained TLS `psql` process result exists. Complete with a real `psql` test against the supported service. |
| D07-SQL-02 | Scoped SQL authentication, database/table grants, revocation and key rotation. | **BLOCKED** | The V2 listener source exists, but scoped-grant behavior, cross-scope isolation, revocation, key rotation, and restart have no candidate-bound process evidence. Test allow and deny cases against the running service. |
| D07-SQL-03 | Per-client SQL session isolation and supported transaction lifecycle. | **BLOCKED** | The V2 runtime path is present in source, but session isolation and transaction lifecycle have not been verified. Test distinct sessions, rollback, commit, cancellation, and restart through the listener. |
| D07-SQL-04 | Supported `SELECT` result/parameter behavior. | **BLOCKED** | The frozen V2 server source now includes the SQL caller path, but there is no current-candidate `psql` result/parameter receipt. Verify supported `SELECT` responses through the process caller. |
| D07-SQL-05 | Administrative table/schema provisioning and immutable supported key types. | **BLOCKED** | The SQL listener/event checkpoint does not establish public table/schema provisioning or immutable key policy. Verify the supported provisioning path and key types before advertising them. |
| D07-SQL-06 | Supported `INSERT`/`UPDATE`/`DELETE`/`UPSERT` row effects. | **BLOCKED** | V2 event producer/receiver source is present, but supported `INSERT`/`UPDATE`/`DELETE`/`UPSERT` row effects are not process-verified. Exercise success and invalid operations through `psql`. |
| D07-SQL-07 | Transaction and retry atomicity: local row effects, outbox and idempotency receipt commit together. | **BLOCKED** | V2 event producer/receiver source exists, but no process result proves row effects, outbox, and idempotency receipt commit atomically. Inject rollback, crash, and uncertain outcomes through the service. |
| D07-SQL-08 | Replicate SQL changes and atomically apply event identity before acknowledgment. | **BLOCKED** | V2 SQL event receiver source exists, but no two-member result proves replicated SQL application and event identity are committed before acknowledgment. Verify peer state and accurate durable/applied frontier. |
| D07-SQL-09 | Retry, transaction conflict and commit/rollback response semantics. | **BLOCKED** | V2 runtime source exists, but retry identity, conflicts, and commit/rollback responses have no process evidence. Verify idempotency and uncertain-outcome behavior with the declared client contract. |
| D07-SQL-10 | Reject unsupported original SQL/translated plans before side effects. | **IN PROGRESS** | V2 listener source now wires the SQL path, but fail-closed rejection of unsupported input has no candidate-bound `psql` evidence. Verify rejection occurs before side effects. |
| D08 / M2 | User filters, projections, ordering, pagination and indexed queries; schema provisioning/validation and relationships/deletion policy; correct results across restart/replication. | **IN PROGRESS** | Frozen source `54289a1fedaddbe6bedc7e853bb6a799f74f331c` / tree `76bfff32158f7d3242f1f6b346240dd5c23e9602` contains indexed query/schema/relationship work. Independent restart audit found that reopen validation rejects E0/E6 local-index keys as foreign and rejects retained `WalRole::LocalIndex` events even though the producer emits them for E0/E6; committed indexed writes therefore cannot reopen on that checkpoint. The two-file correction is now committed at `e16db2efa8ed0b19b6ca16b0200033eb639e2b75` / tree `2647b695741cfddef8dcc013863deeb092f1020b`; its frozen checkpoint is `.qualification/m2-schema/source-checkpoint-e16db2e/checkpoint.json` (SHA-256 `d49cefb6ecc6da7e9b4ea7430e18f16b7c303f27fceeb69100449f7ce05a79f7`, inventory SHA-256 `78e557b159029eb6e08f599146cb041c95acfe22622d563913c02cd400ee0111`). Independent review closes the two restart blockers and the historical-cap concern, with startup-cost risk remaining. Cargo/Fast have not started; no candidate process result closes query, relationship, restart, or replication behavior. |
| D09 / M2 | Reactive snapshot plus tail, resumable opaque checkpoints, auth/revocation, retention reset and bounded slow-consumer behavior. | **IN PROGRESS** | The current six-path source pin is `fd4154b3663f214e19f7b9a3b709cfb199ae240a` / tree `0eeca40b489f27fd52fe93b1a877c72dc1ffcd11`, inventory SHA-256 `f1a4b8b4ba4a904cbcd22abda25cf47414f1af81d9cdd587929d50823709d42a`. It corrects reset/cursor behavior; independent source review found no blocking defect. Rust formatting, JSON parsing, and diff checks passed on the pin, but Cargo/Fast/process runs remain pending. Snapshot cut, cross-member resume, revocation, retention reset, slow-consumer behavior, and the deployed SDK caller still need evidence. |

The ten SQL children are M2 acceptance splits under D07. They do not turn
internal admission, CDC or codec fixtures into service evidence. M2 exit still
requires every chosen supported operation to pass success, invalid input,
permission, retry, restart and replication cases through the real client.

## M3 — operation, backups, lifecycle and regions

| ID | Required caller behavior | Status | Source-backed boundary and completion evidence |
| --- | --- | --- | --- |
| D10 / M3 | Independently retained backup; clean-destination restore; PITR; compare data/schema/index/replication metadata; accept valid writes after restore. | **IN PROGRESS** | The accepted design is an independent fresh clone: source remains active; target gets a fresh database, shard, config, and member origins; preserve logical collection/table IDs only under distinct per-shard storage and outer scope; retain authenticated source cut/events as provenance; use fresh origins for new writes; re-sign target authority/bundle and refresh the SQL bundle digest. This is not same-scope retirement/successor. The current 12-path source delta is identified by inventory SHA-256 `6cd01ed4491c377ef3e30e2ae3ad96c1639ab28dc45d52b1b205d36ba496e7c9`; independent review, Cargo and runtime checks are pending. `backup_clone.rs` is a signed selection foundation plus archive route only: there is no completed catalog point, restored-target import caller, post-restore write, or independent restore receipt. The backup barrier still encodes exactly 2 members while the replication runtime supports 2–8; extend the barrier before claiming broad D10 coverage. |
| D11 / M3 | Real OCI member addition/replacement/drain/scale-in with named-survivor durable/applied proof, writer fencing, restart/uncertain-operation recovery and cleanup. | **IN PROGRESS** | Current Rust topology pin `61a90ca4f663f162d11a16d055f2cda291dba0ba` / tree `18005ef6c1d14eb6c7bc2416da95ffbbf5355f83`, inventory SHA-256 `d1d4b239cdf6696385b23d7eae7c6705889d2b6e1efc37ce12ce78c5d8779eeb`, corrects an activation-anchor shortcut and retry after later successor publication; independent review and Cargo/Fast remain pending. The Go M3 source pin `b9dcb3a8d03489b19cd85711f1c9582c305d4fde` produces `TBSCH002`, while this Rust source still checks `TBSCH001`; integrate the D08 schema format and verify the actual producer-to-native path before qualifying the pair. A local successor process test is also unrun. The live OCI caller still lacks complete member addition/replacement/drain/scale-in, named-survivor durable/applied proof, restart/uncertain-operation recovery, and resource cleanup evidence; source contracts and fake providers do not close D11. |
| D12 / M3 | Form independent regional R3 cells; recover controller/quorum state; prove cross-region DB behavior under selected profile with stale-authority fencing and residency preserved. | **NOT STARTED** | The selected initial M1 scope is a single R3 cell. `founder_plan.go`/`founder_runtime.go` require three controller slots; current topology does not prove a second region, cross-region replication, or controller loss recovery beyond restart. Build a second region and verify the declared cross-region contract; do not infer continuous operation through controller loss. |
| D13 / M3 | Bounded admission and storage/provider exhaustion, retry/cancellation, correct pending/failure result, no partial effects/lost acknowledged data, and no leaked resources/active writers/credentials. | **BLOCKED** | No real OCI exhaustion/cleanup acceptance. Source has a four-job S3 publisher queue acquired before writes, disk quotas that reject before allocation, and bounded provider/read timeouts; these are component-level evidence. `BODY_TIMEOUT` currently shares the malformed-body path and returns `400 invalid_request`; no slow-body expiry case or agreed timeout result was found, so document/qualify its expected caller behavior. Storage stats calculate disk bytes but no server metrics caller exports them. Create/attach calls use durable intents, while ambiguous detach/termination lack equivalent replay/reconciliation; fake-provider tests and current inventories do not prove billable-resource cleanup. Exercise bounded failures and cancellation through real callers, then real OCI owned resources, and retain before/after inventory plus data-integrity evidence. D15 is the separate management-path pressure gate. |

## Deferred scope and unresolved decisions

- Comparative benchmarks, performance thresholds, speed targets, and tuning are
  deferred until functional completion. Resource bounds, deadlines,
  backpressure, and capacity checks remain correctness safeguards.
- Optional model-assisted index advice and optimization studies are deferred;
  ordinary index correctness remains in scope when indexed queries are
  implemented.
- Regional Raft remains a separate proposal and is not an M1 dependency.
- The existing leaderless first-release profile is selected, but the precise
  two-member acknowledgment profile, failure-domain guarantee and supported
  production object-storage provider still require a concrete M1 decision and
  enforcement proof.
- D15 has no numeric reserve/cap thresholds in GOAL. The ARM image and service
  configuration must declare measurable values; acceptance is effective
  settings plus successful pressure/OOM/restart behavior.
- The current SQL DML/constraint/effect subset remains open (`DEC-010`). Query
  ordering/cross-scope semantics remain partly open (`DEC-006`). Relationship
  coordination and delete policy need an explicit contract (`DEC-003` and
  document schema/API work).
- D09's reset/cursor correction is pinned at `fd4154b`, but Cargo/process
  results and snapshot/checkpoint, revocation, retention, and slow-consumer
  behavior still need verification through the real SDK caller under
  TerraBase's root-goal ownership.
- D10's accepted design is an independent fresh clone while the source remains
  active. The clone receives a fresh database/shard/config/member origins and
  re-signed authority/bundle; logical collection/table IDs may be preserved
  only with distinct per-shard storage and outer scope, and source cut/events
  remain authenticated provenance. This is a design decision, not completed
  implementation or runtime acceptance. The current backup barrier covers
  two members while the supported replication runtime accepts two through
  eight; extend the barrier before claiming full-roster support. PITR cutoff
  semantics and restore behavior remain open.
- Initial resource accounting is preliminary: the exact OCI compartment/resource
  IDs, selected image, production object provider, current free-allowance basis,
  and retained raw CLI/cost receipt must be bound into the candidate manifest.

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

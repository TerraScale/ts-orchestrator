# Firecracker qualification evidence — 2026-09-26

This note records two separate local Firecracker runs: dedicated member-status run-03 **passed**, while generic four-VM run-02 **failed** at c1 service startup. It supplements the existing readiness evidence; it does not replace or update the project readiness claims. The evidence below is tied to the archived run packets, not the current shared worktree.

## Dedicated member-status run-03 — PASS

Run-03 booted one isolated guest with two vCPUs, 6 GiB RAM, and no guest network interfaces. The guest ran the pinned Go host cgroup test and the Rust cross-language member-status process test:

| Guest test | Result | Evidence |
| --- | --- | --- |
| `TestNativeTenantReadsFiniteCgroupAccountingAfterRecovery` | PASS, one run | [Go host test log](../../../.qualification/ts-orchestrator/20260926-member-status/run-03/logs/guest-go-host-test.log) |
| `member_control_managed::managed_member_status_cross_language_process_boundary` | PASS, 1/1 | [Rust test log](../../../.qualification/ts-orchestrator/20260926-member-status/run-03/logs/guest-rust-test.log) |

The Rust result includes the nested Go marker `MEMBER_STATUS_GO_OK` and the sender marker `memberstatus: authenticated Go client accepted real sender-enabled process`. This supports the pinned guest's cgroup accounting check and the tested authenticated Go-to-TerraBase member-status process boundary. The run summary records overall `PASS`, stable local source hashes, and clean cleanup. Firecracker exited with code 0; the API socket directory and private guest image were removed. See the [run summary](../../../.qualification/ts-orchestrator/20260926-member-status/run-03/summary.json), [event record](../../../.qualification/ts-orchestrator/20260926-member-status/run-03/logs/events.json), and [guest serial log](../../../.qualification/ts-orchestrator/20260926-member-status/run-03/logs/guest-serial.log).

This run does not establish behavior of the current host worktree, client serving, replicated durability, a production service restart, four-guest clock health, or a quorum policy. It used one isolated guest and had no network interfaces or peer.

## Generic four-VM run-02 — FAIL

Run-02 failed because c1's production controller service did not become ready. Its journal repeatedly recorded `production controller requires baked bootstrap inputs`; the driver then timed out waiting for c1 readiness. This is a startup-input failure, not a successful generic cluster qualification.

c1 did pass its recorded guest clock gate: the kernel maximum error was 500 μs and the probe marked the gate healthy. The recorded c1 clock uncertainty reached 232.522041 ms (about 232.5 ms). These observations apply to c1 only; they do not establish clock health for all four guests.

Cleanup completed without recorded cleanup errors: the scoped NTP firewall rule was removed, all four guest processes stopped with exit code 0, and Chrony stopped with exit code 0. The failed-run guest images and logs were retained as evidence. See the [run summary](../../../.qualification/ts-orchestrator/20260926-firecracker/run-02/summary.json), [event record](../../../.qualification/ts-orchestrator/20260926-firecracker/run-02/logs/events.json), [c1 service journal](../../../.qualification/ts-orchestrator/20260926-firecracker/run-02/logs/c1-retained-service-journal.txt), and [c1 diagnostics](../../../.qualification/ts-orchestrator/20260926-firecracker/run-02/logs/c1-live-diagnostics.txt). No retained configuration dump is linked or reproduced here.

Run-02 does not establish readiness for c2, c3, or the host, nor a four-guest clock result, serving, replication, or quorum behavior.

## Run identities

These IDs identify the archived runs and their exact inputs; they are not claims about the current repository revision. The dedicated driver identity is separate from the application revision. The artifact narrative was independently reviewed against the run packets.

| Run input or evidence | Identity |
| --- | --- |
| Application/Go source commit for run-03 and run-02 | `4c284550310f5629976251d157047bc0282eb7be` |
| TerraBase source commit for run-03 | `12850214606652f036e9fde000695fe5743b374b` |
| Dedicated driver source revision | `17fb8d4612c02d376ffb735499c8d8989d54b019` |
| Dedicated driver `qualify.py` SHA-256 | `b488a206d07764fa03213c6648c9dee3012a09c5735be5bf50c0d9859c170711` |
| Dedicated Rust test source SHA-256 | `a13e23d267a67ffc1aeabd03e5a2f6bc376af5920d6fad0c8ed04d1e1b11713d` |
| V2 run input manifest SHA-256 | `cb85ce5e4501fb6b0bc4a16501d4cca040b270d27544ebc3f33f589bc7b73590` |
| Run-03 Firecracker binary SHA-256 | `186a40ad654c56327222071dd3d174038d0b24536d7e6aa75a4ef41be76fa4a3` |
| Run-03 kernel SHA-256 | `586a02db8ea1fd331d45efa6ebf502fff21ceddfedf010ef70ba389b8e095523` |
| Run-03 rootfs SHA-256 | `a6c1cb9c712d8bb9e67b05dd8f46b7e88827250b445e76015e6bb536a15e1af6` |
| Run-03 Go host test binary SHA-256 | `5b50899d7569f1a7c60db144dc1548c87a0534ac3ff17298f57d6cbd01d6b7e6` |
| Run-03 member-status probe SHA-256 | `d319f786ff63c01a6fc87b653d908216ee0952b8daf41acd95c4a63ca0b2891f` |
| Run-03 TerraBase server SHA-256 | `1b8e28e440263bc0fd6019ad9db92b350e0e0b14e8930e7ff77d5ef3a2477718` |
| Run-03 Rust test binary SHA-256 | `e7aa51a0ae3f57836b9b7418338c234197d650ab298b7e2e1a013e8b11da92f6` |
| Run-03 summary SHA-256 | `eebed828de9e7eb21822997ef80db7f671ac84822c0743ac3ab4779bfe79d6de` |
| Run-03 events SHA-256 | `187050e509a54823f6dc89fcf5a3b0a1fd236eaa1e0ad06dc9b8131f224f7f37` |
| Run-03 guest serial SHA-256 | `4a417a48ea02bf670b93e190001508d0164577ee627c6ec386ddb691d25f26b8` |
| Run-03 Go host test log SHA-256 | `d74de6bc691204188345a3148bdb889e38efb0eef8852eb2786c357c804b104a` |
| Run-03 Rust test log SHA-256 | `8547f669d45a476fff9398db37869d0a2429cf4302662a9795de75feeb48e04b` |
| Run-02 summary SHA-256 | `d8356ab94097f9d9d2211a86d24d9251a0e376f5669339b08b01e434a64cbf7d` |
| Run-02 events SHA-256 | `1ffc82224b726afea40561f37f124523f066e0d6b20eb638ee8d42f0fe297d14` |
| Run-02 c1 service journal SHA-256 | `1520fd9e359adccff61b9c0a4fa098159e770e1ae80562814c04f63a2ff061bf` |
| Run-02 c1 diagnostics SHA-256 | `ec21cbf15b07bf59bf6233f497cebe1bef875a87af93a7a9f1dc380a9aefa106` |

The existing [deployment convergence benchmark](../benchmarks/deployment-convergence-20260925.md) is a separate 30-sample in-memory runner measurement: p50 392.267510 ms, p95 405.332181 ms, and maximum 418.143554 ms. It did not start a VM or OS process and is not a measurement from either Firecracker run.

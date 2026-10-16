# Main CI repair checks

The published baseline `847b55fca6c53f8b4f406a0636158a4e8596fe17` failed CI run [38965408843](https://github.com/TerraScale/ts-orchestrator/actions/runs/38965408843) in nine packages. This repair preserves their admission and isolation assertions and updates the stale fixtures/contracts. Only the network-namespace identity comparison changes production code.

The final code candidate is `6aeed6fbd2bb3c6687e3177c11cfbb67dc23bc49`. `checked-source-files.json` proves that all 14 repaired Go files are byte-identical to the exact source used by their passing checks. The final preview fixture is byte-identical to original `d532b936`, which derives the three changed seed identities from the migrated plans using the production formula.

| Package or check | Source checked | Actual result | Retained log |
| --- | --- | --- | --- |
| app: all reported image, release-channel and rollout failures | `8a4b78b5` | race PASS, 104.700 s | `app-and-preview-intermediate.log` |
| dashboard: six reported retained-history failures | `291c078a` | race PASS, 1.157 s | `observation-history-race.log` |
| insights: two reported history/forecast failures | `291c078a` | race PASS, 1.041 s | same log |
| observability: stream-recreation failure | `291c078a` | race PASS, 1.138 s | same log |
| rolloutexec: two reported spool failures | `d0009fe5` | PASS, 0.345 s | `promotion-and-spool.log` |
| tests/deploy: reported promotion failures | `d0009fe5` | PASS, 14.770 s | same log |
| tests/ci: deployment workflow contract | `7943aa05` | PASS, 0.037 s | `deployment-workflow-contract.log` |
| terrabase: both actual namespace-isolation tests | `f3354c8d` | race PASS, 4.232 s, no skips | `restore-namespace-race.log` |
| deploy/oci-region: baseline and admission preview contracts | `6aeed6fb` | race PASS, 14.807 s | `preview-final-race.log` |

The app invocation also ran an earlier preview fixture that failed. Its full log is retained rather than labeling that entire invocation successful. `preview-identity-intermediate.log` records the later three identity mismatches before their independently derived corrections. The final preview check passes both complete preview suites:

```sh
flock /tmp/ts-orch-refactor-gate-check.lock timeout 180s env GOMAXPROCS=2 GOFLAGS=-p=2 nice -n 19 go test -race ./deploy/oci-region -run '^TestPreview(BaseInventory|Admission)Contracts$' -count=1 -timeout=120s
```

The app check selected:

```text
^Test(ManagedImageVerifier|IndependentManagedImageProof|AcceptedManagedImageInitialization|SpecRegistryAdmitsOnlyCurrentlyQualifiedHostImages|ServiceHostImageArguments|ReleaseChannel|RolloutRequestsDeferFutureReceiptAndRefuseEarlyRollback|TerraBaseSyncRejectsUnqualifiedOrChangedInputsBeforeUpdating)
```

Image, update and promotion fixtures now carry independently root-signed production qualification instead of bypassing admission. Observation fixtures use current clocks so retention does not erase their history; the stream fixture preserves another account FILE stream during recreation. Workflow assertions follow CI, credential-free production admission, retained evidence and admitted rollout. Namespace validation compares kernel namespace link identities while retaining the inherited descriptor, new-namespace requirement, loopback and ioctl checks; a real child with the original namespace descriptor must be rejected.

`git diff --check 847b55fc HEAD` and the zero-configuration guard pass. These are targeted local checks, not a whole-repository CI pass. CI must rerun after publication; Ubuntu nsfs permission behavior remains subject to that run. No deployment, cloud mutation, native ARM image, full runtime startup or production acceptance is established here.

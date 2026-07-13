# Phase 0 NATS readiness handoff

- Branch: `docs/phase0-nats-readiness`
- Scope changed: `docs/audits/nats/**`, `testlab/pins/nats-*.json`, `testlab/nats/**`, and this handoff
- External reads: official NATS GitHub releases/documentation and official NuGet package endpoints
- Mutations: one bounded local loopback `nats-server` smoke; no VM, cloud, systemd, container, persistent service, credential, or sibling-repository action

## Result

Five tool candidates are recorded but unselected: servers 2.14.3 and 2.12.7, clients `NATS.Net` 3.0.0 and 2.8.2, and CLI 0.4.0. Linux amd64/arm64 server and CLI asset metadata is pinned to official release URLs, sizes, and SHA-256 digests. Client packages are pinned to official NuGet URLs and locally calculated SHA-256 digests.

The owner-controlled N/N-1 policy remains null and the candidate pair remains unexecuted. Current/prior labels are inventory roles, not compatibility acceptance.

The 27 capability rows contain 3 local x64 smoke passes, 1 partial loopback monitoring result, 22 unexecuted results, and 1 owner-policy-blocked result. Full L0C, ARM64 qualification, and production qualification remain false.

## Validation

```text
python3 testlab/nats/validate_nats_readiness.py
python3 -m unittest discover -s testlab/nats/tests -v
python3 testlab/nats/run_local_l0c_smoke.py > /tmp/nats-smoke.json
cmp /tmp/nats-smoke.json testlab/nats/local-x64-l0c-report.json
rm -f /tmp/nats-smoke.json
python3 -m json.tool testlab/pins/nats-candidates.json
python3 -m json.tool testlab/nats/local-x64-l0c-report.json
dotnet run --project tests/TerraScale.Orchestrator.ContractTests/TerraScale.Orchestrator.ContractTests.csproj --no-restore -- --no-progress --output Detailed
git diff --check
```

The seven adversarial fixtures cover missing architecture support, missing official provenance, implicit tool selection, implicit N/N-1 policy, false full-L0C readiness, incomplete cleanup, and specification semantic drift.

## Next evidence

1. Owner approval of the compatibility policy and exact mixed-version permutations; no recommendation was accepted here.
2. Internal mirror/signature verification and independent download/hash/SBOM validation for all selected artifacts.
3. Generated dual-plane JWT/TLS/account/permission/gateway configuration before credentialed conformance.
4. Full loopback/temp-directory L0C across R3, gateways, JetStream policies, KV/Object Store, consumer failure, advisories, snapshots, peer replacement, reload/rolling behavior, and selected N/N-1 clients/servers.
5. ARM64 execution and production storage/durability evidence in their mandated later gates.

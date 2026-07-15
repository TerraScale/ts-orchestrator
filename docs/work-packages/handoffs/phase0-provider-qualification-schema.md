# Phase 0 provider-qualification schema handoff

- Branch: `docs/phase0-provider-qualification-schema`
- Work package: `docs/work-packages/phase0-provider-qualification-schema.md`
- Scope changed: lane-owned provider audit, pin datasets, offline validator/tests/fixtures, and this handoff only
- Cloud credentials/API calls/resource mutation: none
- Price retrieval, provider winner/selection, OCI eligible-region claim, and qualification: none

## Result

Created a fail-closed custom field-contract for the normalized OCI/AWS/GCP/Azure TCO and storage benchmark plus the OCI `>=20` eligible-region matrix. It is deliberately not labeled as JSON Schema. The contract enumerates all cost and region fields named by `ORCHESTRATOR.md`. The blank dataset keeps every empirical value unknown, all provider results incomplete/unqualified, the OCI eligible count at zero, the threshold claim false, and provider winner/selection `null`.

The 26-entry source catalog uses only official Oracle, AWS, Google Cloud, and Microsoft documentation. Every source statement is bounded as discovery input rather than account, capacity, price, performance, service, or region qualification evidence.

## Validation

```text
python3 -m json.tool testlab/pins/provider-qualification-schema.json
python3 -m json.tool testlab/pins/provider-qualification-blank.json
python3 -m json.tool testlab/pins/provider-source-catalog.json
python3 -m json.tool tools/phase0/provider-qualification/fixtures/negative-cases.json
python3 tools/phase0/provider-qualification/validate_provider_qualification.py
python3 -m unittest discover -s tools/phase0/provider-qualification -p 'test_*.py' -v
python3 -m py_compile tools/phase0/provider-qualification/validate_provider_qualification.py tools/phase0/provider-qualification/test_validate_provider_qualification.py
git diff --check
```

The deterministic validator separates reusable structural validation from the stricter checked-in-blank policy. It checks exact field coverage, all four providers, all six evidence topics per provider, official-source hosts and freshness, cost currency/unit/effective-date clarity, complete benchmark/region rows, unique qualified-row recounting, the `>=20` invariant, and winner/selection gating. Eighteen data-driven negative cases cover the requested failure modes. A generated, never-written `synthetic-fixture-only` positive case populates all four normalized provider results and 20 complete OCI rows; it proves the structural path while remaining unable to pass the CLI's committed blank-policy mode.

## Remaining gates

- An authorized later lane must gather current public and negotiated prices, taxes, FX, discounts, exact quantities, and actual billing exports under an owner-approved normalization policy.
- The same immutable ARM64 TerraBase/fio workload must run for each serious provider and publish raw artifacts plus normalized BRL/day, BRL/transaction, and BRL/IOPS sensitivity results.
- OCI needs account-visible subscription, shape/image/service/limit/quota evidence and capacity probes for each named region; public documentation alone qualifies zero rows.
- OCI region rows also need real Block Volume, expansion, failure/recovery, inter-region, residency, and cost evidence. At least 20 fully supported rows must pass before `claimSatisfied` can become true.
- Price alone cannot select a provider. Storage/HA SLO acceptance, measured post-OKE residual cost, negotiated/operational fit, and owner decisions remain external gates.

No artifact from this lane authorizes a cloud call, provider selection, deployment, or production claim.

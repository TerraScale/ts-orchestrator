# Provider qualification evidence validator

This standard-library-only validator checks the custom field-contract and blank provider/TCO and OCI region-eligibility dataset without cloud credentials, API calls, resource mutation, or price retrieval. The field-contract is not an implementation of JSON Schema.

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- provider-qualification
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

It fails closed on field drift, incomplete provider/source coverage, stale or non-official sources, partial cost or region rows, ambiguous currencies/units, unsupported qualification claims, false `>=20` claims, and winner/selection claims without complete normalized results. Tests separately exercise structural completeness with a generated, never-written synthetic four-provider/20-region dataset; the CLI always applies the stricter checked-in-blank policy.

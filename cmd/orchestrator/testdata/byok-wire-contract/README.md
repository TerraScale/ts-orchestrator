# BYOK renewal wire contract fixture (historical)

This fixture directory is retained from the pre-C# Go implementation. Its
request and response payloads document the strict Dashboard BYOK renewal
contract and remain useful when interpreting the corresponding historical
evidence. The old `cmd/orchestrator` decoder and focused Go test no longer
exist in the current checkout.

The historical response included `allowed`, `status`, `environment`,
`tenant_id`, `project_id`, `database_id`, `admission_operation_id`, `purpose`,
`expires_at`, and the full `byok` object. It accepted only `pending` or
`verified` status, required the response purpose and BYOK tuple/revision to
match the request, rejected unknown members, bounded bodies to 8192 effective
bytes, used a 20-second timeout, and refused redirects.

Current C# validation commands are documented in the repository
[README](../../../../README.md) and [design map](../../../../DESIGN.md).

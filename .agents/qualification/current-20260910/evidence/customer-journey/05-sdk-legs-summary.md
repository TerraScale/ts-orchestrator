# SDK qualification legs — live 3-member stack, 2026-09-10/11

Stack: terrabase 3-member local stack (GRU 7101, SFO 7102, FRA 7103), proxy 7000.
All data-plane legs run against member GRU http://127.0.0.1:7101 with the stack
bootstrap key (prefix `tskey_stack_...`, masked below as `tskey_stack_`+12).

Common env for every consumer (see /tmp/tsqual/journey.env, 0600):

```
TERRASCALE_API_URL=http://127.0.0.1:7101        # member GRU, data plane
TERRASCALE_AUTH_URL=http://127.0.0.1:7100       # dashboard origin (distinct from API)
TERRASCALE_PROJECT_ID=local
TERRASCALE_DATABASE_ID=sdk-journey
TERRASCALE_API_KEY=<bootstrap key, masked>
TERRASCALE_JOURNEY_RUN_ID=qual20260910 | qual20260911b | qual20260911c (one per journey)
TERRASCALE_DENY_API_KEY=tsauth_denied_scope_unissued_placeholder  # unissued credential; member must 401
TERRASCALE_SYNC_URL=http://127.0.0.1:7101       # reactive sync base (SDK default is sync.api.terrascale.tech)
GOPROXY=file://.../ts-go/scripts/qualification/gojourney/file-proxy GOSUMDB=off   # Go only
```

Database `sdk-journey` (placement GRU,SFO,FRA) created through the real member
API before the legs (needs tenant/project scope headers; see 04-member-health.log
context in 03/06 logs):

```
POST /api/v1/databases {"name":"sdk-journey","placement":["GRU","SFO","FRA"]}
  headers: Authorization: Bearer <bootstrap>, Idempotency-Key, x-terrascale-tenant-id: terrabase-local, x-terrascale-project-id: local
  -> 201 {"name":"sdk-journey","placement":"GRU,SFO,FRA",...}
```

Immutable artifacts (all built from each repo's HEAD on 2026-09-10):

| artifact | path | sha256 (first 16) |
|---|---|---|
| npm @terrascale/sdk 0.3.0 | /tmp/tsqual-artifacts/terrascale-sdk-0.3.0.tgz | b1c9d6d335be6f3a |
| crate terrascale 0.1.0 | ts-rust/target/package/terrascale-0.1.0.crate | 2e67800e68a6bbeb |
| crate terrascale-derive 0.1.0 | ts-rust/target/package/terrascale-derive-0.1.0.crate | bb655143e8e6efed |
| nupkg TerraScale.DotNet 0.1.0 | ts-dotnet/src/TerraScale.DotNet/bin/Release/TerraScale.DotNet.0.1.0.nupkg | 6e2e33cc15533a09 |
| go module terrascale.tech/sdk | gojourney/file-proxy (git archive of 658d897) | 59637ff8feddc471 |

## Results (fresh single-journey run id `qual20260911b`, plus `qual20260911c` for .NET repro)

| leg | seed | verify | exercise | cleanup | evidence |
|---|---|---|---|---|---|
| TypeScript SDK | PASS | PASS (4/4 bodies) | PASS (CRUD, idempotent replay, stale If-Match 412, parameterized SQL, reactive attach+write, cancellation, 404 typed, deny 401) | PASS 204 | 06, 10, 14, 18 |
| Go SDK | PASS | PASS (4/4) | PASS (incl. reactive-update, denied-key 401) | PASS | 07, 11, 15, 18 |
| Rust SDK | PASS | PASS ("all four SDK bodies matched exactly") | PASS (stale ETag 412, deny 401/403, conditional write/SQL/idempotency/reactive cancellation) | PASS | 08, 12, 16, 18 |
| .NET SDK | PASS | PASS (4/4) | **FAIL** reactive attach: "The reactive snapshot belongs to another subscription." | PASS | 09, 13, 17, 18 |

.NET earlier same-run-id retries also showed "authoritative receipt/revision
changed" — traced to MY reuse of one run id across repeated exercise attempts:
the member's idempotency store correctly returned the first invocation's
receipt after the journey documents were deleted and recreated between runs.
Not a product defect; disappeared with fresh run ids.

## .NET exercise failure — root cause (deterministic, reproduced on qual20260911b and qual20260911c)

- The member keys reactive views by statement: attach with subscription
  `qual20260911c-dotnet-view` on `SELECT * FROM sdk_journey` returns the shared
  view `v-089ce4d827ff...` and its cached snapshot chunk (`?cut=56`).
- Decoded msgpack frames (snapshot chunk and log delta) both carry the VIEW id
  at the wire message's first field: `message[0] = "v-089ce4d827ff..."`.
- The TypeScript reference client treats that field as the view id and compares
  it to `state.viewId`: ts-typescript/src/sync/v1/client.ts:410-413
  (`if (wireId !== state.viewId) throw ... "frame belongs to another attached view"`).
  TS/Go/Rust therefore pass.
- The .NET client parses the same field as `Subscription` and validates it
  against the client-chosen subscription id:
  ts-dotnet/src/TerraScale.DotNet/TerraScaleReactiveHttpClient.cs:554 (wire type),
  :438/:510 (call sites), :523 (`ConvertSnapshot` throws
  "The reactive snapshot belongs to another subscription." when
  `subscription != attachment.Subscription`).
- Verdict: .NET SDK contract defect (or an under-specified wire field: the
  member and the TS client agree the field is the view id; the .NET client is
  the outlier and fails every reactive attach on a view it did not create
  itself — including any view shared across SDKs, which is exactly what a
  cross-SDK journey produces).

## ts-cli leg (evidence 19-tscli.log)

| command | result |
|---|---|
| `terrascale auth import --token-stdin` (bootstrap key) | PASS (credential_set:true) |
| `terrascale auth status` | PASS |
| `TERRASCALE_API_URL=...7101 terrascale doctor` | FAIL exit 1: `parse GET /api/v1/health: invalid_response: json: unknown field "version"` — ts-cli's vendored SDK (terrascale.tech/sdk v0.0.0-20260908142517-993167f68660, vendor/) predates the member's health contract; CLI drift, not a stack failure |
| `terrascale db list` | PASS (3 databases incl. sdk-journey) |
| `terrascale sql sdk-journey "SELECT * FROM sdk_journey LIMIT 3"` | PASS ({"matched":12,...}) |

Note: `auth import` stores the credential against the default origin
(api.terrascale.tech); data-plane commands need the credential re-supplied via
TERRASCALE_API_KEY for a non-default origin — the CLI reports "stored
credential belongs to a different API origin" otherwise.

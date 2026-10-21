# FUNCTIONS14 source classification candidate

Review `/tmp/ts-functions14-d4ac-source-classification-o5y_ymin/classification.json`; independent peer acceptance and separate ledger promotion are pending.

Canonical `d4ac68882716e7cfb14afca2f88ad596a38041af` / tree `3b73a410a025bd8050ad1d42e54acc7d5eda4b82`; baseline `bfca60368f60d2da67f9016d1d489317ae8749c8`.

Candidate: **7 integration / 0 unit / 7 mixed / 0 unresolved =14**. All28 baseline/current raw declaration hashes independently match; all14 originals survive exactly. Runtime is UNKNOWN for every root.

| Original function | Candidate category |
| --- | --- |
| `TestSignedReleaseWorkerLifecycle` | mixed |
| `TestWorkerBrokerJWTAndTLSIsolation` | mixed |
| `TestFunctionWorkerProcess` | mixed |
| `TestFunctionWorkerRejectsExpiredMaterial` | integration |
| `TestWorkerGuestExecutionAndIsolation` | mixed |
| `TestWorkerCancellationAndCapacity` | integration |
| `TestWorkerFixedDeadlineAndConcurrentClose` | integration |
| `TestWorkerResourceAndImportBoundaries` | mixed |
| `TestWorkerRejectsUnboundedDecoderResources` | mixed |
| `TestHTTPRealWorkerAuthenticationScopeAndLimits` | mixed |
| `TestHTTPRealWorkerTimeoutAndGuestFailure` | integration |
| `TestQueueRealWorkerReceiptsReplayPoisonAndScope` | integration |
| `TestQueueRealWorkerRetriesTimedOutInvocation` | integration |
| `TestHTTPBoundsPendingBodiesBeforeGuestExecution` | integration |

Real guest execution is limited to embedded Wasm/WASI. HTTP/NATS/process/filesystem cases cite actual effects and readbacks. Separate local admission/decoder/credential/collector/authorizer checks are enumerated; incidental setup grants no credit. Supporting busy/closed observations in actual guest lifecycle tests do not become independent integration claims.

No source/Git/ledger changes, retirement, Go/build/test/runtime execution, runtime receipt review, process/lock/cloud action or new agent. Accepted19 retired/4300 retained/102 classified/4198 unadjudicated stays unchanged.

Next: independently review the14 source categories before any ledger promotion.

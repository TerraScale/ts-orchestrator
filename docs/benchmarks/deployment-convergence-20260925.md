# Deployment convergence — 2026-09-25

One completed opt-in local measurement recorded 5 successful warmups and 30
successful samples. For the 30 measured deployments, the median was
**392.267510 ms**, the nearest-rank p95 was **405.332181 ms**, and the maximum
observed duration was **418.143554 ms**. These are results from one run, not a
production latency target or a throughput measurement. The [raw result and all
samples](deployment-convergence-20260925.json) are preserved verbatim (SHA-256
`e7a184dff6521a51e35064b75af9ed5d281c381d04132c9e53c39ca20a0536eb`).

The timer started immediately before the signed `operator deploy` call and
stopped when `host.Agent` completed `Runner.Apply` for the matching artifact
digest and generation. The test checked the matching accepted receipt after
that endpoint, outside the timed interval. Deployments were sequential, with
one outstanding operation and 35 distinct artifacts admitted before timing.
The caller used one GRU controller and one host, an embedded single-replica
file-backed JetStream in a temporary directory, NKey authentication, plaintext
R1 lab mode, and a 100 ms host reconciliation poll. `Runner.Apply` was an
in-memory observation: it did not start an OS process.

The frozen clean source was commit `c424bb4690c220b5832606c2947036c340cd96ac`
with tree `ed4f2f74d8121a59c9c47a52f222d1a9c9120ae4`; the measurement
source [deployment_convergence_measurement_test.go](../../internal/app/deployment_convergence_measurement_test.go)
had SHA-256 `16174d75e6b72469ad7c331ec9067033a78df24f6c1542b9a036c2a6ea01133d`.
The recorded runtime was Go 1.27.1 on Linux amd64, Intel Xeon E5-2660 v4
2.00 GHz, with `NumCPU=46` and `GOMAXPROCS=46`. The run notes record unrelated
background process CPU and load averages of `5.32 / 6.94 / 6.28`; controlled
build, test, staging, and VM/lab work was quiescent. The source manifest at
`/tmp/ts-orch-c424-qualification/meta/source-manifest.sha256` has SHA-256
`37bd01bc44931bc502ccb3cce6a412c8484a1ec47fe69c10d9fd0039417b55e4`.

The exact opt-in command in the measurement source is:

```sh
TS_ORCH_RUN_DEPLOYMENT_CONVERGENCE_MEASUREMENT=1 go test ./internal/app -run '^TestDeploymentConvergenceMeasurement$' -count=1 -v
```

The completed run passed once; its retained log is
`/tmp/ts-orch-c424-qualification/meta/deployment-convergence-measurement.log`
(SHA-256 `9db619578e559e10732d59a528746ffc6ec0700baa254ad055b4de69abaa8922`).
The summary uses the mean of the middle pair for p50, nearest-rank
`ceil(0.95 × 30)` for p95, and the largest sample for max. It excludes TLS,
native process startup, VM boot, production deployment and durable running
receipt latency. It provides no C# comparison or multi-host capacity claim.

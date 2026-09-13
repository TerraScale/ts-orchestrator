# Orchestrator observer commands

The current C# runtime does not ship a standalone dashboard binary. Its
read-only operator surface is exposed by the main executable and is intended
for an authenticated operator environment:

```bash
dotnet run --project src/TerraScale.Orchestrator -- operator status
dotnet run --project src/TerraScale.Orchestrator -- operator members
```

Both commands require a `tls://` NATS endpoint, a private controller NKey,
and complete mTLS files. They accept `--cell`, `--nats-url`, `--nkey-file`,
`--tls-ca-file`, `--tls-cert-file`, and `--tls-key-file`; the same values may
be supplied through the `TS_ORCH_*` environment variables. They return bounded
JSON observations and have no mutation routes.

For a local, provider-free view of admitted runtime roles, use:

```bash
dotnet run --project src/TerraScale.Orchestrator -- catalog
```

The former Go/Datastar dashboard and its file-backed projection are retained
only in the repository's historical source and evidence. They are not part of
the current .NET runtime or an installable operator command.

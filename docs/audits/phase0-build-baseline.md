# Phase 0 build baseline

Date: 2026-07-13

The repository baseline restores and builds with the pinned .NET SDK 10.0.301, and its two contract/architecture tests pass. Self-contained single-file publishing produces both `linux-x64` and `linux-arm64` ELF apphosts.

This is not release evidence. The current workspace is NixOS, and its x64 .NET apphost embeds a Nix-store ELF interpreter path:

```text
/nix/store/8kvxvr3pmsypxiypq4g8zy13glnfr7nx-glibc-2.42-67/lib/ld-linux-x86-64.so.2
```

The cross-published ARM64 apphost requests the conventional `/lib/ld-linux-aarch64.so.1`, but it has not run on ARM64. A production or recovery artifact must be built in the pinned ordinary-Linux hermetic toolchain, must request an approved loader compatible with the selected host image, and must pass real OCI A1 execution. A successful local `dotnet publish` cannot close `REQ-O005` or authorize a deployment.

Reproduce the baseline checks without starting a VM:

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --no-restore
dotnet test TerraScale.Orchestrator.slnx --no-build
dotnet publish src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj -c Release -r linux-x64 --no-restore
dotnet publish src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj -c Release -r linux-arm64 --no-restore
readelf -l src/TerraScale.Orchestrator/bin/Release/net10.0/linux-x64/publish/terrascale-orchestrator
readelf -l src/TerraScale.Orchestrator/bin/Release/net10.0/linux-arm64/publish/terrascale-orchestrator
```


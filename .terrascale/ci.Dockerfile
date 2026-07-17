FROM mcr.microsoft.com/dotnet/sdk@sha256:ed034a8bf0b24ded0cbbac07e17825d8e9ebfe21e308191d0f7421eaf5ad4664 AS source
WORKDIR /source
COPY . .
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    NUGET_XMLDOC_MODE=skip

FROM source AS restore
RUN dotnet restore TerraScale.Orchestrator.slnx --locked-mode --disable-parallel

FROM restore AS static-check
RUN dotnet run --project tools/TerraScale.Orchestrator.Tooling/TerraScale.Orchestrator.Tooling.csproj --no-restore -- test --repository-only

FROM scratch AS ci-static
COPY --from=static-check /source/tools/TerraScale.Orchestrator.Tooling/bin/Debug/net10.0/ /evidence/tooling/

FROM restore AS build
RUN dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore --maxcpucount:1 --nodeReuse:false -p:UseSharedCompilation=false

FROM scratch AS ci-build
COPY --from=build /source/src/TerraScale.Orchestrator/bin/Release/net10.0/ /evidence/orchestrator/
COPY --from=build /source/src/TerraScale.Orchestrator.CLI/bin/Release/net10.0/ /evidence/cli/

FROM build AS test
RUN dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/control-plane
RUN dotnet run --project tests/TerraScale.Orchestrator.ModelTests/TerraScale.Orchestrator.ModelTests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/model
RUN dotnet run --project tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/protocol
RUN dotnet run --project tests/TerraScale.Orchestrator.Scheduler.Tests/TerraScale.Orchestrator.Scheduler.Tests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/scheduler
RUN dotnet run --project tests/TerraScale.Orchestrator.Tests/TerraScale.Orchestrator.Tests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/orchestrator

FROM scratch AS ci-test
COPY --from=test /evidence/tests/ /evidence/tests/

FROM test AS artifact
RUN dotnet publish src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj -c Release -r linux-x64 --self-contained --no-restore -o /candidate/orchestrator/linux-x64
RUN dotnet publish src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj -c Release -r linux-arm64 --self-contained --no-restore -o /candidate/orchestrator/linux-arm64
RUN dotnet publish src/TerraScale.Orchestrator.CLI/TerraScale.Orchestrator.CLI.csproj -c Release -r linux-x64 --self-contained --no-restore -o /candidate/cli/linux-x64
RUN dotnet publish src/TerraScale.Orchestrator.CLI/TerraScale.Orchestrator.CLI.csproj -c Release -r linux-arm64 --self-contained --no-restore -o /candidate/cli/linux-arm64

FROM scratch AS ci-artifact
COPY --from=artifact /candidate/ /

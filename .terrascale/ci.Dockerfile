FROM mcr.microsoft.com/dotnet/sdk@sha256:b8cc28b501af233e51be59583a41bf3ebde7fc8656418a7dd305b90b21a7f3f9 AS source
WORKDIR /source
COPY . .
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    NUGET_XMLDOC_MODE=skip

FROM source AS restore
RUN dotnet restore TerraScale.Orchestrator.slnx --locked-mode --disable-parallel

FROM restore AS static-check
ARG TS_CI_JOB
ARG TS_CI_PLAN_DIGEST
RUN dotnet run --project tools/TerraScale.Orchestrator.Tooling/TerraScale.Orchestrator.Tooling.csproj --no-restore -- test --repository-only
RUN dotnet run --project tools/TerraScale.Orchestrator.Tooling/TerraScale.Orchestrator.Tooling.csproj --no-build --no-restore -- \
    ci-result-manifest --job "$TS_CI_JOB" --plan-digest "$TS_CI_PLAN_DIGEST" \
    --output /evidence/terrascale-ci-result-v2.json

FROM scratch AS ci-static
COPY --from=static-check /source/tools/TerraScale.Orchestrator.Tooling/bin/Debug/net11.0/ /evidence/tooling/
COPY --from=static-check /evidence/terrascale-ci-result-v2.json /

FROM restore AS build
ARG TS_CI_JOB
ARG TS_CI_PLAN_DIGEST
RUN dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore --maxcpucount:1 --nodeReuse:false -p:UseSharedCompilation=false
RUN dotnet run --project tools/TerraScale.Orchestrator.Tooling/TerraScale.Orchestrator.Tooling.csproj -c Release --no-build --no-restore -- \
    ci-result-manifest --job "$TS_CI_JOB" --plan-digest "$TS_CI_PLAN_DIGEST" \
    --output /evidence/terrascale-ci-result-v2.json

FROM scratch AS ci-build
COPY --from=build /source/src/TerraScale.Orchestrator/bin/Release/net11.0/ /evidence/orchestrator/
COPY --from=build /source/src/TerraScale.Orchestrator.CLI/bin/Release/net11.0/ /evidence/cli/
COPY --from=build /evidence/terrascale-ci-result-v2.json /

FROM build AS test
ARG TS_CI_JOB
ARG TS_CI_PLAN_DIGEST
RUN dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/control-plane --report-trx --report-trx-filename control-plane.trx
RUN dotnet run --project tests/TerraScale.Orchestrator.ModelTests/TerraScale.Orchestrator.ModelTests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/model --report-trx --report-trx-filename model.trx
RUN dotnet run --project tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/protocol --report-trx --report-trx-filename protocol.trx
RUN dotnet run --project tests/TerraScale.Orchestrator.Scheduler.Tests/TerraScale.Orchestrator.Scheduler.Tests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/scheduler --report-trx --report-trx-filename scheduler.trx
RUN dotnet run --project tests/TerraScale.Orchestrator.Tests/TerraScale.Orchestrator.Tests.csproj -c Release --no-build --no-restore -- --maximum-parallel-tests 4 --no-progress --results-directory /evidence/tests/orchestrator --report-trx --report-trx-filename orchestrator.trx
RUN dotnet run --project tools/TerraScale.Orchestrator.Tooling/TerraScale.Orchestrator.Tooling.csproj -c Release --no-build --no-restore -- \
    ci-result-manifest --job "$TS_CI_JOB" --plan-digest "$TS_CI_PLAN_DIGEST" \
    --trx /evidence/tests/control-plane/control-plane.trx \
    --trx /evidence/tests/model/model.trx \
    --trx /evidence/tests/protocol/protocol.trx \
    --trx /evidence/tests/scheduler/scheduler.trx \
    --trx /evidence/tests/orchestrator/orchestrator.trx \
    --output /evidence/terrascale-ci-result-v2.json

FROM scratch AS ci-test
COPY --from=test /evidence/tests/ /evidence/tests/
COPY --from=test /evidence/terrascale-ci-result-v2.json /

FROM test AS artifact
ARG TS_CI_JOB
ARG TS_CI_PLAN_DIGEST
RUN dotnet publish src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj -c Release -r linux-x64 --self-contained --no-restore -o /candidate/linux-x64/orchestrator
RUN dotnet publish src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj -c Release -r linux-arm64 --self-contained --no-restore -o /candidate/linux-arm64/orchestrator
RUN dotnet publish src/TerraScale.Orchestrator.CLI/TerraScale.Orchestrator.CLI.csproj -c Release -r linux-x64 --self-contained --no-restore -o /candidate/linux-x64/cli
RUN dotnet publish src/TerraScale.Orchestrator.CLI/TerraScale.Orchestrator.CLI.csproj -c Release -r linux-arm64 --self-contained --no-restore -o /candidate/linux-arm64/cli
RUN dotnet run --project tools/TerraScale.Orchestrator.Tooling/TerraScale.Orchestrator.Tooling.csproj -c Release --no-build --no-restore -- \
    ci-result-manifest --job "$TS_CI_JOB" --plan-digest "$TS_CI_PLAN_DIGEST" \
    --trx /evidence/tests/control-plane/control-plane.trx \
    --trx /evidence/tests/model/model.trx \
    --trx /evidence/tests/protocol/protocol.trx \
    --trx /evidence/tests/scheduler/scheduler.trx \
    --trx /evidence/tests/orchestrator/orchestrator.trx \
    --artifact "TerraScale/TerraScale.Orchestrator|LinuxX64|linux-x64|cli/terrascale-orchestrator-cli,orchestrator/terrascale-orchestrator" \
    --artifact "TerraScale/TerraScale.Orchestrator|LinuxArm64|linux-arm64|cli/terrascale-orchestrator-cli,orchestrator/terrascale-orchestrator" \
    --output /candidate/terrascale-ci-result-v2.json

FROM scratch AS ci-artifact
COPY --from=artifact /candidate/ /

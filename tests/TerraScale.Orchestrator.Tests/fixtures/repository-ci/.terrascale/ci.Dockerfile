FROM mcr.microsoft.com/dotnet/sdk@sha256:e1ffd2a92ae84c1291bc1b6887501f8af98e6331e7af6d4c8d37168c5e87a64c AS source
WORKDIR /source
COPY . .

FROM source AS restore
RUN dotnet restore TerraScale.Orchestrator.slnx

FROM restore AS static-check
RUN dotnet format TerraScale.Orchestrator.slnx --verify-no-changes --no-restore

FROM restore AS build
RUN dotnet build TerraScale.Orchestrator.slnx --configuration Release --no-restore --output /out/net11.0/

FROM build AS test
RUN dotnet test tests/TerraScale.Orchestrator.Tests/TerraScale.Orchestrator.Tests.csproj --configuration Release --no-build --results-directory /evidence/tests/
RUN dotnet test tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj --configuration Release --no-build --results-directory /evidence/tests/
RUN dotnet test tests/TerraScale.Orchestrator.ModelTests/TerraScale.Orchestrator.ModelTests.csproj --configuration Release --no-build --results-directory /evidence/tests/
RUN dotnet test tests/TerraScale.Orchestrator.Scheduler.Tests/TerraScale.Orchestrator.Scheduler.Tests.csproj --configuration Release --no-build --results-directory /evidence/tests/
RUN dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --configuration Release --no-build --results-directory /evidence/tests/

FROM build AS artifact
RUN mkdir -p /candidate/linux-x64 /candidate/linux-arm64
RUN cp -r /out/net11.0/ /candidate/linux-x64/
RUN cp -r /out/net11.0/ /candidate/linux-arm64/

FROM scratch AS ci-static
COPY --from=static-check /source/ /source/

FROM scratch AS ci-build
COPY --from=build /out/ /out/

FROM scratch AS ci-test
COPY --from=test /evidence/ /evidence/

FROM scratch AS ci-artifact
COPY --from=artifact /candidate/ /

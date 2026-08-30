FROM golang:1.27 AS source
WORKDIR /source
COPY . .

FROM source AS restore
RUN go mod download

FROM restore AS static-check
RUN test -z "$(gofmt -l .)"
RUN go vet ./...

FROM restore AS build
RUN mkdir -p /out
RUN go build -trimpath -o /out/terrascale-orchestrator ./cmd/orchestrator
RUN go build -trimpath -o /out/orchestrator-tooling ./tools/orchestrator-tooling

FROM restore AS test
RUN go test ./...
RUN go test -race ./...

FROM build AS artifact
RUN mkdir -p /candidate/linux-x64 /candidate/linux-arm64
RUN cp /out/terrascale-orchestrator /candidate/linux-x64/terrascale-orchestrator
RUN cp /out/orchestrator-tooling /candidate/linux-x64/orchestrator-tooling
RUN cp /out/terrascale-orchestrator /candidate/linux-arm64/terrascale-orchestrator
RUN cp /out/orchestrator-tooling /candidate/linux-arm64/orchestrator-tooling

FROM scratch AS ci-static
COPY --from=static-check /source/ /source/

FROM scratch AS ci-build
COPY --from=build /out/ /out/

FROM scratch AS ci-test
COPY --from=test /source/ /source/

FROM scratch AS ci-artifact
COPY --from=artifact /candidate/ /

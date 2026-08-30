FROM golang:1.27 AS source
WORKDIR /source
COPY . .

FROM source AS restore
RUN go mod download

FROM restore AS static-check
RUN test -z "$(gofmt -l .)"
RUN go vet ./...

FROM restore AS build
RUN mkdir -p /out/linux-x64 /out/linux-arm64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /out/linux-x64/terrascale-orchestrator ./cmd/orchestrator
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /out/linux-x64/orchestrator-tooling ./tools/orchestrator-tooling
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /out/linux-arm64/terrascale-orchestrator ./cmd/orchestrator
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /out/linux-arm64/orchestrator-tooling ./tools/orchestrator-tooling

FROM restore AS test
RUN go test ./...
RUN go test -race ./...

FROM build AS artifact
RUN mkdir -p /candidate/linux-x64 /candidate/linux-arm64
RUN cp /out/linux-x64/terrascale-orchestrator /candidate/linux-x64/terrascale-orchestrator
RUN cp /out/linux-x64/orchestrator-tooling /candidate/linux-x64/orchestrator-tooling
RUN cp /out/linux-arm64/terrascale-orchestrator /candidate/linux-arm64/terrascale-orchestrator
RUN cp /out/linux-arm64/orchestrator-tooling /candidate/linux-arm64/orchestrator-tooling

FROM scratch AS ci-static
COPY --from=static-check /source/ /source/

FROM scratch AS ci-build
COPY --from=build /out/ /out/

FROM scratch AS ci-test
COPY --from=test /source/ /source/

FROM scratch AS ci-artifact
COPY --from=artifact /candidate/ /

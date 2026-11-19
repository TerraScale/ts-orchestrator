package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/apppull"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

const opaqueCredential = "journeyOpaqueRegistryCredential938428"
const opaqueSignature = "journeyOpaqueRequestSignature328492"

func verifyRefusalLogs(ctx context.Context, source apppull.Source, image string) {
	directory, err := os.MkdirTemp("", "app-pull-refusals-")
	must(err)
	defer os.RemoveAll(directory)
	var journal bytes.Buffer
	logger, err := observability.NewLogger(&journal, observability.LogConfig{}, nil)
	must(err)
	previous := slog.Default()
	observability.ConfigureDefault(logger)
	defer observability.ConfigureDefault(previous)
	updater := apppull.Updater{Region: "stg", Source: source, Apply: mesh.Release(directory)}
	for range 3 {
		must(updater.Cycle(ctx))
	}
	expected := map[string]struct{ release, stage, reason string }{
		"terrabase":    {image, "release attestation", "authorized build provenance and selection required"},
		"ts-auth":      {"ts-auth:release", "release manifest", "HTTP 404"},
		"ts-dashboard": {"terrascale-dashboard:release", "release manifest", "HTTP 400"},
		"app-canary":   {"app-canary:release", "release manifest", "HTTP 404"},
	}
	counts := map[string]int{}
	for _, line := range bytes.Split(bytes.TrimSpace(journal.Bytes()), []byte("\n")) {
		start := bytes.IndexByte(line, '{')
		require(start >= 0, "refusal warning is not structured")
		var record map[string]string
		must(json.Unmarshal(line[start:], &record))
		want, ok := expected[record["service"]]
		require(ok && record["level"] == "WARN" && record["component"] == "apppull" && record["region"] == "stg" && record["msg"] == "app release refused", "refusal warning lacks its scope")
		require(record["release"] == want.release && record["stage"] == want.stage && record["reason"] == want.reason, "refusal warning lost its release, stage or safe reason")
		counts[record["service"]]++
	}
	for service := range expected {
		require(counts[service] == 1, "continuous refusal was not logged exactly once for "+service)
	}
	require(!strings.Contains(journal.String(), opaqueCredential) && !strings.Contains(journal.String(), opaqueSignature), "registry diagnostic leaked credentials to the logger")
	fmt.Println("ok: each app refusal is logged once at WARN with service, release, stage and a safe reason")
}

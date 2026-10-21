package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
)

func TestObserveFunctionWorkerAPIs(t *testing.T) {
	f := newObserveFixture(t)
	now := time.Now().UTC()
	view := globalview.NewView("gru", nil, func() time.Time { return now })
	handler := globalview.Handler(view)
	f.server.HandleAuthenticated("/v1/regions", handler)
	f.server.HandleAuthenticated("/v1/regions/", handler)
	rollup := globalview.Rollup{Version: globalview.Version, Cell: "gru", ObservedAt: now, FunctionsObservedAt: now,
		Functions: []globalview.FunctionObservation{{TenantID: "tenant-a", FunctionID: "echo", Digest: "sha256:module", State: "observed", ObservedAt: now,
			Snapshot: &functions.Snapshot{SchemaVersion: 1, ObservedAt: now, Succeeded: (1 << 60) + 1}}}}
	if !view.Accept(rollup) {
		t.Fatal("function observation rejected")
	}
	for _, format := range []string{"table", "json"} {
		for _, view := range []string{"functions", "function"} {
			flags := []string{"--format", format}
			if view == "function" {
				flags = append(flags, "--tenant", "tenant-a", "--function", "echo")
			}
			output, err := f.run(t, view, flags...)
			if err != nil || !strings.Contains(output, "1152921504606846977") || !strings.Contains(output, "sha256:module") {
				t.Fatalf("function %s lost exact source observation: %s %v", format, output, err)
			}
		}
	}
	rollup.ObservedAt = now.Add(time.Second)
	rollup.Functions[0].State = "unavailable"
	rollup.Functions[0].Snapshot = nil
	if !view.Accept(rollup) {
		t.Fatal("unavailable source observation rejected")
	}
	output, err := f.run(t, "functions")
	if err == nil || !strings.Contains(output, "unavailable") || !strings.Contains(output, "unknown") {
		t.Fatalf("function absence became zero: %s %v", output, err)
	}
	for _, flags := range [][]string{nil, {"--tenant", "tenant-a"}, {"--tenant", "../tenant", "--function", "echo"}} {
		if _, err := f.run(t, "function", flags...); err == nil {
			t.Fatalf("invalid function selector accepted: %v", flags)
		}
	}
}

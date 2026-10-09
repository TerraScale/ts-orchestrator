package app

import (
	"io"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func TestControllerRejectsInvalidStoreQuotaBeforeStartup(t *testing.T) {
	previousPresence := controllerBakedInputsPresent
	controllerBakedInputsPresent = func() (bool, error) { return false, nil }
	t.Cleanup(func() { controllerBakedInputsPresent = previousPresence })
	for _, test := range []struct {
		name          string
		artifactBytes int64
		storeBytes    int64
		want          string
	}{
		{name: "negative artifact limit", artifactBytes: -1, want: "artifact_store_max_bytes"},
		{name: "insufficient control headroom", artifactBytes: 3 << 30, storeBytes: 4 << 30, want: "control state"},
		{name: "legacy headroom omits metric archive", artifactBytes: 64 << 20, storeBytes: (64 + 1536) << 20, want: "control state"},
		{name: "metric archive headroom one byte short", artifactBytes: 64 << 20,
			storeBytes: (64+1536)<<20 + observability.HostMetricStreamBytes - 1, want: "control state"},
		// Exact headroom passes quota validation and reaches workload validation
		// before any broker starts.
		{name: "metric archive headroom exact", artifactBytes: 64 << 20,
			storeBytes: (64+1536)<<20 + observability.HostMetricStreamBytes, want: "explicit workload profiles"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := Config{NATS: natscell.Config{Lab: true, Embedded: &natscell.Embedded{StoreMaxBytes: test.storeBytes}},
				Controller: ControllerConfig{ArtifactStoreMaxBytes: test.artifactBytes}}
			if err := runController(t.Context(), cfg, io.Discard); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("startup error = %v, want %q", err, test.want)
			}
		})
	}
}

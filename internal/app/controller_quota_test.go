package app

import (
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

func TestControllerRejectsInvalidStoreQuotaBeforeStartup(t *testing.T) {
	admission := Config{NATS: natscell.Config{Cell: "gru"}}
	stubAuthenticatedController(t, &admission)
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
			cfg := Config{NATS: natscell.Config{Embedded: &natscell.Embedded{StoreMaxBytes: test.storeBytes}},
				Controller: ControllerConfig{ArtifactStoreMaxBytes: test.artifactBytes}}
			if err := runController(t.Context(), cfg, io.Discard); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("startup error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestControllerRejectsConfigTrustOutsideAcceptedImage(t *testing.T) {
	admission := Config{NATS: natscell.Config{Cell: "lab"}}
	stubAuthenticatedController(t, &admission)
	public, _ := testEd25519(t, t.TempDir(), "operator.key")
	cfg := Config{Version: ConfigVersion, NATS: natscell.Config{Cell: "lab", Instance: "controller",
		Embedded: &natscell.Embedded{StoreMaxBytes: 4 << 30}},
		Controller: ControllerConfig{ArtifactStoreMaxBytes: 64 << 20, SpecTrust: &SpecTrustConfig{},
			TrustedSigners: []TrustedSignerConfig{{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(public),
				Roles: []string{"terrabase"}, Environments: []string{"test"}}},
			Workloads: map[string]WorkloadProfile{"terrabase": {
				Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20},
			}}}}
	if err := runController(t.Context(), cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "image trust roots") {
		t.Fatalf("controller accepted config trust outside its image = %v", err)
	}
}

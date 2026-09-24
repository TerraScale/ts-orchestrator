package app

import (
	"io"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

func TestControllerRejectsInvalidStoreQuotaBeforeStartup(t *testing.T) {
	for _, test := range []struct {
		name          string
		artifactBytes int64
		storeBytes    int64
		want          string
	}{
		{name: "negative artifact limit", artifactBytes: -1, want: "artifact_store_max_bytes"},
		{name: "insufficient control headroom", artifactBytes: 3 << 30, storeBytes: 4 << 30, want: "control state"},
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

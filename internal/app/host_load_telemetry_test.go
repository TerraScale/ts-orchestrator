package app

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestHostTelemetryControlsAreRejectedOnLoadAndRenewal(t *testing.T) {
	t.Parallel()
	for _, version := range []int{0, ConfigVersion, ConfigVersion + 1} {
		for _, settings := range []string{
			`{"load_telemetry_seconds":0}`, `{"load_telemetry_seconds":15}`,
			`{"session_trace":false}`, `{"session_trace":true}`,
		} {
			path := filepath.Join(t.TempDir(), "host.json")
			wire := fmt.Sprintf(`{"version":%d,"host":%s}`, version, settings)
			if err := os.WriteFile(path, []byte(wire), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Errorf("host telemetry control accepted: %s", wire)
			}
			if _, err := readHostLocalOptions(path); err == nil {
				t.Errorf("credential renewal discarded a retired control: %s", wire)
			}
		}
	}
}

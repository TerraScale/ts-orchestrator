package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMembershipConfigurationFileNeedsNoActivationAndRejectsOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.json")
	write := func(controller string) {
		t.Helper()
		wire := fmt.Appendf(nil, `{"version":%d,"controller":{%s}}`, ConfigVersion, controller)
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("")
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("configuration without membership settings: %v", err)
	}
	for _, override := range []string{
		`"enabled":false`, `"replace":false`, `"route_to_seed":false`,
		`"interval_seconds":1`, `"offline_grace_seconds":1`, `"retry_backoff_seconds":1`,
		`"retirement_evidence_dir":"/tmp/retirement"`,
	} {
		write(`"membership":{` + override + `}`)
		if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "membership") {
			t.Fatalf("obsolete override %s: %v", override, err)
		}
	}
}

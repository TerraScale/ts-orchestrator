package atlas

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// publish refuses a section the controllers would refuse before it reads a
// secret or sends a request: no OCI configuration is needed to see it.
func TestPublishValidatesTheSectionFirst(t *testing.T) {
	data, err := os.ReadFile("../../deploy/oci-region/atlas-gru-1.json")
	if err != nil {
		t.Fatal(err)
	}
	plan := func(string) (map[string]any, error) { return map[string]any{"cell": "GRU"}, nil }
	for name, edit := range map[string]func(string) string{
		"plain http": func(s string) string { return strings.Replace(s, "https://atlas", "http://atlas", 1) },
		"another cell's key": func(s string) string {
			return strings.Replace(s, "gru-1-atlas-publish-key", "gru-1-ts-auth-master-key", 1)
		},
	} {
		section := filepath.Join(t.TempDir(), "atlas.json")
		if err := os.WriteFile(section, []byte(edit(string(data))), 0o600); err != nil {
			t.Fatal(err)
		}
		err := Run(t.Context(), []string{"publish", "--plan", "plan.json", "--section", section}, io.Discard, plan)
		if err == nil || !strings.HasPrefix(err.Error(), "atlas section: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

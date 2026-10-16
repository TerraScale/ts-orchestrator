package disasterrecovery

import (
	"encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestReplicateRefusesUnsafeSDKEnvironmentBeforeCloudAccess(t *testing.T) {
	config := Config{Version: 1, Namespace: "namespace",
		GRU: Region{CompartmentID: "ocid1.compartment.oc1..gru", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.gru", KeyID: "ocid1.key.oc1.sa-saopaulo-1.gru"},
		SFO: Region{CompartmentID: "ocid1.compartment.oc1..sfo", VaultID: "ocid1.vault.oc1.us-sanjose-1.sfo", KeyID: "ocid1.key.oc1.us-sanjose-1.sfo"}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "recovery.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			err := Run(t.Context(), []string{"replicate", "--config", path, "--apply"}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "unset "+name) {
				t.Fatalf("unsafe SDK environment reached cloud access: %v", err)
			}
		})
	}
}

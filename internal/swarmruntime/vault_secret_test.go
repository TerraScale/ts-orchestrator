package swarmruntime

import (
	"slices"
	"testing"
)

func TestSecretEnvironmentSplitsFilesAndFailsOnMissing(t *testing.T) {
	keys := []string{"TS_AUTH_MASTER_KEY", "TERRABASE_MANAGEMENT_CREDENTIAL_FILE"}
	files, env, err := secretEnvironment(keys, map[string]string{keys[0]: "plain", keys[1]: "file"})
	if err != nil || string(files["terrabase_management_credential_file"]) != "file" || len(files) != 1 ||
		!slices.Equal(env, []string{"TERRABASE_MANAGEMENT_CREDENTIAL_FILE=" + ContainerMaterialDirectory + "/terrabase_management_credential_file", "TS_AUTH_MASTER_KEY=plain"}) {
		t.Fatalf("files %d env %d: %v", len(files), len(env), err)
	}
	if _, _, err := secretEnvironment(keys, map[string]string{keys[0]: "plain"}); err == nil || err.Error() != "Vault secret for TERRABASE_MANAGEMENT_CREDENTIAL_FILE is missing or empty" {
		t.Fatalf("missing secret error %v", err)
	}
}

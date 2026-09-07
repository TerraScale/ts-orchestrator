package vmengineconfig

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

func TestAbsentDatabaseHostDoesNotInterpretInitialGrantConfiguration(t *testing.T) {
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "orchestrator", Arguments: "initial-gru-r1 --config @config", Configuration: `{"version":1,"regional":{"selected":true}}`}}}
	material := &Material{}
	if err := material.validateDatabaseManifest(manifest); err != nil {
		t.Fatalf("absent optional database host rejected initial grant: %v", err)
	}
	material.databaseFiles = map[string][]byte{"unexpected": []byte("invalid")}
	if err := material.validateDatabaseManifest(manifest); err == nil {
		t.Fatal("declared invalid database material accepted")
	}
}

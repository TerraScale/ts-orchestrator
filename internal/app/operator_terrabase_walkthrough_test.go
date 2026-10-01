package app

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestTerraBaseWalkthroughRejectsEarlierClientProfile(t *testing.T) {
	state, err := openDeployState(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	earlier := `{"version":1,"tenant_id":"t","database_id":"d","shard_id":1,"collections":[{"collection_id":"c",` +
		`"schema_generation":1,"schema_digest":"x","fields":[{"id":1,"name":"title"}]}],"members":[]}`
	if err := state.createFile(deployClientFile, []byte(earlier)); err != nil {
		t.Fatal(err)
	}
	err = runTerraBaseWalkthrough(t.Context(), []string{"--state", state.directory}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "client profile version 1 is unsupported") {
		t.Fatalf("earlier client profile error = %v", err)
	}
}

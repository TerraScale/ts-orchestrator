package vmengineconfig_test

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"strings"
	"terrascale.tech/orchestrator/internal/testengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
	"testing"
)

func TestInitialHostCarriesEveryBackupCredential(t *testing.T) {
	declaration, path := testengineconfig.DatabaseDeclaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
	for i := range declaration.Hosts {
		declaration.Hosts[i].DatabaseHost = nil
		declaration.Hosts[i].EngineControl = nil
	}
	// Initial-host backup material is independent of later database-host admission.
	destination := declaration.Databases[0].Backup.Destinations[0]
	declaration.Databases[0].Backup.Destinations = append(declaration.Databases[0].Backup.Destinations, destination)
	raw, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	materials, err := vmengineconfig.Load(path, strings.Repeat("a", 64), "1.0.0", bindings)
	if err != nil {
		t.Fatal(err)
	}
	for _, material := range materials {
		defer material.Clear()
		files := material.BackupFiles()
		if len(files) != 4 {
			t.Fatalf("backup files = %d", len(files))
		}
		if len(material.DatabaseFiles()) != 0 {
			t.Fatal("initial host gained database admission credentials")
		}
		for path, data := range files {
			if !vmengineconfig.IsBackupPath(path) || len(data) == 0 {
				t.Fatal("invalid backup material")
			}
			copy := bytes.Clone(data)
			clear(data)
			if !bytes.Equal(material.BackupFiles()[path], copy) {
				t.Fatal("mutable credential alias")
			}
		}
	}
}

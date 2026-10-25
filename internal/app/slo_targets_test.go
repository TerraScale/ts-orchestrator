package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestSLOTargetFileRetiresTargetsAndIsPubliclyReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "discovery", "targets.json")
	targets := []swarmruntime.SLOTarget{{Targets: []string{"127.0.0.1:41001"}, Labels: map[string]string{"service": "ts-auth", "instance": "task-one", "region": "gru"}}}
	if err := writeSLOTargets(path, targets); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []swarmruntime.SLOTarget
	if err := json.Unmarshal(data, &decoded); err != nil || len(decoded) != 1 || decoded[0].Labels["instance"] != "task-one" {
		t.Fatalf("discovery file = %s: %v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("Prometheus cannot read discovery file: %v %v", info, err)
	}
	if err := writeSLOTargets(path, []swarmruntime.SLOTarget{}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil || string(data) != "[]" {
		t.Fatalf("retired targets remain: %s %v", data, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files remain: %v %v", entries, err)
	}
}

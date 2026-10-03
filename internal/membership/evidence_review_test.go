package membership

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A present but unusable evidence file is ignored (never trusted) and
// reported once, so the operator learns why the slot still waits.
func TestFileEvidenceLogsAnIgnoredFileOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "controller-b.retirement"), []byte("not an envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	source := NewFileEvidence(dir, testTopology().Slots, slog.New(slog.NewTextHandler(&logs, nil)))
	for range 3 {
		evidence, err := source.Evidence(t.Context())
		if err != nil || len(evidence) != 0 {
			t.Fatalf("evidence = %+v, %v", evidence, err)
		}
	}
	if count := strings.Count(logs.String(), "retirement evidence file ignored"); count != 1 {
		t.Fatalf("ignored file reported %d times:\n%s", count, logs.String())
	}
	if !strings.Contains(logs.String(), "slot=controller-b") {
		t.Fatalf("log lacks the slot:\n%s", logs.String())
	}
}

func TestDefaultEvidenceDirIsUnderTheControllerStateDirectory(t *testing.T) {
	if !strings.HasPrefix(DefaultRetirementEvidenceDir, "/var/lib/terrascale-orchestrator-controller/") {
		t.Fatalf("evidence dir %s is not writable by the controller unit", DefaultRetirementEvidenceDir)
	}
}

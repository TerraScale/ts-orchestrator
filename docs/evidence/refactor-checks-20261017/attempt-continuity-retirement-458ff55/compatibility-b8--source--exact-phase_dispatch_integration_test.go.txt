package attempt_test

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/attempt"
)

func TestRetiredContinuityPhaseThroughAttemptRun(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "attempt.json")
	wire, err := json.Marshal(map[string]string{
		"workdir":       filepath.Join(dir, "work"),
		"deployment_id": "0000000000F9PR1WNVDTEXS31Z",
		"prefix":        "bootstrap/a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, wire, 0600); err != nil {
		t.Fatal(err)
	}

	var diagnostics bytes.Buffer
	code := attempt.Run(t.Context(), []string{"--config", config, "continuity"}, io.Discard, &diagnostics)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; diagnostics = %q", code, diagnostics.String())
	}
	if got, want := diagnostics.String(), "unknown attempt phase \"continuity\"\n"; got != want {
		t.Fatalf("diagnostics = %q, want %q", got, want)
	}
}

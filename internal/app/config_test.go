package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigPreservesSignedBytesAndRejectsUnknownMembers(t *testing.T) {
	load := func(body string) (Config, error) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(path)
	}
	wire := `{"version": 2, "nats": {"cell": "gru"}, "controller": {"candidate_id": "ctl-1"}}`
	cfg, err := load(wire)
	if err != nil {
		t.Fatalf("version-2 config: %v", err)
	}
	if cfg.Version != ConfigVersion || cfg.NATS.Cell != "gru" || cfg.Controller.CandidateID != "ctl-1" {
		t.Fatalf("version-2 config decoded as %+v", cfg)
	}
	// Admission digests the signed bytes themselves, including whitespace.
	if signed, err := cfg.signedWire(); err != nil || string(signed) != wire {
		t.Fatalf("signed wire = %q, %v; want the loaded bytes", signed, err)
	}
	for name, body := range map[string]string{

		"unknown member": `{"version": 2, "nats": {"cell": "gru", "added": true}}`,
	} {
		if _, err := load(body); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

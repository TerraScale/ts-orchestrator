package app

import (
	"errors"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// Adoption swaps the signers before it publishes the spec, and a spec whose
// signers are refused is not adopted, so no consumer sees one generation's
// spec with another's signers.
func TestCellSpecAdoptionSwapsSignersFirst(t *testing.T) {
	cfg := Config{NATS: natscell.Config{Cell: "gru"}}
	newAcceptedSpecTrust(t, &cfg)
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	var seen []uint64
	refuse := false
	registry.replaceSigners = func([]TrustedSignerConfig) error {
		seen = append(seen, registry.current.Generation)
		if refuse {
			return errors.New("refused")
		}
		return nil
	}
	spec := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 8,
		Signers: []TrustedSignerConfig{{Actor: "ops"}}}
	registry.adopt(spec, 1)
	if registry.current.Generation != 1 || !slices.Equal(seen, []uint64{0}) {
		t.Fatalf("adopted generation %d, signers swapped at %v", registry.current.Generation, seen)
	}
	refuse = true
	spec.Generation = 2
	registry.adopt(spec, 2)
	if registry.current.Generation != 1 {
		t.Fatalf("a spec whose signers were refused was adopted: generation %d", registry.current.Generation)
	}
}

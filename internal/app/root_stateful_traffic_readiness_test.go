//go:build linux

package app

import (
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestRootTrafficBundleRejectsEveryChangedSignedMaterialField(t *testing.T) {
	signed := release.ContainerBundle{Claim: []byte(`{"claim":"original"}`), Index: []byte("index"), Sequence: []byte("sequence"),
		Delegation: []byte(`{"delegation":"original"}`), Migration: []byte(`{"migration":"original"}`)}
	if err := rootTrafficBundleMatches(signed, signed); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"claim", "index", "sequence", "delegation", "migration"} {
		t.Run(field, func(t *testing.T) {
			changed := signed
			switch field {
			case "claim":
				changed.Claim = []byte(`{"claim":"replacement"}`)
			case "index":
				changed.Index = []byte("replacement")
			case "sequence":
				changed.Sequence = []byte("replacement")
			case "delegation":
				changed.Delegation = []byte(`{"delegation":"replacement"}`)
			case "migration":
				changed.Migration = []byte(`{"migration":"replacement"}`)
			}
			if err := rootTrafficBundleMatches(signed, changed); !errors.Is(err, rootoci.ErrUnauthorized) {
				t.Fatalf("changed %s accepted: %v", field, err)
			}
		})
	}
}

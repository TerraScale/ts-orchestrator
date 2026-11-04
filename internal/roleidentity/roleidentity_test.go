package roleidentity_test

import (
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/roleidentity"
)

func TestRoleScopePublishesObservationsInOwnCell(t *testing.T) {
	if !slices.Contains(roleidentity.Scope("key").Template.Pub.Allow, "ts.orch.v1.{{tag(cell)}}.obs.{{tag(obs)}}") {
		t.Fatal("role scope does not let members publish their cell's observation leaves")
	}
}

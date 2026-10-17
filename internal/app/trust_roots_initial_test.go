package app

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

func TestInitialRootPublicationRejectsAbsentCreationBeforeBrokerAccess(t *testing.T) {
	registry := &rootRegistry{}
	if err := registry.publishInitial(t.Context(), new(natscell.Runtime), region.VerifiedBrokerCreation{}); err == nil {
		t.Fatal("an unproven original broker authorized initial root publication")
	}
}

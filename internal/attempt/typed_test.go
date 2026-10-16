package attempt

import (
	"bytes"
	"encoding/json/v2"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// A candidate built as a map is written in the signing command's canonical
// field order, which sign-founder-plan compares byte for byte.
func TestTypedWritesTheCanonicalFieldOrder(t *testing.T) {
	a := &Attempt{}
	plan := typed(a, Object{"seedSlot": "controller-a", "cell": "GRU", "schemaVersion": 1, "deploymentId": "d", "environment": "canary"}, &bootstrap.FounderPlan{})
	if a.err != nil {
		t.Fatal(a.err)
	}
	written, err := json.Marshal(plan, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := protocol.EncodeJSON(*plan)
	if err != nil || !bytes.Equal(written, canonical) || !bytes.HasPrefix(written, []byte(`{"schemaVersion":1,"deploymentId":"d","cell":"GRU"`)) {
		t.Fatalf("written %s, canonical %s, %v", written, canonical, err)
	}
	selection := typed(a, Object{"manifests": []any{Object{"sha256": "s", "slot": "controller-a"}}, "generation": 1, "schemaVersion": 1}, &bootstrapstart.FounderSelection{})
	written, _ = json.Marshal(selection, json.Deterministic(true))
	if canonical, err := protocol.EncodeJSON(*selection); a.err != nil || err != nil || !bytes.Equal(written, canonical) {
		t.Fatalf("selection %s, canonical %s, %v %v", written, canonical, a.err, err)
	}
	if typed(a, Object{"unknown": 1}, &bootstrap.FounderPlan{}); a.err == nil {
		t.Fatal("an unknown member was dropped instead of refused")
	}
}

package rootcapacity

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/region"
)

func TestCompletedPoolOwnerRequiresOriginalPositiveCompletion(t *testing.T) {
	now := time.Now().UTC()
	positive := &region.PoolWireRecord{AcceptedAt: now, WorkCompletedAt: now}
	for _, test := range []struct {
		name, operation string
		record          region.FoundationRecord
	}{
		{"birth", "birth", region.FoundationRecord{PoolChildren: map[string]region.PoolChildRecord{"birth": {
			PoolID: "pool", ReadyAt: now, Attach: positive,
		}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !completedPoolOperation(test.record, "pool", test.operation) || completedPoolOperation(test.record, "another-pool", test.operation) ||
				completedPoolOperation(test.record, "pool", "unresolved") {
				t.Fatal("completed owner recovery changed original operation or pool")
			}
		})
	}
	unresolved := region.FoundationRecord{PoolChildren: map[string]region.PoolChildRecord{"birth": {
		PoolID: "pool", Stage: region.PoolChildAttachUnknown, Attach: &region.PoolWireRecord{EverUnknown: true},
	}}}
	if completedPoolOperation(unresolved, "pool", "birth") {
		t.Fatal("unknown attach outcome was inferred complete")
	}
}

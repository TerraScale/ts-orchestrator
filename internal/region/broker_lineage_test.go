package region

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

func TestBrokerOriginAndTrustFloorCannotBeReset(t *testing.T) {
	now := time.Now().UTC()
	before := &RuntimeLineageRecord{Broker: &RuntimeBrokerCreation{OperationID: "original", ExpiresAt: now.Add(time.Second)},
		TrustFloor: &RuntimeTrustFloor{OperationID: "original", RootSequence: 3, RootHead: "head", RootChainSHA256: "chain", SpecGeneration: 4, SpecSHA256: "spec", UpdatedAt: now}}
	for _, change := range []func(*RuntimeLineageRecord){
		func(record *RuntimeLineageRecord) { record.Broker = nil },
		func(record *RuntimeLineageRecord) { record.Broker.ExpiresAt = now.Add(time.Hour) },
		func(record *RuntimeLineageRecord) { record.TrustFloor = nil },
		func(record *RuntimeLineageRecord) { record.TrustFloor.RootSequence-- },
		func(record *RuntimeLineageRecord) { record.TrustFloor.SpecSHA256 = "same-generation-replacement" },
	} {
		after := *before
		after.Broker, after.TrustFloor = new(*before.Broker), new(*before.TrustFloor)
		change(&after)
		if err := retainBrokerLineage(before, &after); err == nil {
			t.Fatal("protected broker origin or current signed floor was reset")
		}
	}
	if err := (VerifiedBrokerCreation{}).Revalidate(t.Context()); err == nil {
		t.Fatal("zero broker proof authorized original publication")
	}
	if _, _, err := (*BrokerCreationPermit)(nil).Start(t.Context(), natscell.Config{}); err == nil {
		t.Fatal("missing protected permit started an original broker")
	}
}

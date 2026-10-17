package region

import (
	"testing"
	"time"
)

func TestRuntimeLineageCannotBeReinitialized(t *testing.T) {
	original := &RuntimeLineageRecord{Version: 1, FoundationOperationID: "original-foundation"}
	if err := retainRuntimeLineage(nil, original); err == nil {
		t.Fatal("uncertified existing foundation acquired runtime genesis")
	}
	if err := retainRuntimeLineage(original, nil); err == nil {
		t.Fatal("protected runtime genesis was removed")
	}
	changed := *original
	changed.FoundationOperationID = "replacement-foundation"
	if err := retainRuntimeLineage(original, &changed); err == nil {
		t.Fatal("runtime genesis was rebound to a new foundation")
	}
	changed = *original
	changed.Creation = &RuntimeCreation{OperationID: "first-creation"}
	if err := retainRuntimeLineage(original, &changed); err != nil {
		t.Fatal(err)
	}
	if err := retainRuntimeLineage(&changed, original); err == nil {
		t.Fatal("ambiguous started creation was reset")
	}
	completed := changed
	creation := *changed.Creation
	creation.Genesis = &RuntimeSwarmGenesis{ClusterID: "actual-original-cluster"}
	completed.Creation = &creation
	if err := retainRuntimeLineage(&changed, &completed); err != nil {
		t.Fatal(err)
	}
	if err := retainRuntimeLineage(&completed, &changed); err == nil {
		t.Fatal("completed genesis was reset to an uncommitted creation")
	}
	replacement := completed
	replacementCreation := creation
	replacementCreation.Genesis = &RuntimeSwarmGenesis{ClusterID: "different-empty-cluster"}
	replacement.Creation = &replacementCreation
	if err := retainRuntimeLineage(&completed, &replacement); err == nil {
		t.Fatal("deleted cluster was replaced by a different empty cluster")
	}
	if err := retainRuntimeLineage(&completed, &completed); err != nil {
		t.Fatal(err)
	}
	extended := changed
	extendedCreation := *changed.Creation
	extendedCreation.ExpiresAt = time.Now().Add(time.Hour)
	extended.Creation = &extendedCreation
	if err := retainRuntimeLineage(&changed, &extended); err == nil {
		t.Fatal("new observation renewed the original creation lifetime")
	}
}

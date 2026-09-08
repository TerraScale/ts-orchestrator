package databaseadmission

import (
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
)

func TestUnusedHostRemovalFreezesAuthoritativeEmptyScope(t *testing.T) {
	_, _, current, key := successorFixture(t)
	var signed placementtransition.Signed
	if err := json.Unmarshal(current.PlacementTargets[0].AcceptedProof, &signed); err != nil {
		t.Fatal(err)
	}
	var proof placementtransition.Proof
	if err := json.Unmarshal(signed.Payload, &proof); err != nil {
		t.Fatal(err)
	}
	state := newJournalState()
	value := UnusedHostRemoval{OperationID: "remove-unused/placement", ScopeID: proof.Request.ScopeID, MemberIdentity: "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAV/01ARZ3NDEKTSV4RRFFQ69G5FB3", ResourceID: "instance-unused", Generation: 3, InventoryDigest: PlacementInventoryDigest(nil), Head: signed}
	if err := beginUnusedHostRemoval(&state, value, nil, key); err != nil {
		t.Fatal(err)
	}
	if err := beginUnusedHostRemoval(&state, value, nil, key); err != nil {
		t.Fatal("retry", err)
	}
	record := journalFixture(t)
	if _, err := saveRecord(&state, ScopeKey(record.Request), 0, record); !errors.Is(err, ErrConflict) {
		t.Fatal("create crossed no-data removal fence", err)
	}
	if state.PlacementRelocation != value.OperationID || state.CompletedRelocations[value.OperationID] == "" || len(state.CurrentPlacements) != 0 {
		t.Fatal("empty proof fabricated a database or released fence")
	}
	request := DeleteRequest{Environment: record.Request.Environment, TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, DatabaseID: record.DatabaseID, OperationID: "delete"}
	if _, err := beginDeletion(&state, request, time.Now(), time.Time{}); !errors.Is(err, ErrConflict) {
		t.Fatal("deletion crossed no-data removal fence", err)
	}
	changed := value
	changed.Generation++
	if err := beginUnusedHostRemoval(&state, changed, nil, key); !errors.Is(err, ErrConflict) {
		t.Fatal("incarnation rebound", err)
	}
}
func TestUnusedHostRemovalRejectsServingSeatAndOmittedSnapshot(t *testing.T) {
	state, old, current, key := successorFixture(t)
	var signed placementtransition.Signed
	_ = json.Unmarshal(current.PlacementTargets[0].AcceptedProof, &signed)
	var proof placementtransition.Proof
	_ = json.Unmarshal(signed.Payload, &proof)
	value := UnusedHostRemoval{OperationID: "remove-unused/placement", ScopeID: proof.Request.ScopeID, MemberIdentity: proof.Request.Members[0].Identity, ResourceID: "instance", Generation: 1, InventoryDigest: PlacementInventoryDigest([]Record{old}), Head: signed}
	if err := beginUnusedHostRemoval(&state, value, []Record{old}, key); err == nil {
		t.Fatal("serving seat classified unused")
	}
	value.MemberIdentity += "-unused"
	value.InventoryDigest = PlacementInventoryDigest(nil)
	if err := beginUnusedHostRemoval(&state, value, nil, key); !errors.Is(err, ErrConflict) {
		t.Fatal("nonempty inventory omitted", err)
	}
}

package databaseadmission

import (
	"encoding/json/v2"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

func TestPoolAuthorityRequestUsesForwardingEnvelope(t *testing.T) {
	request := PoolAuthorityRequest{
		ServerIdentity: "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAD/01ARZ3NDEKTSV4RRFFQ69G5FAE",
		MemberID:       "01ARZ3NDEKTSV4RRFFQ69G5FAE",
		Work: PoolWork{Request: writebudget.PoolRefillRequest{
			RefillOperationID: "refill-1",
			HolderID:          "01ARZ3NDEKTSV4RRFFQ69G5FAE",
		}},
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PoolAuthorityRequest
	if err := json.Unmarshal(data, &decoded, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if decoded.ServerIdentity != request.ServerIdentity || decoded.MemberID != request.MemberID || decoded.Work.Request.RefillOperationID != request.Work.Request.RefillOperationID {
		t.Fatalf("forwarded request changed: got %#v", decoded)
	}
	var legacy PoolWork
	if err := json.Unmarshal(data, &legacy, json.RejectUnknownMembers(true)); err == nil {
		t.Fatal("authority envelope was accepted as an unwrapped pool work message")
	}
}

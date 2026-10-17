package rootoci

import (
	"encoding/json/jsontext"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestNodeOperationAcceptsOnlyOriginalOperationSelector(t *testing.T) {
	id := entityid.New()
	service := new(Service)
	for _, test := range []struct {
		payload string
		valid   bool
	}{
		{`{"operation_id":"` + id + `"}`, true},
		{`{"operation_id":"` + id + `","instance_id":"ocid1.instance.other"}`, false},
		{`{"operation_id":"` + id + `","step":"reboot"}`, false},
		{`{"operation_id":"` + id + `","ocpus":4}`, false},
		{`{"operation_id":"invalid"}`, false},
	} {
		if got := service.validRequest(wireRequest{Operation: OperationReconcileNodeOperation, Payload: jsontext.Value(test.payload)}); got != test.valid {
			t.Errorf("validRequest(%s) = %t; want %t", test.payload, got, test.valid)
		}
	}
	if OperationReconcileNodeOperation.ReadOnly() || OperationReconcileNodeOperation.observationOnly() {
		t.Fatal("node compute acquired the observation-only admission exemption")
	}
}

func TestNodeOperationReceiptRetainsExactOriginalOutcome(t *testing.T) {
	now := time.Now().UTC()
	request := NodeOperationRequest{OperationID: entityid.New()}
	original := NodeOperationReceipt{OperationID: request.OperationID, RequestSHA256: strings.Repeat("a", 64),
		InstanceID: "ocid1.instance.original", Phase: "complete", ActedAt: now.Add(-time.Second),
		ObservedAt: now, ExpiresAt: now.Add(time.Second)}
	if !validNodeOperationReceipt(original, request, now) {
		t.Fatal("valid original receipt rejected")
	}
	for _, change := range []func(*NodeOperationReceipt){
		func(r *NodeOperationReceipt) { r.OperationID = entityid.New() },
		func(r *NodeOperationReceipt) { r.RequestSHA256 = "" },
		func(r *NodeOperationReceipt) { r.ExpiresAt = now },
		func(r *NodeOperationReceipt) { r.ActedAt = time.Time{} },
		func(r *NodeOperationReceipt) { r.InstanceID = "ocid1.instance.other\n" },
		func(r *NodeOperationReceipt) { r.Phase = "reboot" },
	} {
		receipt := original
		change(&receipt)
		if validNodeOperationReceipt(receipt, request, now) {
			t.Errorf("invalid receipt accepted: %+v", receipt)
		}
	}
	for _, phase := range []string{"pending", "ambiguous"} {
		receipt := original
		receipt.Phase, receipt.ActedAt = phase, time.Time{}
		if !validNodeOperationReceipt(receipt, request, now) {
			t.Errorf("protected %s outcome rejected", phase)
		}
	}
}

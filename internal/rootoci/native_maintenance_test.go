package rootoci

import (
	"encoding/json/jsontext"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestOrchestratorMaintenanceAcceptsOnlyUnitSelector(t *testing.T) {
	service := new(Service)
	for _, test := range []struct {
		payload string
		valid   bool
	}{
		{`{"unit":"ctrl-a"}`, true},
		{`{"unit":"ctrl-a","instance_id":"ocid1.instance.other"}`, false},
		{`{"unit":"ctrl-a","operation_id":"other"}`, false},
		{`{"unit":"ctrl-a","digest":"other"}`, false},
		{`{"unit":"ctrl-a","phase":"restart"}`, false},
		{`{"unit":"ctrl-a","expires_at":"2099-01-01T00:00:00Z"}`, false},
		{`{"unit":"ctrl-a","unit":"ctrl-b"}`, false},
		{`{"unit":"../ctrl-a"}`, false},
		{`{"unit":""}`, false},
	} {
		if got := service.validRequest(wireRequest{Operation: OperationReconcileOrchestratorMaintenance, Payload: jsontext.Value(test.payload)}); got != test.valid {
			t.Errorf("validRequest(%s) = %t; want %t", test.payload, got, test.valid)
		}
	}
	if OperationReconcileOrchestratorMaintenance.ReadOnly() || OperationReconcileOrchestratorMaintenance.observationOnly() {
		t.Fatal("maintenance acquired an observation-only admission exemption")
	}
}

func TestOrchestratorMaintenanceReceiptRejectsImpossibleProgress(t *testing.T) {
	now := time.Now().UTC()
	request := OrchestratorMaintenanceRequest{Unit: "ctrl-a"}
	original := OrchestratorMaintenanceReceipt{Unit: request.Unit, OperationID: entityid.New(), SourceSHA256: strings.Repeat("a", 64),
		InstanceID: "ocid1.instance.original", FromDigest: strings.Repeat("b", 64), ToDigest: strings.Repeat("c", 64), Phase: "complete",
		DrainedAt: now.Add(-2 * time.Second), DispatchedAt: now.Add(-time.Second), ObservedAt: now, ExpiresAt: now.Add(time.Second)}
	if !validOrchestratorMaintenanceReceipt(original, request, now) {
		t.Fatal("valid original receipt rejected")
	}
	for _, test := range []struct {
		name   string
		change func(*OrchestratorMaintenanceReceipt)
	}{
		{"unit-mismatch", func(r *OrchestratorMaintenanceReceipt) { r.Unit = "ctrl-b" }},
		{"invalid-operation", func(r *OrchestratorMaintenanceReceipt) { r.OperationID = "invalid" }},
		{"missing-source", func(r *OrchestratorMaintenanceReceipt) { r.SourceSHA256 = "" }},
		{"noncanonical-source", func(r *OrchestratorMaintenanceReceipt) { r.SourceSHA256 = strings.Repeat("A", 64) }},
		{"invalid-from", func(r *OrchestratorMaintenanceReceipt) { r.FromDigest = "invalid" }},
		{"invalid-to", func(r *OrchestratorMaintenanceReceipt) { r.ToDigest = "invalid" }},
		{"same-binary", func(r *OrchestratorMaintenanceReceipt) { r.ToDigest = r.FromDigest }},
		{"missing-instance", func(r *OrchestratorMaintenanceReceipt) { r.InstanceID = "" }},
		{"empty-instance-suffix", func(r *OrchestratorMaintenanceReceipt) { r.InstanceID = "ocid1.instance." }},
		{"invalid-instance", func(r *OrchestratorMaintenanceReceipt) { r.InstanceID += "\n" }},
		{"unknown-phase", func(r *OrchestratorMaintenanceReceipt) { r.Phase = "restart" }},
		{"missing-drain", func(r *OrchestratorMaintenanceReceipt) { r.DrainedAt = time.Time{} }},
		{"missing-dispatch", func(r *OrchestratorMaintenanceReceipt) { r.DispatchedAt = time.Time{} }},
		{"dispatch-before-drain", func(r *OrchestratorMaintenanceReceipt) { r.DispatchedAt = r.DrainedAt.Add(-time.Second) }},
		{"future-drain", func(r *OrchestratorMaintenanceReceipt) { r.DrainedAt = now.Add(time.Second) }},
		{"future-dispatch", func(r *OrchestratorMaintenanceReceipt) { r.DispatchedAt = now.Add(time.Second) }},
		{"prehistoric-drain", func(r *OrchestratorMaintenanceReceipt) { r.DrainedAt = time.Unix(-1, 0) }},
		{"missing-observation", func(r *OrchestratorMaintenanceReceipt) { r.ObservedAt = time.Time{} }},
		{"future-observation", func(r *OrchestratorMaintenanceReceipt) { r.ObservedAt = now.Add(time.Second) }},
		{"expired", func(r *OrchestratorMaintenanceReceipt) { r.ExpiresAt = now }},
		{"missing-expiry", func(r *OrchestratorMaintenanceReceipt) { r.ExpiresAt = time.Time{} }},
		{"pending-after-drain", func(r *OrchestratorMaintenanceReceipt) { r.Phase = "pending" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt := original
			test.change(&receipt)
			if validOrchestratorMaintenanceReceipt(receipt, request, now) {
				t.Fatalf("invalid progress accepted: %+v", receipt)
			}
		})
	}
	for _, test := range []struct {
		phase           string
		drain, dispatch bool
	}{
		{"pending", false, false},
		{"drained", true, false},
		{"drained", true, true},
		{"ambiguous", false, false},
		{"ambiguous", true, false},
		{"ambiguous", true, true},
		{"complete", true, true},
	} {
		receipt := original
		receipt.Phase = test.phase
		if !test.drain {
			receipt.DrainedAt = time.Time{}
		}
		if !test.dispatch {
			receipt.DispatchedAt = time.Time{}
		}
		if !validOrchestratorMaintenanceReceipt(receipt, request, now) {
			t.Errorf("coherent %s progress rejected: %+v", test.phase, receipt)
		}
	}
}

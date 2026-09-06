package cloudflare

import (
	"context"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

func deletionFixture() databaseadmission.Deletion {
	cutoff := time.Unix(1800000000, 500000000).UTC()
	request := databaseadmission.DeleteRequest{Environment: "production", TenantID: "org", ProjectID: "project", DatabaseID: "db", OperationID: "delete-1"}
	d := databaseadmission.Deletion{Request: request, Cutoff: cutoff, State: "edge_pending"}
	for _, database := range []string{"db", "child"} {
		for _, region := range []string{"GRU", "FRA"} {
			stop := databaseadmission.DeletionStop{Environment: request.Environment, OrganizationID: request.TenantID, ProjectID: request.ProjectID, DatabaseID: database, OperationID: request.OperationID, Region: region, Cutoff: cutoff}
			d.Targets = append(d.Targets, databaseadmission.DeletionTarget{Stop: stop, Receipt: &databaseadmission.DeletionReceipt{DeletionStop: stop, AccessRevoked: true, UsageStopped: true}})
		}
	}
	return d
}

func TestDeletionRevocationsCoverDescendantsAndRoundExpiryUp(t *testing.T) {
	d := deletionFixture()
	entries, expires, err := deletionRevocations(d)
	if err != nil || len(entries) != 2 || !expires.Equal(d.Cutoff.Add(1200*time.Second)) {
		t.Fatalf("entries=%v expires=%v err=%v", entries, expires, err)
	}
	for _, entry := range entries {
		if entry.ExpiresAt != 1800001201 {
			t.Fatalf("expiry rounded down: %d", entry.ExpiresAt)
		}
	}
	if entries[0].Scope == entries[1].Scope {
		t.Fatal("descendant scope lost")
	}
}

func TestDeletionRevocationsRejectIncompleteEvidence(t *testing.T) {
	tests := map[string]func(*databaseadmission.Deletion){
		"missing receipt":  func(d *databaseadmission.Deletion) { d.Targets[0].Receipt = nil },
		"usage running":    func(d *databaseadmission.Deletion) { d.Targets[0].Receipt.UsageStopped = false },
		"access running":   func(d *databaseadmission.Deletion) { d.Targets[0].Receipt.AccessRevoked = false },
		"wrong cutoff":     func(d *databaseadmission.Deletion) { d.Targets[0].Receipt.Cutoff = d.Cutoff.Add(time.Second) },
		"wrong identity":   func(d *databaseadmission.Deletion) { d.Targets[0].Receipt.OrganizationID = "other" },
		"wrong operation":  func(d *databaseadmission.Deletion) { d.Targets[0].Receipt.OperationID = "other" },
		"wrong region":     func(d *databaseadmission.Deletion) { d.Targets[0].Receipt.Region = "SFO" },
		"duplicate target": func(d *databaseadmission.Deletion) { d.Targets = append(d.Targets, d.Targets[0]) },
		"preparing":        func(d *databaseadmission.Deletion) { d.State = "preparing" },
		"no root":          func(d *databaseadmission.Deletion) { d.Request.DatabaseID = "other" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			d := deletionFixture()
			mutate(&d)
			if _, _, err := deletionRevocations(d); err == nil {
				t.Fatal("accepted incomplete evidence")
			}
		})
	}
}

type deletionLookupJournal struct {
	databaseadmission.DeletionJournal
	records []databaseadmission.Deletion
}

func (j deletionLookupJournal) ListDeletions(context.Context) ([]databaseadmission.Deletion, error) {
	return j.records, nil
}

func TestDeletionRevokerDoesNotTrustCallerEvidence(t *testing.T) {
	d := deletionFixture()
	for _, records := range [][]databaseadmission.Deletion{nil, {d, d}} {
		r, err := NewCapabilityDeletionRevoker(&SnippetCapabilityStore{}, deletionLookupJournal{records: records}, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := r.RevokeDeletion(t.Context(), d)
		if err == nil || receipt.AccessRevoked {
			t.Fatal("caller evidence authorized revocation")
		}
	}
	authoritative := deletionFixture()
	authoritative.Targets[0].Receipt = nil
	r, _ := NewCapabilityDeletionRevoker(&SnippetCapabilityStore{}, deletionLookupJournal{records: []databaseadmission.Deletion{authoritative}}, time.Now)
	if _, err := r.RevokeDeletion(t.Context(), d); err == nil {
		t.Fatal("ignored authoritative incomplete receipt")
	}
}

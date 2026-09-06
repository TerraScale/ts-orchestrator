package databaseadmission

import (
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func journalFixture(t *testing.T) Record {
	t.Helper()
	r := Record{Request: Request{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAY", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAZ", Name: "example", OperationID: "create-example", Regions: []string{"GRU"}}, DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FB0", KeyVersion: "01ARZ3NDEKTSV4RRFFQ69G5FB1", State: "accepted"}
	members := []string{"01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAX"}
	proposal, err := proto.Marshal(&pb.PlacementStageRequest{Proposal: &pb.PlacementProposal{Environment: r.Request.Environment, Cluster: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Generation: 1, Epoch: 1, Regions: []*pb.PlacementRegionSeats{{Region: "GRU", Members: members}}, Assignments: []*pb.PlacementDatabaseAssignment{{Tenant: r.Request.TenantID, Project: r.Request.ProjectID, Database: r.DatabaseID, Region: "GRU", WriterMember: members[0], FollowerMember: members[1]}}}})
	if err != nil {
		t.Fatal(err)
	}
	provision := keylease.ProvisionTarget{Binding: keylease.Binding{Environment: r.Request.Environment, TenantID: r.Request.TenantID, ProjectID: r.Request.ProjectID, DatabaseID: r.DatabaseID, KeyVersion: r.KeyVersion, Region: "GRU", Purpose: "data"}, CryptoEndpoint: "https://unit-crypto.kms.sa-saopaulo-1.oraclecloud.com", KEKID: "ocid1.key.oc1.sa-saopaulo-1.unit", KEKVersionID: "ocid1.keyversion.oc1.sa-saopaulo-1.unit", LeaseSeconds: 60, NotAfter: time.Now().UTC().Add(time.Hour)}
	for _, member := range members {
		r.Targets = append(r.Targets, Target{ServerIdentity: "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAV/" + member, MemberID: member, Region: "GRU", Provision: provision, Proposal: proposal})
	}
	if err := ValidateRecord(r); err != nil {
		t.Fatal(err)
	}
	return r
}
func journalWrapped(r Record) []keylease.Entry {
	p := r.Targets[0].Provision
	return []keylease.Entry{{Binding: p.Binding, CryptoEndpoint: p.CryptoEndpoint, KEKID: p.KEKID, KEKVersionID: p.KEKVersionID, Ciphertext: "wrapped-ciphertext", LeaseSeconds: p.LeaseSeconds, NotAfter: p.NotAfter}}
}
func TestJournalAtomicNameAndOperationOwnership(t *testing.T) {
	journal := NewMemoryJournal()
	record := journalFixture(t)
	key := ScopeKey(record.Request)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, err := journal.Save(t.Context(), key, 0, record); results <- err })
	}
	wg.Wait()
	close(results)
	successes := 0
	conflicts := 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrJournalConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	loaded, found, err := journal.Load(t.Context(), key)
	if err != nil || !found || loaded.Revision != 1 {
		t.Fatalf("load=%+v found=%v err=%v", loaded, found, err)
	}
	loaded.Request.OperationID = "replacement"
	if _, err := journal.Save(t.Context(), key, 1, loaded); !errors.Is(err, ErrConflict) {
		t.Fatalf("name replaced: %v", err)
	}
	other := record
	other.Request.Name = "other"
	if _, err := journal.Save(t.Context(), ScopeKey(other.Request), 0, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("operation rebound: %v", err)
	}
	loaded.Targets[0].Proposal[0] ^= 0xff
	reread, _, _ := journal.Load(t.Context(), key)
	if reread.Targets[0].Proposal[0] == loaded.Targets[0].Proposal[0] {
		t.Fatal("read exposed journal memory")
	}
}
func TestJournalCiphertextAndProgressAreMonotonic(t *testing.T) {
	journal := NewMemoryJournal()
	r := journalFixture(t)
	key := ScopeKey(r.Request)
	r.Revision, _ = journal.Save(t.Context(), key, 0, r)
	r.State = "keys_provisioned"
	r.Wrapped = journalWrapped(r)
	var err error
	r.Revision, err = journal.Save(t.Context(), key, r.Revision, r)
	if err != nil {
		t.Fatal(err)
	}
	original := r.Wrapped[0].Ciphertext
	r.Wrapped[0].Ciphertext = "different"
	if _, err := journal.Save(t.Context(), key, r.Revision, r); !errors.Is(err, ErrConflict) {
		t.Fatalf("ciphertext replaced: %v", err)
	}
	r.Wrapped[0].Ciphertext = original
	r.Targets[0].Installed = true
	r.Revision, err = journal.Save(t.Context(), key, r.Revision, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Targets[0].Installed = false
	if _, err := journal.Save(t.Context(), key, r.Revision, r); !errors.Is(err, ErrConflict) {
		t.Fatalf("progress regressed: %v", err)
	}
	r.Targets[0].Installed = true
	r.State = "placement_pending"
	if _, err := journal.Save(t.Context(), key, r.Revision, r); err == nil {
		t.Fatal("uninstalled/unproposed targets became pending")
	}
	r.State = "ready"
	if _, err := journal.Save(t.Context(), key, r.Revision, r); err == nil {
		t.Fatal("journal fabricated readiness")
	}
}

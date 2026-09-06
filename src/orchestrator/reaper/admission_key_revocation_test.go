package reaper

import (
	"google.golang.org/protobuf/proto"
	"reflect"
	"slices"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"testing"
	"time"
)

func revocationRecordFixture(t *testing.T) databaseadmission.Record {
	t.Helper()
	r := databaseadmission.Record{CreatedAt: time.Now().UTC(), Request: databaseadmission.Request{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAY", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAZ", Name: "example", OperationID: "create-example", Regions: []string{"GRU"}}, DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FB0", KeyVersion: "01ARZ3NDEKTSV4RRFFQ69G5FB1", State: "accepted"}
	members := []string{"01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAX"}
	proposal, err := proto.Marshal(&pb.PlacementControlServiceStageRequest{Proposal: &pb.PlacementProposal{Environment: r.Request.Environment, Cluster: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Generation: 1, Epoch: 1, Regions: []*pb.PlacementRegionSeats{{Region: "GRU", Members: members}}, Assignments: []*pb.PlacementDatabaseAssignment{{Tenant: r.Request.TenantID, Project: r.Request.ProjectID, Database: r.DatabaseID, Region: "GRU", WriterMember: members[0], FollowerMember: members[1]}}}})
	if err != nil {
		t.Fatal(err)
	}
	provision := keylease.ProvisionTarget{Binding: keylease.Binding{Environment: r.Request.Environment, TenantID: r.Request.TenantID, ProjectID: r.Request.ProjectID, DatabaseID: r.DatabaseID, KeyVersion: r.KeyVersion, Region: "GRU", Purpose: "data"}, CryptoEndpoint: "https://unit-crypto.kms.sa-saopaulo-1.oraclecloud.com", KEKID: "ocid1.key.oc1.sa-saopaulo-1.unit", KEKVersionID: "ocid1.keyversion.oc1.sa-saopaulo-1.unit", LeaseSeconds: 60, NotAfter: time.Now().UTC().Add(time.Hour)}
	for _, member := range members {
		r.Targets = append(r.Targets, databaseadmission.Target{ServerIdentity: "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAV/" + member, MemberID: member, Region: "GRU", Provision: provision, Proposal: proposal})
	}
	for _, target := range r.Targets {
		r.PlacementTargets = append(r.PlacementTargets, databaseadmission.PlacementTarget{ServerIdentity: target.ServerIdentity, MemberID: target.MemberID, Region: target.Region, Proposal: target.Proposal})
	}
	if err := databaseadmission.ValidateRecord(r); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestAdmissionKeyRecordRetainsUnacknowledgedDeliveryIntent(t *testing.T) {
	record := revocationRecordFixture(t)
	record.Revision = 7
	got, err := admissionKeyRecord([]databaseadmission.Record{record}, record.Request.Environment, record.DatabaseID)
	if err != nil || !reflect.DeepEqual(got, record) || len(got.Targets) != 2 {
		t.Fatal("delivery intent lost", err)
	}
	for _, target := range got.Targets {
		if target.Installed {
			t.Fatal("fixture should represent lost acknowledgments")
		}
	}
}
func TestAdmissionKeyRecordRefusesAmbiguousOrInvalidInventory(t *testing.T) {
	record := revocationRecordFixture(t)
	for _, kind := range []string{"duplicate-record", "duplicate-target", "wrong-environment", "missing", "foreign-target", "empty-targets"} {
		t.Run(kind, func(t *testing.T) {
			bad := record
			bad.Targets = slices.Clone(record.Targets)
			records := []databaseadmission.Record{bad}
			switch kind {
			case "duplicate-record":
				records = append(records, record)
			case "duplicate-target":
				records[0].Targets[1] = records[0].Targets[0]
			case "wrong-environment":
				records[0].Request.Environment = "staging"
			case "missing":
				records = nil
			case "foreign-target":
				records[0].Targets[0].ServerIdentity = "spiffe://terrascale.tech/staging/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAV/01ARZ3NDEKTSV4RRFFQ69G5FAW"
			case "empty-targets":
				records[0].Targets = nil
			}
			if _, err := admissionKeyRecord(records, record.Request.Environment, record.DatabaseID); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
}

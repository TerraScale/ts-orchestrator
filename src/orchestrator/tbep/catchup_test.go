package tbep

import (
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"testing"
	"time"
)

func TestCatchUpRequiresCompleteFreshDistinctScopes(t *testing.T) {
	good := func() *pb.MaintenanceServiceCatchUpStatusResponse {
		return &pb.MaintenanceServiceCatchUpStatusResponse{Complete: true, AssignmentRevision: "assignment-1", ObservedAtUnixMs: uint64(time.Now().UnixMilli()), Databases: []*pb.DatabaseCatchUpStatus{{Tenant: "tenant", Project: "project", Database: "database", SourceSequence: 4, RegionalMeasured: true, RegionalSequence: 4, CausalMeasured: true, CausalCaughtUp: true, BackupMeasured: true, BackupSourceSequence: 3, BackupProtectedSequence: 3, BackupCaughtUp: true}}}
	}
	if err := validateCatchUp(good()); err != nil {
		t.Fatal(err)
	}
	if err := validateCatchUp(&pb.MaintenanceServiceCatchUpStatusResponse{}); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*pb.MaintenanceServiceCatchUpStatusResponse){
		func(s *pb.MaintenanceServiceCatchUpStatusResponse) { s.Complete = false },
		func(s *pb.MaintenanceServiceCatchUpStatusResponse) { s.Databases = nil },
		func(s *pb.MaintenanceServiceCatchUpStatusResponse) { s.ObservedAtUnixMs = 1 },
		func(s *pb.MaintenanceServiceCatchUpStatusResponse) {
			s.ObservedAtUnixMs = uint64(time.Now().Add(time.Minute).UnixMilli())
		},
		func(s *pb.MaintenanceServiceCatchUpStatusResponse) { s.Databases = append(s.Databases, s.Databases[0]) },
		func(s *pb.MaintenanceServiceCatchUpStatusResponse) { s.Databases[0].RegionalMeasured = false },
		func(s *pb.MaintenanceServiceCatchUpStatusResponse) { s.Databases[0].CausalMeasured = false },
		func(s *pb.MaintenanceServiceCatchUpStatusResponse) { s.Databases[0].BackupMeasured = false },
		func(s *pb.MaintenanceServiceCatchUpStatusResponse) { s.Databases[0].BackupProtectedSequence = 2 },
	} {
		s := good()
		alter(s)
		if err := validateCatchUp(s); err == nil {
			t.Fatalf("invalid catchup accepted %+v", s)
		}
	}
}

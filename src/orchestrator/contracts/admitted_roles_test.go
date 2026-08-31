package contracts

import "testing"

func TestAdmittedRolesContainOnlyLaunchWorkloads(t *testing.T) {
	tests := []struct {
		name string
		kind RoleKind
		role AdmittedRole
	}{
		{"Dashboard", RoleKindDashboard, NewDashboardRole()},
		{"DatabaseAPI", RoleKindDatabaseAPI, NewDatabaseAPIRole()},
		{"TerraBaseMember", RoleKindTerraBaseMember, NewTerraBaseMemberRole()},
		{"Nats", RoleKindNats, NewNatsRole()},
		{"Autoscaler", RoleKindAutoscaler, NewAutoscalerRole()},
		{"JournalWriter", RoleKindJournalWriter, NewJournalWriterRole()},
	}

	for _, test := range tests {
		if !roleKindIsDefined(test.kind) {
			t.Fatalf("role kind %v is not defined", test.kind)
		}
		if test.role.Kind() != test.kind {
			t.Fatalf("%s kind = %v, want %v", test.name, test.role.Kind(), test.kind)
		}
		if test.role.Projection() != test.name {
			t.Fatalf("%s projection = %q", test.name, test.role.Projection())
		}
	}

	if roleKindIsDefined(RoleKindUnspecified) || roleKindIsDefined(RoleKindJournalWriter+1) {
		t.Fatal("the workload role vocabulary must stay closed")
	}
}

// This file ports tests/TerraScale.Orchestrator.Tests/
// AdmittedRoleCatalogTests.cs.
package runtime

import (
	"testing"
)

func TestCatalogIsClosedCompleteAndUsesProductionRuntimeDefaults(t *testing.T) {
	all := AdmittedRoleCatalog.All()
	if len(all) != len(AllAdmittedRoles) {
		t.Fatalf("catalog must cover every role: %d vs %d", len(all), len(AllAdmittedRoles))
	}
	distinct := map[AdmittedRole]bool{}
	for _, descriptor := range all {
		distinct[descriptor.Role] = true
	}
	if len(distinct) != len(all) {
		t.Fatal("catalog roles must be distinct")
	}
	assertDriver := func(role AdmittedRole, driver RuntimeDriver) {
		t.Helper()
		descriptor, err := AdmittedRoleCatalog.Get(role)
		if err != nil {
			t.Fatalf("get %v: %v", role, err)
		}
		if descriptor.DefaultDriver != driver {
			t.Fatalf("role %v default driver mismatch: %v", role, descriptor.DefaultDriver)
		}
	}
	assertDriver(AdmittedRoleTerraBaseMember, RuntimeDriverNativeSystemd)
	assertDriver(AdmittedRoleCustomerDashboard, RuntimeDriverOciContainer)
	assertDriver(AdmittedRoleGrafana, RuntimeDriverOciContainer)
	assertReplicas := func(role AdmittedRole, minimumReplicas int) {
		t.Helper()
		descriptor, err := AdmittedRoleCatalog.Get(role)
		if err != nil {
			t.Fatalf("get %v: %v", role, err)
		}
		if descriptor.MinimumReplicas != minimumReplicas {
			t.Fatalf("role %v minimum replicas mismatch: %d", role, descriptor.MinimumReplicas)
		}
	}
	assertReplicas(AdmittedRoleControlNatsServer, 3)
	assertReplicas(AdmittedRoleProductNatsServer, 3)
	assertDriver(AdmittedRoleJournalWriter, RuntimeDriverNativeSystemd)
	journalWriter, err := AdmittedRoleCatalog.Get(AdmittedRoleJournalWriter)
	if err != nil {
		t.Fatalf("get journal writer: %v", err)
	}
	if !journalWriter.OnePerHost {
		t.Fatal("journal writer must be one per host")
	}
}

func TestDriverAdmissionRejectsAnUnapprovedRuntime(t *testing.T) {
	if _, err := AdmittedRoleCatalog.Admit(AdmittedRoleGrafana, RuntimeDriverNativeSystemd); err == nil {
		t.Fatal("Grafana is not admitted on systemd")
	}
	if _, err := AdmittedRoleCatalog.Admit(AdmittedRoleOrchestrator, RuntimeDriverOciContainer); err == nil {
		t.Fatal("Orchestrator is not admitted on OCI")
	}
	descriptor, err := AdmittedRoleCatalog.Admit(AdmittedRoleTerraBaseMember, RuntimeDriverOciContainer)
	if err != nil {
		t.Fatalf("TerraBaseMember on OCI: %v", err)
	}
	if descriptor.Role != AdmittedRoleTerraBaseMember {
		t.Fatal("admitted descriptor must carry the requested role")
	}
}

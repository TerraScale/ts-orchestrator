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
	for index, role := range AllAdmittedRoles {
		if all[index].Role != role {
			t.Fatalf("catalog role %d = %v, want %v", index, all[index].Role, role)
		}
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
	assertDriver(AdmittedRoleNats, RuntimeDriverNativeSystemd)
	assertDriver(AdmittedRoleAutoscaler, RuntimeDriverNativeSystemd)
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
	assertReplicas(AdmittedRoleNats, 3)
	assertReplicas(AdmittedRoleAutoscaler, 3)
	assertReplicas(AdmittedRoleTerraBaseMember, 2)
	assertDriver(AdmittedRoleJournalWriter, RuntimeDriverNativeSystemd)
	journalWriter, err := AdmittedRoleCatalog.Get(AdmittedRoleJournalWriter)
	if err != nil {
		t.Fatalf("get journal writer: %v", err)
	}
	if !journalWriter.OnePerHost {
		t.Fatal("journal writer must be one per host")
	}
}

func TestPersistedRoleValuesRemainCompatibleWithV1Checkpoints(t *testing.T) {
	want := map[AdmittedRole]int{
		AdmittedRoleDashboard:       0,
		AdmittedRoleTerraBaseMember: 1,
		AdmittedRoleAutoscaler:      2,
		AdmittedRoleNats:            3,
		AdmittedRoleJournalWriter:   16,
		AdmittedRoleDatabaseAPI:     17,
	}
	for role, value := range want {
		if int(role) != value {
			t.Fatalf("%v persisted value = %d, want %d", role, role, value)
		}
	}

	for value := 4; value <= 15; value++ {
		if AdmittedRole(value).defined() {
			t.Fatalf("retired v1 role value %d acquired a new meaning", value)
		}
	}
}

func TestDriverAdmissionRejectsAnUnapprovedRuntime(t *testing.T) {
	// D-69: no containers. The OCI driver is retired for every role (I-3
	// replaces it with native systemd delivery).
	for _, role := range AllAdmittedRoles {
		if _, err := AdmittedRoleCatalog.Admit(role, RuntimeDriverOciContainer); err == nil {
			t.Fatalf("%v must not be admitted on OCI", role)
		}
	}
	// Retired v1 container roles are refused on every driver.
	for _, role := range []AdmittedRole{AdmittedRoleDashboard, AdmittedRoleDatabaseAPI} {
		if _, err := AdmittedRoleCatalog.Admit(role, RuntimeDriverNativeSystemd); err == nil {
			t.Fatalf("retired role %v was admitted on systemd", role)
		}
		if _, err := AdmittedRoleCatalog.Admit(role, RuntimeDriverOciContainer); err == nil {
			t.Fatalf("retired role %v was admitted on OCI", role)
		}
	}
	descriptor, err := AdmittedRoleCatalog.Admit(AdmittedRoleTerraBaseMember, RuntimeDriverNativeSystemd)
	if err != nil {
		t.Fatalf("TerraBaseMember on systemd: %v", err)
	}
	if descriptor.Role != AdmittedRoleTerraBaseMember {
		t.Fatal("admitted descriptor must carry the requested role")
	}
}

func TestRuntimeRoleParserAdmitsOnlyTheLaunchCatalog(t *testing.T) {
	want := map[string]AdmittedRole{
		"terrabase-member": AdmittedRoleTerraBaseMember,
		"nats":             AdmittedRoleNats,
		"autoscaler":       AdmittedRoleAutoscaler,
		"journal-writer":   AdmittedRoleJournalWriter,
	}
	for input, role := range want {
		got, err := HostRuntimeCli.ParseRole(input)
		if err != nil || got != role {
			t.Fatalf("ParseRole(%q) = %v, %v; want %v", input, got, err, role)
		}
	}
	for _, removed := range []string{
		"dashboard", "database-api",
		"platform", "mcp", "grafana", "loki", "vpn-coordination-relay",
		"control-nats-server", "product-nats-server", "ci-runner",
	} {
		if _, err := HostRuntimeCli.ParseRole(removed); err == nil {
			t.Fatalf("removed role %q was admitted", removed)
		}
	}
}

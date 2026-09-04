package runtime

import (
	"errors"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const hostRuntimePlanDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mustRuntimeAllocationId(t *testing.T, value string) RuntimeAllocationId {
	t.Helper()
	id, err := NewRuntimeAllocationId(value)
	if err != nil {
		t.Fatalf("allocation id: %v", err)
	}
	return id
}

func mustArtifactDigest(t *testing.T, value string) ArtifactDigest {
	t.Helper()
	digest, err := NewArtifactDigest(value)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return digest
}

func containsString(t *testing.T, values []string, expected string) {
	t.Helper()
	for _, value := range values {
		if value == expected {
			return
		}
	}
	t.Fatalf("expected %q among %v", expected, values)
}

func TestNativePlanUsesOnlyCatalogDerivedPathsAndHardenedSystemdProperties(t *testing.T) {
	plan, err := NewHostRuntimePlan(
		AdmittedRoleTerraBaseMember,
		RuntimeDriverNativeSystemd,
		mustRuntimeAllocationId(t, "gru-terrabase-1"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	if plan.Systemd == nil {
		t.Fatal("native plan must carry a systemd plan")
	}
	if plan.Oci != nil {
		t.Fatal("native plan must not carry an OCI plan")
	}
	if plan.Systemd.UnitName != "terrascale-gru-terrabase-1.service" {
		t.Fatalf("unexpected unit name %q", plan.Systemd.UnitName)
	}
	executable := "/opt/terrascale/artifacts/terrabase-server/sha256-" + hostRuntimePlanDigest + "/terrabase-server"
	if plan.Systemd.Executable != executable {
		t.Fatalf("unexpected executable %q", plan.Systemd.Executable)
	}
	containsString(t, plan.Systemd.Properties, "NoNewPrivileges=yes")
	containsString(t, plan.Systemd.Properties, "DynamicUser=yes")
	containsString(t, plan.Systemd.Properties, "PrivateDevices=yes")
	containsString(t, plan.Systemd.Properties, "ProtectSystem=strict")
	containsString(t, plan.Systemd.Properties, "ProtectHome=yes")
	containsString(t, plan.Systemd.Properties, "ProtectKernelTunables=yes")
	containsString(t, plan.Systemd.Properties, "ProtectKernelModules=yes")
	containsString(t, plan.Systemd.Properties, "ProtectControlGroups=yes")
	containsString(t, plan.Systemd.Properties, "LockPersonality=yes")
	containsString(t, plan.Systemd.Properties, "MemoryDenyWriteExecute=yes")
	containsString(t, plan.Systemd.Properties, "RestrictSUIDSGID=yes")
	containsString(t, plan.Systemd.Properties, "CapabilityBoundingSet=")
	containsString(t, plan.Systemd.Properties, "SystemCallFilter=@system-service")
	containsString(t, plan.Systemd.Properties, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6")
	containsString(t, plan.Systemd.Properties, "ReadWritePaths=/var/lib/terrascale-gru-terrabase-1")
	containsString(t, plan.Systemd.Properties, "EnvironmentFile=-/var/lib/terrascale-gru-terrabase-1/environment")
	containsString(t, plan.Systemd.Properties,
		"LoadCredentialEncrypted=workload:/var/lib/terrascale-gru-terrabase-1/credentials/workload.cred")
	containsString(t, plan.Systemd.Properties, "MemoryMax=8589934592")
	containsString(t, plan.Systemd.Properties, "MemoryHigh=7730941132")
	containsString(t, plan.Systemd.Properties, "MemorySwapMax=0")
	containsString(t, plan.Systemd.Properties, "CPUWeight=1000")
	containsString(t, plan.Systemd.Properties, "IOWeight=1000")
	containsString(t, plan.Systemd.Properties, "Nice=0")
}

func TestRuntimePlanRejectsRetiredRolesAndContainerDriversAtConstruction(t *testing.T) {
	cases := []struct {
		name   string
		role   AdmittedRole
		driver RuntimeDriver
	}{
		{name: "retired dashboard role", role: AdmittedRoleDashboard, driver: RuntimeDriverNativeSystemd},
		{name: "retired database api role", role: AdmittedRoleDatabaseAPI, driver: RuntimeDriverNativeSystemd},
		{name: "container driver", role: AdmittedRoleTerraBaseMember, driver: RuntimeDriverOciContainer},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewHostRuntimePlan(
				testCase.role,
				testCase.driver,
				mustRuntimeAllocationId(t, "gru-retired-plan"),
				mustArtifactDigest(t, hostRuntimePlanDigest),
				HostArchitectureArm64,
				nil); err == nil {
				t.Fatal("retired role or container driver must be rejected at construction")
			}
		})
	}
}

func TestRuntimeLimitsCanBeReducedWithinTheClosedRolePolicy(t *testing.T) {
	requested := RuntimeResourceLimits{
		MemoryMaxBytes: 512 * 1024 * 1024, TasksMax: 128,
		CpuQuotaPercent: 100, CpuWeight: 100, IoWeight: 100, Nice: 5,
	}

	plan, err := NewHostRuntimePlan(
		AdmittedRoleAutoscaler,
		RuntimeDriverNativeSystemd,
		mustRuntimeAllocationId(t, "gru-autoscaler-limited"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		&requested)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	if plan.SchemaVersion != 2 {
		t.Fatalf("unexpected schema version %d", plan.SchemaVersion)
	}
	if plan.Resources != requested {
		t.Fatalf("resources mismatch: %+v", plan.Resources)
	}
	if plan.Resources.MemoryHighBytes() != 483_183_820 {
		t.Fatalf("unexpected high watermark %d", plan.Resources.MemoryHighBytes())
	}
}

func TestRuntimeLimitsCannotEscapeTheClosedRolePolicy(t *testing.T) {
	excessive := RuntimeResourceLimits{
		MemoryMaxBytes: 2 * 1024 * 1024 * 1024, TasksMax: 128,
		CpuQuotaPercent: 100, CpuWeight: 100, IoWeight: 100, Nice: 5,
	}
	_, err := NewHostRuntimePlan(
		AdmittedRoleAutoscaler,
		RuntimeDriverNativeSystemd,
		mustRuntimeAllocationId(t, "gru-autoscaler-excessive"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		&excessive)
	var rangeError *errs.ArgumentOutOfRangeError
	if !errors.As(err, &rangeError) {
		t.Fatalf("expected errs.ArgumentOutOfRangeError, got %v", err)
	}
}

func TestRuntimeCliAcceptsExplicitNativeLimits(t *testing.T) {
	plan, err := HostRuntimeCli.ParsePlan([]string{
		"plan", "--role", "autoscaler", "--allocation", "gru-autoscaler-cli",
		"--digest", hostRuntimePlanDigest,
		"--memory-max-bytes", "536870912", "--tasks-max", "128",
		"--cpu-quota-percent", "100", "--cpu-weight", "100", "--io-weight", "100", "--nice", "5",
	})
	if err != nil {
		t.Fatalf("parse plan: %v", err)
	}
	expected := RuntimeResourceLimits{
		MemoryMaxBytes: 536870912, TasksMax: 128,
		CpuQuotaPercent: 100, CpuWeight: 100, IoWeight: 100, Nice: 5,
	}
	if plan.Resources != expected {
		t.Fatalf("resources mismatch: %+v", plan.Resources)
	}
}

func TestRuntimeInputsCannotInjectPathsImagesOrUnknownRoles(t *testing.T) {
	if _, err := NewRuntimeAllocationId("../../root"); err == nil {
		t.Fatal("path injection must be rejected")
	}
	if _, err := NewArtifactDigest("latest"); err == nil {
		t.Fatal("floating tag must be rejected")
	}
	if _, err := HostRuntimeCli.ParseRole("arbitrary-container"); err == nil {
		t.Fatal("unknown role must be rejected")
	}
	_, blankRoleErr := HostRuntimeCli.ParseRole("")
	if blankRoleErr == nil || !strings.Contains(blankRoleErr.Error(), "Unknown or unadmitted role") {
		t.Fatalf("role errors must keep the exact message: %v", blankRoleErr)
	}
}

func TestHostRuntimePlanRevalidatesValueObjectFieldsAtPlanBoundary(t *testing.T) {
	validAllocation := mustRuntimeAllocationId(t, "gru-orchestrator-1")
	validDigest := mustArtifactDigest(t, hostRuntimePlanDigest)
	cases := []struct {
		name         string
		allocation   RuntimeAllocationId
		digest       ArtifactDigest
		architecture HostArchitecture
	}{
		{"path traversal allocation", RuntimeAllocationId{Value: "../../root"}, validDigest, HostArchitectureArm64},
		{"empty allocation", RuntimeAllocationId{}, validDigest, HostArchitectureArm64},
		{"floating digest", validAllocation, ArtifactDigest{Value: "latest"}, HostArchitectureArm64},
		{"empty digest", validAllocation, ArtifactDigest{}, HostArchitectureArm64},
		{"unknown architecture", validAllocation, validDigest, HostArchitecture(99)},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewHostRuntimePlan(
				AdmittedRoleAutoscaler,
				RuntimeDriverNativeSystemd,
				testCase.allocation,
				testCase.digest,
				testCase.architecture,
				nil); err == nil {
				t.Fatal("malformed value-object fields must be rejected before path derivation")
			}
		})
	}
}

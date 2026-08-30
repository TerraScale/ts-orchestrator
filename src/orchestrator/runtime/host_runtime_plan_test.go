// This file ports tests/TerraScale.Orchestrator.Tests/HostRuntimePlanTests.cs.
package runtime

import (
	"errors"
	"strings"
	"testing"
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
	containsString(t, plan.Systemd.Properties, "ProtectSystem=strict")
	containsString(t, plan.Systemd.Properties, "ProtectControlGroups=yes")
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

func TestOciPlanIsDigestPinnedRootlessAndCapabilityFree(t *testing.T) {
	plan, err := NewHostRuntimePlan(
		AdmittedRoleCustomerDashboard,
		RuntimeDriverOciContainer,
		mustRuntimeAllocationId(t, "sfo-dashboard-1"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	if plan.Oci == nil {
		t.Fatal("OCI plan must carry an OCI plan")
	}
	if plan.Systemd != nil {
		t.Fatal("OCI plan must not carry a systemd plan")
	}
	image := "registry.terrascale.internal/terrascale/terrascale-dashboard@sha256:" + hostRuntimePlanDigest
	if plan.Oci.ImageReference != image {
		t.Fatalf("unexpected image reference %q", plan.Oci.ImageReference)
	}
	if plan.Oci.Platform != "linux/arm64" {
		t.Fatalf("unexpected platform %q", plan.Oci.Platform)
	}
	if plan.Oci.Security.RunAsUser != 65532 {
		t.Fatalf("unexpected run-as user %d", plan.Oci.Security.RunAsUser)
	}
	if !plan.Oci.Security.NoNewPrivileges || !plan.Oci.Security.ReadOnlyRootFileSystem {
		t.Fatal("OCI plan must be rootless and read-only")
	}
	if len(plan.Oci.Security.DroppedCapabilities) != 1 || plan.Oci.Security.DroppedCapabilities[0] != "ALL" {
		t.Fatalf("unexpected dropped capabilities %v", plan.Oci.Security.DroppedCapabilities)
	}
	if plan.Oci.Security.CgroupParent != "terrascale/sfo-dashboard-1" {
		t.Fatalf("unexpected cgroup parent %q", plan.Oci.Security.CgroupParent)
	}
	if plan.Resources.MemorySwapMaxBytes() != 0 {
		t.Fatal("swap must be pinned to zero")
	}
}

func TestRuntimeLimitsCanBeReducedWithinTheClosedRolePolicy(t *testing.T) {
	requested := RuntimeResourceLimits{
		MemoryMaxBytes: 512 * 1024 * 1024, TasksMax: 128,
		CpuQuotaPercent: 100, CpuWeight: 100, IoWeight: 100, Nice: 5,
	}

	plan, err := NewHostRuntimePlan(
		AdmittedRoleCustomerDashboard,
		RuntimeDriverOciContainer,
		mustRuntimeAllocationId(t, "gru-dashboard-limited"),
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
		AdmittedRoleCustomerDashboard,
		RuntimeDriverOciContainer,
		mustRuntimeAllocationId(t, "gru-dashboard-excessive"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		&excessive)
	var rangeError *ArgumentOutOfRangeError
	if !errors.As(err, &rangeError) {
		t.Fatalf("expected ArgumentOutOfRangeError, got %v", err)
	}
}

func TestRuntimeCliAcceptsExplicitContainerLimits(t *testing.T) {
	plan, err := HostRuntimeCli.ParsePlan([]string{
		"plan", "--role", "customer-dashboard", "--allocation", "gru-dashboard-cli",
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
				AdmittedRoleOrchestrator,
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

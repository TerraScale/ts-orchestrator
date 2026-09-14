package control

import "testing"

func TestRuntimeRoleAdmissionRetainsSafeLegacyRoles(t *testing.T) {
	for _, value := range []RuntimeRole{
		RuntimeRoleOrchestrator, RuntimeRoleTerraBase, RuntimeRoleDashboard, RuntimeRoleNatsServer,
	} {
		if !runtimeRoleIsDefined(value) {
			t.Fatalf("retained runtime role %d is not admissible", value)
		}
		if _, err := NewRuntimeAdmission(value, RuntimeDriverNativeSystemd,
			RuntimeArchitectureLinuxX64, RuntimeGeneration{}); err != nil {
			t.Fatalf("retained runtime role %d was rejected: %v", value, err)
		}
	}
}

func TestRemovedAndReducedRuntimeRoleValuesAreRefused(t *testing.T) {
	for _, value := range []RuntimeRole{
		0, RuntimeRolePlatform, RuntimeRoleAuthentication, RuntimeRoleTelemetry,
		RuntimeRoleGrafana, RuntimeRoleTrustedCi, 16, 17, 99,
	} {
		if runtimeRoleIsDefined(value) {
			t.Fatalf("removed or unrelated runtime role %d is still admissible", value)
		}
		if _, err := NewRuntimeAdmission(value, RuntimeDriverNativeSystemd,
			RuntimeArchitectureLinuxX64, RuntimeGeneration{}); err == nil {
			t.Fatalf("removed or unrelated runtime role %d passed the admission boundary", value)
		}
	}
}

func TestRetainedRuntimeDescriptorsRequireExactPairing(t *testing.T) {
	valid := []struct {
		name string
		spec WorkloadRuntimeSpec
	}{
		{
			name: "orchestrator",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleOrchestrator,
				Payload: NativeRuntimePayload{Descriptor: NativeUnitDescriptorOrchestrator},
			},
		},
		{
			name: "terrabase-native",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleTerraBase,
				Payload: NativeRuntimePayload{Descriptor: NativeUnitDescriptorTerraBase},
			},
		},
		{
			name: "terrabase-oci",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleTerraBase,
				Payload: OciRuntimePayload{Descriptor: OciRuntimeDescriptorTerraBase},
			},
		},
		{
			name: "nats",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleNatsServer,
				Payload: NativeRuntimePayload{Descriptor: NativeUnitDescriptorNatsServer},
			},
		},
		{
			name: "dashboard",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleDashboard,
				Payload: OciRuntimePayload{Descriptor: OciRuntimeDescriptorDashboard},
			},
		},
	}
	for _, test := range valid {
		t.Run(test.name+" valid", func(t *testing.T) {
			if !runtimeDescriptorMatches(test.spec) {
				t.Fatalf("retained %s role descriptor was rejected", test.name)
			}
		})
	}

	for _, test := range valid {
		t.Run(test.name+" mismatched", func(t *testing.T) {
			mismatched := test.spec
			switch payload := mismatched.Payload.(type) {
			case NativeRuntimePayload:
				payload.Descriptor = NativeUnitDescriptorTelemetry
				mismatched.Payload = payload
			case OciRuntimePayload:
				payload.Descriptor = OciRuntimeDescriptorGrafana
				mismatched.Payload = payload
			}
			if runtimeDescriptorMatches(mismatched) {
				t.Fatalf("mismatched %s role descriptor was accepted", test.name)
			}
		})
	}
}

func TestRemovedRuntimeDescriptorsCannotBypassAdmission(t *testing.T) {
	tests := []struct {
		name string
		spec WorkloadRuntimeSpec
	}{
		{
			name: "platform",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRolePlatform,
				Payload: OciRuntimePayload{Descriptor: OciRuntimeDescriptorPlatform},
			},
		},
		{
			name: "authentication",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleAuthentication,
				Payload: OciRuntimePayload{Descriptor: OciRuntimeDescriptorAuthentication},
			},
		},
		{
			name: "telemetry",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleTelemetry,
				Payload: NativeRuntimePayload{Descriptor: NativeUnitDescriptorTelemetry},
			},
		},
		{
			name: "grafana",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleGrafana,
				Payload: OciRuntimePayload{Descriptor: OciRuntimeDescriptorGrafana},
			},
		},
		{
			name: "trusted-ci",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleTrustedCi,
				Payload: OciRuntimePayload{Descriptor: OciRuntimeDescriptorTrustedCi},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if runtimeDescriptorMatches(test.spec) {
				t.Fatalf("retired %s role descriptor bypassed admission", test.name)
			}
		})
	}
}

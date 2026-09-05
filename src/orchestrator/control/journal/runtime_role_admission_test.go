package journal

import "testing"

func TestRuntimeRoleAdmissionRetainsSafeLegacyRoles(t *testing.T) {
	for _, value := range []RuntimeRole{
		RuntimeRoleOrchestrator, RuntimeRoleTerraBase, RuntimeRoleNatsServer,
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
		// 5 is the retired Dashboard role; it must stay refused forever.
		0, RuntimeRolePlatform, RuntimeRoleAuthentication, 5, RuntimeRoleTelemetry,
		RuntimeRoleGrafana, 9, 16, 17, 99,
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
			name: "nats",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleNatsServer,
				Payload: NativeRuntimePayload{Descriptor: NativeUnitDescriptorNatsServer},
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
			name: "telemetry",
			spec: WorkloadRuntimeSpec{
				Role:    RuntimeRoleTelemetry,
				Payload: NativeRuntimePayload{Descriptor: NativeUnitDescriptorTelemetry},
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

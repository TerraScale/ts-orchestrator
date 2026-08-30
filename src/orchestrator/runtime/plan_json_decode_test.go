// This file tests the strict JSON decode of the canonical runtime plan
// against the exact bytes the MarshalJSON in host_runtime_plan.go produces.
package runtime

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func planJsonDecodeTestNativePlan(t *testing.T) HostRuntimePlan {
	t.Helper()
	plan, err := NewHostRuntimePlan(
		AdmittedRoleOrchestrator,
		RuntimeDriverNativeSystemd,
		mustRuntimeAllocationId(t, "gru-orchestrator-1"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func planJsonDecodeTestOciPlan(t *testing.T) HostRuntimePlan {
	t.Helper()
	plan, err := NewHostRuntimePlan(
		AdmittedRoleTerraBaseMember,
		RuntimeDriverOciContainer,
		mustRuntimeAllocationId(t, "terrabase-member-7"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureX64,
		&RuntimeResourceLimits{
			MemoryMaxBytes:  4 * 1024 * 1024 * 1024,
			TasksMax:        1024,
			CpuQuotaPercent: 200,
			CpuWeight:       500,
			IoWeight:        300,
			Nice:            0,
		})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func planJsonDecodeTestControlNatsPlan(t *testing.T) HostRuntimePlan {
	t.Helper()
	plan, err := NewHostRuntimePlan(
		AdmittedRoleControlNatsServer,
		RuntimeDriverNativeSystemd,
		mustRuntimeAllocationId(t, "nats-a"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureX64,
		&RuntimeResourceLimits{
			MemoryMaxBytes:  1 * 1024 * 1024 * 1024,
			TasksMax:        512,
			CpuQuotaPercent: 200,
			CpuWeight:       800,
			IoWeight:        800,
			Nice:            0,
		})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func TestUnmarshalJSONRoundTripsNativeSystemdPlan(t *testing.T) {
	original := planJsonDecodeTestNativePlan(t)

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded HostRuntimePlan
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Fatalf("round trip changed the plan:\noriginal: %#v\ndecoded:  %#v", original, decoded)
	}

	again, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if string(again) != string(encoded) {
		t.Fatalf("remarshal is not stable:\nfirst:  %s\nsecond: %s", encoded, again)
	}
}

func TestUnmarshalJSONRoundTripsOciPlan(t *testing.T) {
	original := planJsonDecodeTestOciPlan(t)

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded HostRuntimePlan
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Fatalf("round trip changed the plan:\noriginal: %#v\ndecoded:  %#v", original, decoded)
	}
}

func TestUnmarshalJSONDecodesCamelCaseWireShape(t *testing.T) {
	// MarshalJSON emits the canonical camelCase wire shape. Keep this test
	// focused on decoding that shape rather than duplicating the derived
	// execution-plan policy in a hand-written payload.
	payload := string(mustMarshalPlan(t, planJsonDecodeTestControlNatsPlan(t)))

	var decoded HostRuntimePlan
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Role != AdmittedRoleControlNatsServer {
		t.Fatalf("role = %v", decoded.Role)
	}
	if decoded.Driver != RuntimeDriverNativeSystemd {
		t.Fatalf("driver = %v", decoded.Driver)
	}
	if decoded.AllocationId.Value != "nats-a" {
		t.Fatalf("allocation id = %q", decoded.AllocationId.Value)
	}
	if decoded.Architecture != HostArchitectureX64 {
		t.Fatalf("architecture = %v", decoded.Architecture)
	}
	if decoded.Resources.TasksMax != 512 || decoded.Resources.CpuWeight != 800 {
		t.Fatalf("resources = %#v", decoded.Resources)
	}
	if decoded.Systemd == nil || decoded.Systemd.UnitName != "terrascale-nats-a.service" {
		t.Fatalf("systemd plan = %#v", decoded.Systemd)
	}
	if len(decoded.Systemd.Arguments) != 2 {
		t.Fatalf("arguments = %#v", decoded.Systemd.Arguments)
	}
	if decoded.Oci != nil {
		t.Fatalf("oci plan = %#v", decoded.Oci)
	}
}

func TestUnmarshalJSONRejectsNonCanonicalPayloads(t *testing.T) {
	validNative := string(mustMarshalPlan(t, planJsonDecodeTestNativePlan(t)))
	validOci := string(mustMarshalPlan(t, planJsonDecodeTestOciPlan(t)))
	replace := func(payload, needle, replacement string) string {
		return strings.Replace(payload, needle, replacement, 1)
	}

	tests := []struct {
		name        string
		payload     string
		rawJSONOnly bool
	}{
		{
			name:    "unsupported schema version",
			payload: replace(validNative, `"schemaVersion":2`, `"schemaVersion":3`),
		},
		{
			name:    "absent schema version",
			payload: replace(validNative, `"schemaVersion":2,`, ``),
		},
		{
			name:    "unknown role enum",
			payload: replace(validNative, `"role":"orchestrator"`, `"role":"tenantWorkload"`),
		},
		{
			name:    "unknown driver enum",
			payload: replace(validNative, `"driver":"nativeSystemd"`, `"driver":"microVm"`),
		},
		{
			name:    "PascalCase driver enum",
			payload: replace(validNative, `"driver":"nativeSystemd"`, `"driver":"NativeSystemd"`),
		},
		{
			name:    "unknown architecture enum",
			payload: replace(validNative, `"architecture":"arm64"`, `"architecture":"riscv"`),
		},
		{
			name:    "invalid allocation token",
			payload: replace(validNative, `"value":"gru-orchestrator-1"`, `"value":"gru_orchestrator"`),
		},
		{
			name:    "invalid artifact digest",
			payload: replace(validNative, `"value":"`+hostRuntimePlanDigest+`"`, `"value":"abc"`),
		},
		{
			name:    "unknown top-level field",
			payload: replace(validNative, `{"schemaVersion":2`, `{"injected":1,"schemaVersion":2`),
		},
		{
			name:    "unknown resources field",
			payload: replace(validNative, `"resources":{`, `"resources":{"extra":1,`),
		},
		{
			name:    "unknown systemd plan field",
			payload: replace(validNative, `"systemd":{`, `"systemd":{"evil":true,`),
		},
		{
			name:    "unknown OCI security field",
			payload: replace(validOci, `"security":{`, `"security":{"privileged":true,`),
		},
		{
			// encoding/json rejects these shapes itself, before the custom
			// decoder runs, so any non-nil error is the deterministic outcome.
			name:        "trailing second document",
			payload:     validNative + `{"schemaVersion":2}`,
			rawJSONOnly: true,
		},
		{
			name:        "trailing garbage",
			payload:     validNative + `!`,
			rawJSONOnly: true,
		},
		{
			name:    "renamed systemd plan field",
			payload: replace(validNative, `"systemd":`, `"ociPlan":`),
		},
		{
			name: "oci driver carrying a systemd plan",
			payload: replace(validOci, `"systemd":null`,
				`"systemd":{"unitName":"x.service","executable":"/x","arguments":[],"properties":[]}`),
		},
		{
			name:    "native driver carrying an oci plan",
			payload: replace(validNative, `"oci":null`, `"oci":{"containerId":"c","imageReference":"i","platform":"linux/amd64","security":{},"resources":{}}`),
		},
		{
			name:        "empty payload",
			payload:     ``,
			rawJSONOnly: true,
		},
		{
			name:    "array payload",
			payload: `[]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded HostRuntimePlan
			err := json.Unmarshal([]byte(test.payload), &decoded)
			if err == nil {
				t.Fatal("expected a decode error")
			}
			if test.rawJSONOnly {
				return
			}
			var invalidData *InvalidDataError
			var argumentError *ArgumentError
			var outOfRange *ArgumentOutOfRangeError
			if !errors.As(err, &invalidData) && !errors.As(err, &argumentError) &&
				!errors.As(err, &outOfRange) {
				t.Fatalf("error %v is not a package data error", err)
			}
		})
	}
}

func TestUnmarshalJSONLeavesReceiverUntouchedOnError(t *testing.T) {
	original := planJsonDecodeTestNativePlan(t)
	corrupted := strings.Replace(
		string(mustMarshalPlan(t, original)), `"schemaVersion":2`, `"schemaVersion":9`, 1)

	decoded := original
	if err := decoded.UnmarshalJSON([]byte(corrupted)); err == nil {
		t.Fatal("expected a decode error")
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Fatal("a failed decode must leave the receiver untouched")
	}
}

func TestUnmarshalJSONRejectsDriverPlanShapeMismatch(t *testing.T) {
	oci := string(mustMarshalPlan(t, planJsonDecodeTestOciPlan(t)))
	memberStart := strings.LastIndex(oci, `,"oci":`)
	if memberStart < 0 {
		t.Fatal("the oci member was not found")
	}
	absent := oci[:memberStart] + `}`

	var decoded HostRuntimePlan
	err := json.Unmarshal([]byte(absent), &decoded)
	if err == nil {
		t.Fatal("an ociContainer plan without its OCI plan must be rejected")
	}
	var invalidData *InvalidDataError
	if !errors.As(err, &invalidData) {
		t.Fatalf("error %v is not an InvalidDataError", err)
	}
	if !strings.Contains(err.Error(), "must carry its OCI plan") {
		t.Fatalf("unexpected shape error %v", err)
	}
}

func mustMarshalPlan(t *testing.T, plan HostRuntimePlan) []byte {
	t.Helper()
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

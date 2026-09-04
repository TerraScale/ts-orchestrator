// This file tests the strict JSON decode of the canonical runtime plan
// against the exact bytes the MarshalJSON in host_runtime_plan.go produces.
package runtime

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func planJsonDecodeTestNativePlan(t *testing.T) HostRuntimePlan {
	t.Helper()
	plan, err := NewHostRuntimePlan(
		AdmittedRoleAutoscaler,
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

func planJsonDecodeTestControlNatsPlan(t *testing.T) HostRuntimePlan {
	t.Helper()
	plan, err := NewHostRuntimePlan(
		AdmittedRoleNats,
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

func TestUnmarshalJSONDecodesCamelCaseWireShape(t *testing.T) {
	// MarshalJSON emits the canonical camelCase wire shape. Keep this test
	// focused on decoding that shape rather than duplicating the derived
	// execution-plan policy in a hand-written payload.
	payload := string(mustMarshalPlan(t, planJsonDecodeTestControlNatsPlan(t)))

	var decoded HostRuntimePlan
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Role != AdmittedRoleNats {
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
			payload: replace(validNative, `"role":"autoscaler"`, `"role":"tenantWorkload"`),
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
			name:    "retired oci driver enum",
			payload: replace(validNative, `"driver":"nativeSystemd"`, `"driver":"ociContainer"`),
		},
		{
			name:    "retired dashboard role enum",
			payload: replace(validNative, `"role":"autoscaler"`, `"role":"dashboard"`),
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
			var argumentError *errs.Argument
			var outOfRange *errs.ArgumentOutOfRangeError
			if !errors.As(err, &invalidData) && !errors.As(err, &argumentError) &&
				!errors.As(err, &outOfRange) {
				t.Fatalf("error %v is not a package data error", err)
			}
		})
	}
}

// TestUnmarshalJSONRejectsNonCanonicalExecutionPlans proves the decoder itself
// enforces the canonical-plan trust boundary: structurally valid payloads
// whose execution plans differ from what NewHostRuntimePlan would derive for
// the decoded role, resources, and identity are rejected as invalid data,
// instead of waiting for an adapter's requireCanonical* fence.
func TestUnmarshalJSONRejectsNonCanonicalExecutionPlans(t *testing.T) {
	validNative := string(mustMarshalPlan(t, planJsonDecodeTestNativePlan(t)))
	replace := func(payload, needle, replacement string) string {
		return strings.Replace(payload, needle, replacement, 1)
	}

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "systemd unit name rewritten",
			payload: replace(validNative, `"unitName":"terrascale-gru-orchestrator-1.service"`, `"unitName":"evil.service"`),
		},
		{
			name:    "systemd executable rewritten",
			payload: replace(validNative, `"executable":"/opt/terrascale/artifacts/terrascale-orchestrator/sha256-`, `"executable":"/tmp/pwned/sha256-`),
		},
		{
			name:    "systemd property injected",
			payload: replace(validNative, `"Type=exec"`, `"Type=exec","User=root"`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded HostRuntimePlan
			err := json.Unmarshal([]byte(test.payload), &decoded)
			if err == nil {
				t.Fatal("expected a decode error for a non-canonical execution plan")
			}
			var invalidData *InvalidDataError
			if !errors.As(err, &invalidData) {
				t.Fatalf("error %v is not an InvalidDataError", err)
			}
			if !strings.Contains(err.Error(), "not the canonical plan") {
				t.Fatalf("unexpected error %v", err)
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
	native := string(mustMarshalPlan(t, planJsonDecodeTestNativePlan(t)))
	memberStart := strings.LastIndex(native, `,"systemd":`)
	if memberStart < 0 {
		t.Fatal("the systemd member was not found")
	}
	absent := native[:memberStart] + `}`

	var decoded HostRuntimePlan
	err := json.Unmarshal([]byte(absent), &decoded)
	if err == nil {
		t.Fatal("a nativeSystemd plan without its systemd plan must be rejected")
	}
	var invalidData *InvalidDataError
	if !errors.As(err, &invalidData) {
		t.Fatalf("error %v is not an InvalidDataError", err)
	}
	if !strings.Contains(err.Error(), "must carry its systemd plan") {
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

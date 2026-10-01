package runtimepriority

import (
	"encoding/json/v2"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

// Frozen observations contain only invocation arguments and dependency replies
// captured from the former Python cases. Go owns selection and all expectations.
const pressureEvidenceObservation = `
import contextlib, datetime
from pathlib import Path
from unittest import mock
def restore(value):
    if isinstance(value, dict):
        if set(value) == {"$datetime"}:
            return datetime.datetime.fromisoformat(value["$datetime"])
        if set(value) == {"$path"}:
            return Path(value["$path"])
        return {key: restore(item) for key, item in value.items()}
    if isinstance(value, list):
        return [restore(item) for item in value]
    return value
def wire(value):
    if isinstance(value, datetime.datetime):
        return {"$datetime": value.isoformat()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: wire(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [wire(item) for item in value]
    return value
args, kwargs = restore(a["args"]), restore(a["kwargs"])
runner = None
with contextlib.ExitStack() as stack:
    for key, reply in a.get("mocks", {}).items():
        stack.enter_context(mock.patch.object(m, key, return_value=restore(reply)))
    if "state" in a:
        state = restore(a["state"])
        runner = m.AdapterRunner(state["manifest"], state["manifest_hash"], state["evidence_dir"])
        runner.__dict__.update(state)
        call = getattr(runner, a["operation"])
    else:
        call = getattr(m, a["operation"])
    try:
        result = {"value": wire(call(*args, **kwargs))}
    except Exception as error:
        result = {"error": str(error), "error_type": type(error).__name__}
    if runner is not None:
        result["state"] = {key: wire(getattr(runner, key)) for key in a["inspect"]}
`

func shiftObservation(t *testing.T, value any, delta time.Duration) any {
	t.Helper()
	switch v := value.(type) {
	case string:
		if stamp, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return sampleTimestamp(stamp.Add(delta))
		}
		if strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") {
			var data any
			if json.Unmarshal([]byte(v), &data) == nil {
				data = shiftObservation(t, data, delta)
				raw, err := json.Marshal(data, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				return string(raw)
			}
		}
		return v
	case []any:
		for i, item := range v {
			v[i] = shiftObservation(t, item, delta)
		}
		return v
	case map[string]any:
		for key, item := range v {
			if key == "__REALTIME_TIMESTAMP" {
				if s, ok := item.(string); ok {
					n, err := strconv.ParseInt(s, 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					v[key] = strconv.FormatInt(n+delta.Microseconds(), 10)
					continue
				}
			}
			v[key] = shiftObservation(t, item, delta)
		}
		for rawKey, hashKey := range map[string]string{"operator_hosts_json": "operator_hosts_sha256", "worker_state_record": "worker_state_sha256", "journal_watermark_raw_record": "journal_watermark_raw_record_sha256", "raw_record": "raw_record_sha256", "transaction_request_raw": "transaction_request_sha256", "write_receipt_raw": "write_receipt_sha256", "peer_read_raw": "peer_read_sha256"} {
			if raw, ok := v[rawKey].(string); ok {
				v[hashKey] = digest([]byte(raw))
			}
		}
		return v
	default:
		return value
	}
}
func pressureInputs(t *testing.T, name string) []any {
	t.Helper()
	fixtures := decodeObject(t, script.Read(t, filepath.Join(script.Root(t), "tests/runtime_priority/testdata/pressure-observations.json")))
	records := fixtures[name].([]any)
	// The clock is shifted by Go so process-report age and journal windows remain
	// realistic while preserving the intervals that each case exercises.
	origin := fixtures["test_oom_event_and_receipt_bind_exact_role_and_restored_signed_cap"].([]any)[0].(map[string]any)["args"].([]any)[2].(string)
	stamp, err := time.Parse(time.RFC3339Nano, origin)
	if err != nil {
		t.Fatal(err)
	}
	delta := time.Since(stamp)
	return shiftObservation(t, records, delta).([]any)
}
func mergeObservation(target, patch object) {
	for key, value := range patch {
		if nested, ok := value.(map[string]any); ok {
			if current, ok := target[key].(map[string]any); ok {
				mergeObservation(current, nested)
				continue
			}
		}
		target[key] = value
	}
}

func replayPressureInput(t *testing.T, record object, inspect ...string) object {
	t.Helper()
	record["inspect"] = inspect
	if state, ok := record["state"].(map[string]any); ok {
		manifest := exampleManifest(t)
		mergeObservation(manifest, field(state, "manifest_patch"))
		delete(state, "manifest_patch")
		state["manifest"] = manifest
		if _, ok := state["harness_sha256"]; ok {
			hash := digest(script.Read(t, filepath.Join(script.Root(t), "tests/runtime_priority/pressure.py")))
			state["harness_sha256"] = hash
			for _, arg := range record["args"].([]any) {
				if arg, ok := arg.(map[string]any); ok {
					if _, ok := arg["worker_harness_sha256"]; ok {
						arg["worker_harness_sha256"] = hash
					}
				}
			}
		}
		state["evidence_dir"] = object{"$path": t.TempDir()}
	}
	return decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_runner.py", record, pressureEvidenceObservation))
}
func TestPressureQualifiedRoleCgroups(t *testing.T) {
	records := pressureInputs(t, "test_oom_cgroups_must_be_rooted_and_the_database_role_must_be_direct_child")
	native := "/sys/fs/cgroup/system.slice/terrascale-host.service/supervisor/terrascale-host-1"
	for i, reason := range []string{"", "safely below the cgroup root", "direct native role child", "safe cgroup-root-relative"} {
		got := replayPressureInput(t, records[i].(map[string]any))
		if reason == "" {
			assertEqual(t, got["value"], []string{native, native + "/terrabase", "terrabase"})
		} else {
			assertPressureError(t, got, reason)
		}
	}
}
func TestPressureReadOnlyHostReports(t *testing.T) {
	records := pressureInputs(t, "test_host_status_uses_controller_admitted_read_only_reports_and_raw_process_witnesses")
	got := replayPressureInput(t, records[0].(map[string]any))
	if got["error"] != nil {
		t.Fatal(got)
	}
	assertEqual(t, field(field(field(got, "value"), "members"), "source")["managed_identity"].(map[string]any)["pid"], 42)
	assertPressureError(t, replayPressureInput(t, records[1].(map[string]any)), "verified must remain false")
}
func TestPressureManagerRecoveryPreservesPeerSession(t *testing.T) {
	records := pressureInputs(t, "test_host_manager_recovery_allows_only_source_session_advance_with_restart_witness")
	for i, reason := range []string{"", "", "", "process identity/restart counter changed", "host session identity changed", "host session identity changed"} {
		got := replayPressureInput(t, records[i].(map[string]any))
		if reason != "" {
			assertPressureError(t, got, reason)
		} else {
			if got["error"] != nil {
				t.Fatal(got)
			}
			if i == 1 {
				assertEqual(t, field(field(field(got, "value"), "members"), "source")["epoch"], 2)
			}
		}
	}
}
func TestPressureFailureTargetRequiresQualifiedRole(t *testing.T) {
	records := pressureInputs(t, "test_terrabase_sigkill_rejects_report_cgroup_outside_qualified_role")
	assertPressureError(t, replayPressureInput(t, records[0].(map[string]any)), "differs from the qualifier-pinned native role cgroup")
}
func TestPressureLiveOCIIdentityPins(t *testing.T) {
	records := pressureInputs(t, "test_live_oci_image_metadata_is_matched_to_controller_host_and_manifest_pins")
	for i, reason := range []string{"", "live OCI metadata", "pinned controller instance"} {
		got := replayPressureInput(t, records[i].(map[string]any))
		if reason == "" {
			if got["error"] != nil {
				t.Fatal(got)
			}
		} else {
			assertPressureError(t, got, reason)
		}
	}
}
func TestPressureObjectDurabilityRequiresExactPeerRead(t *testing.T) {
	records := pressureInputs(t, "test_object_durable_receipt_sequence_is_bound_to_exact_peer_read")
	got := replayPressureInput(t, records[0].(map[string]any))
	if got["error"] != nil {
		t.Fatal(got)
	}
	assertEqual(t, field(got, "value")["event_sequence"], 21)
	assertEqual(t, field(got, "value")["commit_sequence_opaque"], "507")
	assertPressureError(t, replayPressureInput(t, records[1].(map[string]any)), "does not contain exactly one sibling")
}
func TestPressureExternalScopeRequiresEffectiveCaps(t *testing.T) {
	records := pressureInputs(t, "test_external_systemd_scope_is_accepted_only_with_exact_effective_caps")
	got := replayPressureInput(t, records[0].(map[string]any), "pressure_path")
	if got["error"] != nil {
		t.Fatal(got)
	}
	if !strings.HasSuffix(field(got, "state")["pressure_path"].(string), ".scope") {
		t.Fatal(got)
	}
	assertPressureError(t, replayPressureInput(t, records[1].(map[string]any)), "memory.min and memory.low at zero")
}
func TestPressureOOMRequiresExactRoleAndRestoredCap(t *testing.T) {
	records := pressureInputs(t, "test_oom_event_and_receipt_bind_exact_role_and_restored_signed_cap")
	before := records[0].(map[string]any)
	got := replayPressureInput(t, before, "oom_restore_intent")
	if got["error"] != nil {
		t.Fatal(got)
	}
	intent := before["args"].([]any)[0].(map[string]any)["oom_restore_intent"]
	assertEqual(t, field(got, "state")["oom_restore_intent"], intent)
	evidenceDir := field(field(before, "state"), "evidence_dir")["$path"].(string)
	assertEqual(t, decodeObject(t, script.Read(t, filepath.Join(evidenceDir, "oom-restore-intent.json"))), intent)
	// Record 1 is the nested role-path validation; records 2 and 3 are the
	// successful event validation and the altered restored-cap rejection.
	got = replayPressureInput(t, records[2].(map[string]any), "oom_observed", "oom_restore_receipt")
	if got["error"] != nil {
		t.Fatal(got)
	}
	assertEqual(t, field(got, "state")["oom_observed"], true)
	assertEqual(t, field(got, "state")["oom_restore_receipt"], records[2].(map[string]any)["args"].([]any)[0].(map[string]any)["memory_limit_receipt"])
	assertPressureError(t, replayPressureInput(t, records[3].(map[string]any)), "not safely lowered and restored")
}
func TestPressurePeerProofFinishesDuringWorkers(t *testing.T) {
	records := pressureInputs(t, "test_during_pressure_peer_proof_must_finish_before_workers_end")
	got := replayPressureInput(t, records[0].(map[string]any))
	if got["error"] != nil {
		t.Fatal(got)
	}
	assertPressureError(t, replayPressureInput(t, records[1].(map[string]any)), "did not complete during active pressure")
}

func TestPressureRequiresDistinctPinnedController(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(object)
	}{{"missing_identity", "controller_identity", func(m object) { delete(m, "controller_identity") }}, {"different_oci_target", "controller SSH target OCI instance ID", func(m object) {
		field(field(field(field(m, "transport"), "ssh"), "targets"), "controller")["oci_instance_id"] = "ocid1.instance.oc1.sa-saopaulo-1.other-controller-id"
	}}} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := exampleManifest(t)
			tc.change(manifest)
			assertPressureError(t, validateManifest(t, manifest, true, false), tc.reason)
		})
	}
}
func TestControllerOperationsUseControllerSSH(t *testing.T) {
	for _, tc := range []struct {
		name, operation string
		request, reply  object
	}{{"service", "_service_state", object{"guest_role": "controller"}, object{"guest_role": "controller", "units": object{}, "host_boot_id": "boot"}}, {"probe", "_qualify", object{"guest_role": "controller", "request_id": "request"}, object{"summary": object{}, "commands_log": "read-only\n"}}} {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_adapter.py", object{"operation": tc.operation, "request": tc.request, "reply": tc.reply}, `from unittest import mock
with mock.patch.object(m, "_ssh", return_value=a["reply"]) as ssh:
    value = getattr(m, a["operation"])(a["request"])
result = {"value": value, "calls": [[list(call.args), call.kwargs] for call in ssh.call_args_list]}`))
			action := "service_state"
			if tc.name == "probe" {
				action = "qualify"
			}
			assertEqual(t, got["calls"], []any{[]any{[]any{tc.request, "controller", action}, object{}}})
			if tc.name == "service" {
				assertEqual(t, got["value"], tc.reply)
			}
		})
	}
}

const controllerProbeObservation = `
import types
from pathlib import Path
from unittest import mock
probe = m.Probe(types.SimpleNamespace(**a["args"]))
for key, reply in a["replies"].items():
    setattr(probe, key, mock.Mock(return_value=reply))
probe.source_identity = mock.Mock(return_value=(None, Path(a["units"])))
with mock.patch.object(m, "normalize_cpu_max", return_value=a["cpu_max"]):
    summary = probe.run()
result = {"summary": summary, "unit_calls": [list(call.args) for call in probe.unit.call_args_list], "host_calls": probe.verify_host_runtime.call_count}
`

func TestControllerProbeAvoidsAbsentHostUnit(t *testing.T) {
	unit := "terrascale-orchestrator-controller.service"
	units := t.TempDir()
	script.Write(t, filepath.Join(units, unit), []byte("[Service]\n"), 0600)
	args := object{"role": "controller", "controller_unit": unit, "host_unit": "terrascale-orchestrator-host.service", "database_pid": nil, "oci_instance_id": "controller-ocid", "image_id": "image-ocid", "artifact_id": "artifact", "config_id": "config", "profile_id": "profile"}
	replies := object{"command": "systemd 255", "unit": object{"ControlGroup": "/system.slice/" + unit}, "verify_baked_profile": object{}, "assert_unit_priority": 42, "assert_process": object{"pid": 42, "cgroup": "/sys/fs/cgroup/system.slice/" + unit}, "verify_priority_cgroup": object{"cpu_weight": 10000, "io_weight": 10000}, "verify_memory_budget": object{}, "verify_oomd_policy": object{}, "verify_host_runtime": object{}, "memory_usage_sample": object{}}
	got := decodeObject(t, script.Python(t, "tests/runtime_priority/qualify.py", object{"args": args, "replies": replies, "units": units, "cpu_max": "max 100000"}, controllerProbeObservation))
	if got["error"] != nil {
		t.Fatal(got)
	}
	summary := field(got, "summary")
	assertEqual(t, summary["guest_role"], "controller")
	hashes := field(summary, "unit_sha256")
	assertEqual(t, len(hashes), 1)
	assertEqual(t, hashes[unit], digest([]byte("[Service]\n")))
	assertEqual(t, got["unit_calls"], [][]string{{unit}})
	assertEqual(t, got["host_calls"], 0)
}

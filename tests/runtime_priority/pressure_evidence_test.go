package runtimepriority

import (
	"encoding/json/v2"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"context"
	"fmt"
	rp "git.terrascale.tech/TerraScale/ts-orchestrator/internal/runtimepriority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
	"golang.org/x/sys/unix"
	"os"
)

// Frozen records contain input evidence only. Every decision is executed by the
// production Go validators, and Go owns all expected outcomes.
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
	setupStarted := time.Now()
	record["inspect"] = inspect
	if state, ok := record["state"].(map[string]any); ok {
		manifest := exampleManifest(t)
		mergeObservation(manifest, field(state, "manifest_patch"))
		delete(state, "manifest_patch")
		state["manifest"] = manifest
		if _, ok := state["harness_sha256"]; ok {
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			hash := digest(script.Read(t, binary))
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
	if record["operation"] == "_validate_pressure" {
		evidence := record["args"].([]any)[1].(map[string]any)
		observed := field(evidence, "pressure_cgroup")
		device := observed["io_device"].(string)
		observed["io_backing"] = normalize(t, object{"filesystem_device": device, "mountpoint": "/var/tmp", "filesystem_type": "xfs", "block_leaf_devices": []string{"8:0"}, "block_device_chain": []object{{"device": device, "sysfs_path": "/sys/devices/virtual/block/dm-0", "subsystem": "block", "virtual": true, "pseudo": false, "partition_parent": nil, "slaves": []string{"8:0"}, "size_sectors": 100000}, {"device": "8:0", "sysfs_path": "/sys/devices/pci/block/sda", "subsystem": "block", "virtual": false, "pseudo": false, "partition_parent": nil, "slaves": []string{}, "size_sectors": 100000}}})
	}
	record = restoreRecord(record).(map[string]any)
	args := record["args"].([]any)
	operation := record["operation"].(string)
	var value any
	var err error
	var runner *rp.Runner
	if state, ok := record["state"].(map[string]any); ok {
		runner = rp.NewRunner(field(state, "manifest"), state["manifest_hash"].(string), state["evidence_dir"].(string))
		for key, v := range state {
			runner.State[key] = v
		}
	}
	switch operation {
	case "_qualified_role_cgroups":
		a, b, c, e := rp.QualifiedRoleCgroups(args[0].(string), args[1].(string))
		value = []any{a, b, c}
		err = e
	case "validate_report_evidence":
		value, err = rp.ValidateReportEvidence(args[0].(map[string]any), args[1].(map[string]any), args[2].(string), args[3].(map[string]any), args[4].(map[string]any))
	case "validate_database_wire":
		value, err = rp.ValidateDatabaseWire(args[0].(map[string]any), args[1].(map[string]any), args[2].(map[string]any))
	case "_compare_services":
		err = runner.CompareServices(args[0].(map[string]any), args[1].(string))
	case "_failure_target":
		// Native executable hashing can exceed the witness window under the
		// race detector. Preserve the fixture's report age at validator entry.
		runner.State = shiftObservation(t, runner.State, time.Since(setupStarted)).(map[string]any)
		value, err = runner.FailureTarget()
	case "_validate_role":
		err = runner.ValidateRole(args[0].(string), args[1].(string), args[2].(map[string]any), args[3].(map[string]any))
	case "_validate_pressure":
		err = runner.ValidatePressure(args[0].(string), args[1].(map[string]any), args[2].(map[string]any), args[3].(map[string]any))
	case "_validate_oom":
		err = runner.ValidateOOM(args[0].(map[string]any), args[1].(map[string]any), args[2].(string))
	default:
		t.Fatalf("unhandled native validation %s", operation)
	}
	result := errorObservation(err)
	if err == nil {
		result["value"] = value
	}
	if runner != nil {
		state := object{}
		for _, key := range inspect {
			state[key] = runner.State[key]
		}
		result["state"] = state
	}
	return normalize(t, result)
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
	manifest := exampleManifest(t)
	runner := rp.NewRunner(manifest, strings.Repeat("a", 64), t.TempDir())
	start := time.Now()
	runner.State["pressure_started_at"] = start
	if err := runner.ValidateActiveObservation("host_status", "after_write", sampleTimestamp(start.Add(10*time.Second))); err != nil {
		t.Fatal(err)
	}
	err := runner.ValidateActiveObservation("host_status", "after_write", sampleTimestamp(start.Add(61*time.Second)))
	assertPressureError(t, errorObservation(err), "did not complete during active pressure")
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
	for _, operation := range []string{"service_state", "qualify"} {
		t.Run(operation, func(t *testing.T) {
			request := object{"role": operation, "guest_role": "controller", "request_id": "request"}
			reply := object{"guest_role": "controller", "units": object{}, "host_boot_id": "boot"}
			if operation == "qualify" {
				reply = object{"summary": object{}, "commands_log": "read-only\n"}
			}
			calls := []any{}
			adapter := rp.Adapter{SSH: func(_ context.Context, request rp.Object, label, action string, payload rp.Object) (rp.Object, error) {
				calls = append(calls, []any{request, label, action})
				return reply, nil
			}}
			value, err := adapter.Dispatch(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			assertEqual(t, calls, []any{[]any{request, "controller", operation}})
			if operation == "service_state" {
				assertEqual(t, value, reply)
			}
		})
	}
}
func TestControllerProbeAvoidsAbsentHostUnit(t *testing.T) {
	// Native qualifier integration is exercised with real isolated proc/cgroup
	// files and an injected command runner; only the selected controller is read.
	root := t.TempDir()
	cg := filepath.Join(root, "cgroup")
	proc := filepath.Join(root, "proc")
	system := filepath.Join(cg, "system.slice")
	service := filepath.Join(system, rp.ControllerUnit)
	units := filepath.Join(root, "units")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := object{"role": "controller", "profile_id": "profile", "system_reserve_bytes": int64(16384), "allocatable_memory_bytes": int64(32768), "expected_controller_memory_min_bytes": int64(4096), "expected_controller_memory_low_bytes": int64(8192), "expected_system_slice_memory_min_bytes": int64(4096), "expected_system_slice_memory_low_bytes": int64(8192)}
	for _, path := range []string{cg, system, service} {
		for name, raw := range map[string]string{"cpu.weight": "10000", "io.weight": "default 10000", "cpu.max": "max 100000", "memory.max": "max", "memory.min": "4096", "memory.low": "8192", "memory.current": "123", "memory.peak": "456", "memory.stat": "anon 123\n"} {
			script.Write(t, filepath.Join(path, name), []byte(raw), 0600)
		}
	}
	script.Write(t, filepath.Join(proc, "sys/kernel/random/boot_id"), []byte(sampleBoot), 0600)
	script.Write(t, filepath.Join(proc, "meminfo"), []byte("MemTotal: 1024 kB\n"), 0600)
	stat := fmt.Sprintf("42 (controller) S %s", strings.Repeat("0 ", 40))
	fields := strings.Fields(strings.Split(stat, ")")[1])
	fields[16] = "-20"
	fields[19] = "700"
	fields[38] = "0"
	stat = "42 (controller) " + strings.Join(fields, " ")
	for name, raw := range map[string]string{"stat": stat, "cgroup": "0::/system.slice/" + rp.ControllerUnit + "\n", "oom_score_adj": "-1000"} {
		script.Write(t, filepath.Join(proc, "42", name), []byte(raw), 0600)
	}
	script.Write(t, filepath.Join(units, rp.ControllerUnit), []byte("[Service]\n"), 0600)
	profile := filepath.Join(root, "profile.json")
	script.Write(t, profile, []byte(`{"version":1,"profile_id":"profile","system_reserve_bytes":16384}`), 0644)
	// Inject only the baked file's ownership observation; profile shape/reserve
	// validation and the complete controller branch still execute in Go.
	if err := syscallSetOmit(service); err != nil {
		t.Skipf("filesystem lacks user xattrs: %v", err)
	}
	calls := []string{}
	probe := rp.Qualifier{BakedProfile: func() (rp.Object, error) {
		return rp.ValidateBakedProfile(script.Read(t, profile), 0644, 0, 0, 1, "profile", 16384)
	}, Args: args, CgroupRoot: cg, ProcRoot: proc, ProfilePath: profile, UnitRoot: units, Executable: binary, Command: func(_ context.Context, argv []string) (string, error) {
		calls = append(calls, strings.Join(argv, " "))
		if argv[0] == "ionice" {
			return "best-effort: prio 0", nil
		}
		if argv[1] == "--version" {
			return "systemd 255", nil
		}
		if argv[2] != rp.ControllerUnit {
			return "", fmt.Errorf("unexpected absent host unit")
		}
		return "ActiveState=active\nMainPID=42\nControlGroup=/system.slice/" + rp.ControllerUnit + "\nNice=-20\nOOMScoreAdjust=-1000\nCPUWeight=10000\nIOWeight=10000\nCPUSchedulingPolicy=other\nIOSchedulingClass=best-effort\nIOSchedulingPriority=0\nManagedOOMPreference=omit\nDelegate=no\nDelegateSubgroup=\nMemoryMin=4096\nMemoryLow=8192", nil
	}}
	summary, err := probe.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, summary["guest_role"], "controller")
	hashes := field(summary, "unit_sha256")
	assertEqual(t, len(hashes), 1)
	assertEqual(t, hashes[rp.ControllerUnit], digest([]byte("[Service]\n")))
	for _, call := range calls {
		if strings.Contains(call, rp.HostUnit) {
			t.Fatalf("queried absent host unit: %s", call)
		}
	}
}
func restoreRecord(value any) any {
	switch v := value.(type) {
	case map[string]any:
		if len(v) == 1 {
			if path, ok := v["$path"].(string); ok {
				return path
			}
			if stamp, ok := v["$datetime"].(string); ok {
				return stamp
			}
		}
		out := object{}
		for key, item := range v {
			out[key] = restoreRecord(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = restoreRecord(item)
		}
		return out
	default:
		return v
	}
}

func syscallSetOmit(path string) error { return unix.Setxattr(path, "user.oomd_omit", []byte("1"), 0) }

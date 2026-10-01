package runtimepriority

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

const pressureModule = "tests/runtime_priority/pressure.py"
const hostServicePath = "/sys/fs/cgroup/system.slice/terrascale-orchestrator-host.service"
const controllerServicePath = "/sys/fs/cgroup/system.slice/terrascale-orchestrator-controller.service"
const sampleBoot = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const sampleSystemd = "systemd 255 (test)"

func exampleManifest(t *testing.T) object {
	t.Helper()
	return decodeObject(t, script.Read(t, filepath.Join(script.Root(t), "tests/runtime_priority/example-dry-run.json")))
}
func cloneObject(t *testing.T, o object) object { t.Helper(); return decodeObject(t, jsonWire(t, o)) }
func observePressure(t *testing.T, args any, body string) object {
	t.Helper()
	return decodeObject(t, script.Python(t, pressureModule, args, body))
}
func validateManifest(t *testing.T, m object, dry, allocations bool) object {
	t.Helper()
	return observePressure(t, object{"manifest": m, "dry": dry, "allocations": allocations}, `result = {"reasons": m.validate_manifest(a["manifest"], dry_run=a["dry"], allow_allocations=a["allocations"])}`)
}
func reasonsText(o object) string { return fmt.Sprint(o["reasons"]) }
func TestPressureDryRunAndUnqualifiedEvidence(t *testing.T) {
	manifest := exampleManifest(t)
	got := validateManifest(t, manifest, true, false)
	for _, reason := range []string{"OCI owner has not explicitly authorized live pressure", "host_service memory floors are allocations, not measured floors", "operator executable pin"} {
		assertContains(t, reasonsText(got), reason)
	}
	manifestPath := filepath.Join(script.Root(t), "tests/runtime_priority/example-dry-run.json")
	got = observePressure(t, object{"path": manifestPath}, `import contextlib, hashlib, io, json
from pathlib import Path
manifest, wire = m.load_json(Path(a["path"]))
output = io.StringIO()
with contextlib.redirect_stdout(output):
    status = m.dry_run(manifest, hashlib.sha256(wire).hexdigest())
result = {"status": status, "plan": json.loads(output.getvalue())}`)
	assertEqual(t, got["status"], 0)
	plan := field(got, "plan")
	assertEqual(t, plan["schema"], manifest["schema"])
	assertEqual(t, plan["qualification_status"], "UNQUALIFIED")
	assertEqual(t, plan["commands_executed"], false)
	assertEqual(t, plan["pressure_started"], false)
	evidence := filepath.Join(t.TempDir(), "evidence")
	got = observePressure(t, object{"path": manifestPath, "evidence": evidence}, `import hashlib
from pathlib import Path
from unittest import mock
manifest, wire = m.load_json(Path(a["path"]))
with mock.patch.object(m.subprocess, "Popen") as spawn:
    status = m.run_qualification(manifest, wire, hashlib.sha256(wire).hexdigest(), Path(a["evidence"]))
result = {"status": status, "spawns": spawn.call_count}`)
	assertEqual(t, got["status"], 1)
	assertEqual(t, got["spawns"], 0)
	summary := decodeObject(t, script.Read(t, filepath.Join(evidence, "summary.json")))
	assertEqual(t, summary["qualification_status"], "UNQUALIFIED")
	assertEqual(t, summary["commands_executed"], false)
	assertEqual(t, summary["pressure_started"], false)
	assertEqual(t, string(script.Read(t, filepath.Join(evidence, "manifest.json"))), string(script.Read(t, manifestPath)))
	if _, err := os.Stat(filepath.Join(evidence, "checksums.sha256")); err != nil {
		t.Fatal(err)
	}
}
func TestPressureResourceBounds(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(object)
	}{
		{"memory", "exceeds the pressure cgroup memory.max", func(m object) { field(m, "pressure")["memory_bytes"] = 500 * 1024 * 1024 }},
		{"cpu_period", "<quota> 100000", func(m object) { field(field(m, "pressure"), "workload_cgroup")["cpu_max"] = "75000 100001" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := exampleManifest(t)
			tc.change(manifest)
			assertPressureError(t, validateManifest(t, manifest, true, false), tc.reason)
		})
	}
	manifest := exampleManifest(t)
	p := field(manifest, "pressure")
	p["scenario"] = "terrabase_oom"
	p["scenario_event_after_seconds"] = 30
	p["oom_fault"] = object{"target_memory_max_bytes": 512 * 1024 * 1024, "deadline_seconds": 10}
	deadlines := field(field(manifest, "adapter"), "deadlines_seconds")
	deadlines["kernel_oom_evidence"] = 20
	got := validateManifest(t, manifest, true, false)
	if strings.Contains(reasonsText(got), "required adapter 'kernel_oom_evidence'") {
		t.Fatal(got)
	}
	delete(deadlines, "kernel_oom_evidence")
	assertContains(t, reasonsText(validateManifest(t, manifest, true, false)), "required adapter 'kernel_oom_evidence'")
	deadlines["kernel_oom_evidence"] = 20
	field(p, "oom_fault")["target_memory_max_bytes"] = 1024 * 1024 * 1024
	assertPressureError(t, validateManifest(t, manifest, true, false), "below the signed TerraBase role cap")
}
func pinnedFile(t *testing.T, parent object, pathKey, hashKey, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	script.Write(t, path, raw, mode)
	parent[pathKey] = path
	if hashKey != "" {
		parent[hashKey] = digest(raw)
	}
}
func fullyPinnedAllocationManifest(t *testing.T) object {
	t.Helper()
	manifest := exampleManifest(t)
	root := t.TempDir()
	suite := filepath.Join(script.Root(t), "tests/runtime_priority")
	auth := field(manifest, "authorization")
	auth["live_stress_authorized"] = true
	pinnedFile(t, auth, "owner_handoff_path", "owner_handoff_sha256", filepath.Join(root, "owner-handoff.json"), []byte("owner-authorized qualification handoff\n"), 0600)
	adapterPath := filepath.Join(suite, "alpha_adapter.py")
	adapterHash := digest(script.Read(t, adapterPath))
	contract := field(manifest, "adapter_contract")
	contract["id"] = "frozen-alpha-d15-test"
	contract["frozen"] = true
	contract["source_path"] = adapterPath
	contract["source_sha256"] = adapterHash
	python := script.Run(t, script.Root(t), nil, "python3", "-c", "import sys; print(sys.executable)")
	if python.Code != 0 {
		t.Fatal(python.Stderr)
	}
	pythonPath := strings.TrimSpace(python.Stdout)
	adapter := field(manifest, "adapter")
	adapter["python_path"] = pythonPath
	adapter["python_sha256"] = digest(script.Read(t, pythonPath))
	adapter["source_path"] = adapterPath
	adapter["source_sha256"] = adapterHash
	for _, key := range []string{"memory_floor_evidence", "controller_memory_floor_evidence"} {
		for scope, e := range field(manifest, key) {
			pinnedFile(t, e.(map[string]any), "source_path", "source_sha256", filepath.Join(root, key+"-"+scope+".json"), jsonWire(t, object{"scope": scope, "basis": "allocation"}), 0600)
		}
	}
	transport := field(manifest, "transport")
	operator := field(transport, "operator")
	pinnedFile(t, operator, "executable_path", "executable_sha256", filepath.Join(root, "operator"), []byte("fixture operator\n"), 0700)
	pinnedFile(t, operator, "config_path", "config_sha256", filepath.Join(root, "operator.toml"), []byte("[fixture]\n"), 0600)
	ssh := field(transport, "ssh")
	pinnedFile(t, ssh, "executable_path", "executable_sha256", filepath.Join(root, "ssh"), []byte("fixture ssh\n"), 0700)
	for label, v := range field(ssh, "targets") {
		target := v.(map[string]any)
		pinnedFile(t, target, "known_hosts_path", "known_hosts_sha256", filepath.Join(root, label+"-known-hosts"), []byte("fixture host key\n"), 0600)
		pinnedFile(t, target, "identity_file_path", "", filepath.Join(root, label+"-key"), []byte("fixture private key\n"), 0600)
	}
	https := field(transport, "https")
	pinnedFile(t, https, "ca_bundle_path", "ca_bundle_sha256", filepath.Join(root, "client-ca.pem"), []byte("fixture CA bundle\n"), 0600)
	for _, label := range []string{"source", "peer"} {
		pinnedFile(t, https, label+"_credential_file", "", filepath.Join(root, label+"-token"), []byte("fixture-token\n"), 0600)
	}
	runtime := field(transport, "runtime")
	runtime["stress_launcher_sha256"] = digest(script.Read(t, filepath.Join(suite, "pressure.py")))
	qualifier := script.Read(t, filepath.Join(suite, "qualify.py"))
	runtime["qualify_sha256"] = digest(qualifier)
	runtime["qualify_path"] = fmt.Sprintf("/run/terrascale-d15/probes/%s/%s/qualify.py", manifest["repository_revision"], digest(qualifier))
	receipt := object{"schema": "terrascale.d15.probe-admission/v1", "repository": "TerraScale/ts-orchestrator", "source_revision": manifest["repository_revision"], "source_tree": strings.Repeat("a", 40), "release_tag": fmt.Sprintf("ci-%s-run-1", manifest["repository_revision"]), "run_id": 1, "run_number": 1, "workflow": "ci.yml", "job": producerJob, "job_id": 1, "attempt": 1, "probe_asset": probeAsset, "probe_bytes": len(qualifier), "probe_sha256": digest(qualifier), "publication_sha256": strings.Repeat("b", 64), "qualification_sha256": strings.Repeat("c", 64), "run_detail_sha256": strings.Repeat("d", 64), "job_log_sha256": strings.Repeat("e", 64)}
	pinnedFile(t, field(manifest, "probe_admission"), "receipt_path", "receipt_sha256", filepath.Join(root, "probe-admission.json"), jsonWire(t, receipt), 0600)
	field(field(manifest, "pressure"), "workload_cgroup")["io_device"] = "8:1"
	return manifest
}
func TestAllocationProfilePreflight(t *testing.T) {
	manifest := fullyPinnedAllocationManifest(t)
	got := validateManifest(t, manifest, true, false)
	count := 0
	for _, v := range got["reasons"].([]any) {
		if strings.Contains(v.(string), "allocations, not measured") {
			count++
		}
	}
	assertEqual(t, count, len(field(manifest, "memory_floor_evidence"))+2)
	assertEqual(t, validateManifest(t, manifest, true, true)["reasons"], []any{})
	got = validateManifest(t, manifest, false, true)
	if got["error"] != nil {
		t.Fatal(got)
	}
	evidence := filepath.Join(t.TempDir(), "evidence")
	wire := jsonWire(t, manifest)
	got = decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_runner.py", object{"manifest": manifest, "wire": string(wire), "hash": digest(wire), "evidence": evidence, "runner_state": object{"harness_sha256": strings.Repeat("a", 64), "run_id": "allocation-preflight-test", "results": []any{}, "memory_usage_samples": []any{}, "pressure_completed": false, "failure_observed": false, "recovery_observed": false, "oom_observed": false, "oom_restore_intent": nil, "oom_restore_unresolved_reason": nil, "oom_restore_cleanup_verified": false}}, `from pathlib import Path
from unittest import mock
roles = []
class StopAtFirstAdapter:
    def __init__(self, *_args):
        for key, value in a["runner_state"].items():
            setattr(self, key, value)
    def call(self, role, *_args, **_kwargs):
        roles.append(role)
        raise m.HarnessError("test stop after run preflight")
with mock.patch.object(m, "AdapterRunner", StopAtFirstAdapter):
    status = m.run_qualification(a["manifest"], a["wire"].encode(), a["hash"], Path(a["evidence"]))
result = {"roles": roles, "status": status}`))
	assertEqual(t, got["roles"], []string{"target_identity"})
	assertEqual(t, got["status"], 1)
	summary := decodeObject(t, script.Read(t, filepath.Join(evidence, "summary.json")))
	assertEqual(t, summary["qualification_status"], "FAIL")
	assertEqual(t, summary["pressure_started"], false)
	floors := object{}
	for scope := range field(manifest, "memory_floor_evidence") {
		floors[scope] = "allocation"
	}
	assertEqual(t, field(summary, "memory_usage_sampling")["floor_basis_by_scope"], floors)
}
func TestAllocationRunStatusRequiresCompletionRecoveryAndSamples(t *testing.T) {
	phases := []string{}
	for _, role := range []string{"host", "controller"} {
		for _, phase := range []string{"before", "during", "after"} {
			phases = append(phases, role+":"+phase)
		}
	}
	for _, tc := range []struct {
		name, status, reason, scenario string
		complete, recovery             bool
		phases                         []string
	}{{"complete", "PASS", "", "terrabase_oom", true, true, phases}, {"unfinished", "FAIL", "full configured duration", "terrabase_oom", false, true, phases}, {"unrecovered", "FAIL", "recovery evidence", "terrabase_oom", true, false, phases}, {"missing_controller_before", "UNQUALIFIED", "before", "management_stability", true, false, append(append([]string{}, phases[:3]...), phases[4:]...)}} {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_runner.py", object{"complete": tc.complete, "recovery": tc.recovery, "scenario": tc.scenario, "phases": tc.phases}, `status, reasons = m.evaluate_run_status([], pressure_started=True, pressure_completed=a["complete"], scenario=a["scenario"], recovery_observed=a["recovery"], memory_sample_phases=set(a["phases"]))
result = {"status": status, "reasons": reasons}`))
			assertEqual(t, got["status"], tc.status)
			if tc.reason == "" {
				assertEqual(t, got["reasons"], []any{})
			} else {
				assertContains(t, reasonsText(got), tc.reason)
			}
		})
	}
}

func sampleTimestamp(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05.000Z") }
func sealSample(t *testing.T, sample object) {
	t.Helper()
	delete(sample, "sample_sha256")
	raw, err := json.Marshal(sample, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	sample["sample_sha256"] = digest(raw)
}
func newMemorySample(t *testing.T, manifest object, started, finished time.Time) object {
	t.Helper()
	identity := field(manifest, "identity")
	scopes := object{}
	for name, row := range map[string]struct {
		path  string
		inode int
	}{"host_service": {hostServicePath, 101}, "system_slice": {"/sys/fs/cgroup/system.slice", 100}} {
		raw := "anon 10\nfile 20\n"
		scopes[name] = object{"cgroup_path": row.path, "cgroup_inode": row.inode, "memory_current_raw": "30\n", "memory_current_bytes": 30, "memory_peak_raw": "40\n", "memory_peak_bytes": 40, "memory_stat_raw": raw, "memory_stat_sha256": digest([]byte(raw))}
	}
	sample := object{"schema": "terrascale.d15.memory-usage-sample/v2", "guest_role": "host", "host_boot_id": sampleBoot, "kernel_release": "6.8.0-test", "systemd_version": sampleSystemd, "started_at_utc": sampleTimestamp(started), "finished_at_utc": sampleTimestamp(finished), "scopes": scopes, "system_slice_direct_child_cgroups": []string{"terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service"}}
	for _, key := range []string{"oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id"} {
		sample[key] = identity[key]
	}
	sealSample(t, sample)
	return sample
}
func validateMemorySample(t *testing.T, sample, identity object, role, path string, started, finished time.Time) object {
	t.Helper()
	return observePressure(t, object{"sample": sample, "identity": identity, "role": role, "path": path, "before": sampleTimestamp(started.Add(-time.Second)), "after": sampleTimestamp(finished.Add(time.Second)), "boot": sampleBoot, "systemd": sampleSystemd}, `result = m.validate_memory_usage_sample(a["sample"], identity=a["identity"], guest_role=a["role"], expected_service_cgroup=a["path"], expected_boot_id=a["boot"], expected_systemd_version=a["systemd"], not_before=m.parse_timestamp(a["before"], "before"), not_after=m.parse_timestamp(a["after"], "after"))`)
}
func TestMemorySampleIdentityAndRawEvidence(t *testing.T) {
	manifest := exampleManifest(t)
	started := time.Now().Add(-2 * time.Second)
	finished := started.Add(time.Second)
	sample := newMemorySample(t, manifest, started, finished)
	identity := field(manifest, "identity")
	assertEqual(t, validateMemorySample(t, sample, identity, "host", hostServicePath, started, finished)["sample_sha256"], sample["sample_sha256"])
	cases := []struct {
		name, reason string
		change       func(object)
		seal         bool
	}{
		{"service_path", "exact unit scope", func(s object) {
			field(field(s, "scopes"), "host_service")["cgroup_path"] = "/sys/fs/cgroup/user.slice/host.service"
		}, true},
		{"stale", "stale", func(s object) {
			s["started_at_utc"] = "2020-01-01T00:00:00.000Z"
			s["finished_at_utc"] = "2020-01-01T00:00:01.000Z"
		}, true},
		{"duplicate_stat", "repeats key", func(s object) {
			r := field(field(s, "scopes"), "host_service")
			r["memory_stat_raw"] = "anon 10\nanon 20\n"
			r["memory_stat_sha256"] = digest([]byte(r["memory_stat_raw"].(string)))
		}, true},
		{"oversized_stat", "fixed evidence bound", func(s object) {
			r := field(field(s, "scopes"), "host_service")
			r["memory_stat_raw"] = strings.Repeat("anon 1\n", 16384/len("anon 1\n")+1)
			r["memory_stat_sha256"] = digest([]byte(r["memory_stat_raw"].(string)))
		}, true},
		{"oversized_counter", "fixed evidence bound", func(s object) {
			r := field(field(s, "scopes"), "host_service")
			raw := strings.Repeat("9", 128)
			for _, key := range []string{"current", "peak"} {
				r["memory_"+key+"_raw"] = raw + "\n"
				r["memory_"+key+"_bytes"] = jsontext.Value(raw)
			}
		}, true},
		{"child_count", "fixed evidence bound", func(s object) {
			children := []string{}
			for i := range 257 {
				children = append(children, fmt.Sprintf("child-%03d", i))
			}
			s["system_slice_direct_child_cgroups"] = children
		}, true},
		{"child_name_bytes", "fixed evidence bound", func(s object) { s["system_slice_direct_child_cgroups"] = []string{strings.Repeat("x", 16385)} }, true},
		{"hash", "sample hash", func(s object) { s["sample_sha256"] = strings.Repeat("0", 64) }, false},
	}
	for key, value := range map[string]string{"oci_instance_id": "ocid1.instance.oc1.test-other-instance", "image_id": "ocid1.image.oc1.test-other-image", "artifact_id": "other-artifact", "config_id": "other-config", "profile_id": "preview-other-profile", "host_boot_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"} {
		cases = append(cases, struct {
			name, reason string
			change       func(object)
			seal         bool
		}{key, "", func(s object) { s[key] = value }, true})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := cloneObject(t, sample)
			tc.change(changed)
			if tc.seal {
				sealSample(t, changed)
			}
			got := validateMemorySample(t, changed, identity, "host", hostServicePath, started, finished)
			assertPressureError(t, got, tc.reason)
		})
	}
	controller := cloneObject(t, sample)
	controllerIdentity := field(manifest, "controller_identity")
	for _, key := range []string{"oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id"} {
		controller[key] = controllerIdentity[key]
	}
	controller["guest_role"] = "controller"
	scopes := field(controller, "scopes")
	scopes["controller_service"] = scopes["host_service"]
	delete(scopes, "host_service")
	field(scopes, "controller_service")["cgroup_path"] = controllerServicePath
	sealSample(t, controller)
	assertEqual(t, validateMemorySample(t, controller, controllerIdentity, "controller", controllerServicePath, started, finished), controller)
	controller["oci_instance_id"] = identity["oci_instance_id"]
	sealSample(t, controller)
	assertPressureError(t, validateMemorySample(t, controller, controllerIdentity, "controller", controllerServicePath, started, finished), "oci_instance_id")
}

const runnerQualifierObservation = `
from pathlib import Path
runner = m.AdapterRunner(a["manifest"], a["hash"], Path(a["evidence_dir"]))
runner.host_snapshot = a["host_snapshot"]
runner.service_snapshot = a["service_snapshot"]
observations = []
for call in a["calls"]:
    try:
        runner._validate_qualifier(call["evidence"], a["request"], a["observed"], call["phase"])
        observations.append({"samples": list(runner.memory_usage_samples)})
    except Exception as error:
        observations.append({"error": str(error), "error_type": type(error).__name__, "samples": list(runner.memory_usage_samples)})
result = {"observations": observations}
`

func qualifierSummaryDigest(t *testing.T, summary object) string {
	t.Helper()
	raw, err := json.Marshal(summary, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		t.Fatal(err)
	}
	return digest(append(raw, '\n'))
}
func TestRunnerRetainsOnlyIdentityBoundMemorySamples(t *testing.T) {
	manifest := exampleManifest(t)
	started := time.Now().Add(-2 * time.Second)
	finished := started.Add(time.Second)
	sample := newMemorySample(t, manifest, started, finished)
	identity := field(manifest, "identity")
	qualification := field(manifest, "qualification")
	unit := "terrascale-orchestrator-host.service"
	rolePath := "/system.slice/" + unit + "/supervisor/runner/terrabase"
	summary := object{"status": "PASS", "guest_role": "host", "qualifier_sha256": field(field(manifest, "transport"), "runtime")["qualify_sha256"], "unit_sha256": object{unit: strings.Repeat("2", 64)}, "systemd_version": sampleSystemd, "memory_profile": object{"host_memory_min_bytes": qualification["expected_memory_min_bytes"], "host_memory_low_bytes": qualification["expected_memory_low_bytes"], "system_slice_memory_min_bytes": qualification["expected_system_slice_memory_min_bytes"], "system_slice_memory_low_bytes": qualification["expected_system_slice_memory_low_bytes"], "system_reserve_bytes": qualification["system_reserve_bytes"], "allocatable_memory_bytes": qualification["allocatable_memory_bytes"]}, "processes": object{"host_supervisor": object{"pid": 70, "process_start_time": "700"}, "terrabase": object{"pid": 77, "cgroup": rolePath}}, "cgroups": object{"host_service": hostServicePath, "native_runner": hostServicePath + "/supervisor/runner", "roles": object{"terrabase": object{"memory": object{"memory_max": fmt.Sprintf("%.0f", qualification["database_memory_max_bytes"])}}}}, "memory_usage_sample": sample, "started_at_utc": sampleTimestamp(started.Add(-100 * time.Millisecond)), "finished_at_utc": sampleTimestamp(finished.Add(100 * time.Millisecond))}
	for _, key := range []string{"oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id"} {
		summary[key] = identity[key]
	}
	request := object{"request_id": "memory-sample-request", "guest_role": "host", "sent_at_utc": sampleTimestamp(started.Add(-time.Second))}
	commands := "$ systemctl show\n"
	evidence := object{"summary": summary, "probe_evidence": object{"fresh_for_request_id": request["request_id"], "summary_sha256": qualifierSummaryDigest(t, summary), "commands_log": commands, "commands_sha256": digest([]byte(commands))}}
	wrong := cloneObject(t, evidence)
	wrongSample := field(field(wrong, "summary"), "memory_usage_sample")
	wrongSample["profile_id"] = "wrong-profile"
	sealSample(t, wrongSample)
	field(wrong, "probe_evidence")["summary_sha256"] = qualifierSummaryDigest(t, field(wrong, "summary"))
	args := object{"manifest": manifest, "hash": strings.Repeat("a", 64), "evidence_dir": t.TempDir(), "host_snapshot": object{"members": object{"source": object{"host_boot_id": sampleBoot, "managed_identity": object{"pid": 77, "cgroup": rolePath}}}}, "service_snapshot": object{unit: object{"main_pid": 70, "process_start": "700", "control_group": "/system.slice/" + unit, "host_boot_id": sampleBoot}}, "request": request, "observed": sampleTimestamp(time.Now()), "calls": []object{{"phase": "before", "evidence": evidence}, {"phase": "during", "evidence": wrong}}}
	got := decodeObject(t, script.Python(t, "tests/runtime_priority/alpha_runner.py", args, runnerQualifierObservation))
	observations := got["observations"].([]any)
	expected := []object{{"phase": "before", "guest_role": "host", "request_id": request["request_id"], "sample_sha256": sample["sample_sha256"]}}
	first := observations[0].(map[string]any)
	if first["error"] != nil {
		t.Fatal(first)
	}
	assertEqual(t, first["samples"], expected)
	second := observations[1].(map[string]any)
	assertPressureError(t, second, "profile_id differs")
	assertEqual(t, second["samples"], expected)
}

const qualifierCaptureObservation = `
import os, types
from pathlib import Path
from unittest import mock
import pressure
root, proc = Path(a["root"]), Path(a["proc"])
system_slice, host = root / "system.slice", root / "system.slice" / a["unit"]
probe = m.Probe(types.SimpleNamespace(**a["identity"]))
visited = []
replaced = False
original_iterdir, original_open = Path.iterdir, os.open
def tracked_iterdir(path):
    for child in original_iterdir(path):
        if path == system_slice:
            visited.append(str(child))
        yield child
def replace_after_open(path, flags, *args, **kwargs):
    global replaced
    fd = original_open(path, flags, *args, **kwargs)
    if not replaced and isinstance(path, Path) and path == host and flags & os.O_DIRECTORY:
        host.rename(system_slice / "replaced-host.service")
        host.mkdir()
        replaced = True
    return fd
patches = [mock.patch.object(m, "CGROUP_ROOT", root), mock.patch.object(m, "PROC_ROOT", proc), mock.patch.object(pressure, "CGROUP_ROOT", root)]
if a["mode"] == "bound":
    patches.append(mock.patch.object(Path, "iterdir", tracked_iterdir))
if a["mode"] == "replacement":
    patches.append(mock.patch.object(m.os, "open", replace_after_open))
import contextlib
with contextlib.ExitStack() as stack:
    for patch in patches:
        stack.enter_context(patch)
    try:
        sample = probe.memory_usage_sample({"host_service": host, "system_slice": system_slice}, a["systemd"])
        result = {"sample": sample}
    except Exception as error:
        result = {"error": str(error), "error_type": type(error).__name__}
result.update({"visited": len(visited), "replaced": replaced})
`

func TestPackagedQualifierCapturesBoundedStableCgroups(t *testing.T) {
	for _, mode := range []string{"exact", "bound", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			manifest := exampleManifest(t)
			identity := cloneObject(t, field(manifest, "identity"))
			identity["role"] = "host"
			temp := t.TempDir()
			root := filepath.Join(temp, "cgroup")
			system := filepath.Join(root, "system.slice")
			host := filepath.Join(system, "terrascale-orchestrator-host.service")
			controller := filepath.Join(system, "terrascale-orchestrator-controller.service")
			proc := filepath.Join(temp, "proc")
			for _, path := range []string{host, controller} {
				for name, raw := range map[string]string{"memory.current": "123\n", "memory.peak": "456\n", "memory.stat": "anon 12\nfile 34\n"} {
					script.Write(t, filepath.Join(path, name), []byte(raw), 0600)
				}
			}
			if mode != "replacement" {
				for name, raw := range map[string]string{"memory.current": "789\n", "memory.peak": "900\n", "memory.stat": "anon 56\nfile 78\n"} {
					script.Write(t, filepath.Join(system, name), []byte(raw), 0600)
				}
			}
			if mode == "bound" {
				for i := range 300 {
					if err := os.Mkdir(filepath.Join(system, fmt.Sprintf("child-%03d.scope", i)), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			script.Write(t, filepath.Join(proc, "sys/kernel/random/boot_id"), []byte(sampleBoot+"\n"), 0600)
			got := decodeObject(t, script.Python(t, "tests/runtime_priority/qualify.py", object{"root": root, "proc": proc, "unit": filepath.Base(host), "identity": identity, "systemd": sampleSystemd, "mode": mode}, qualifierCaptureObservation))
			switch mode {
			case "exact":
				if got["error"] != nil {
					t.Fatal(got)
				}
				sample := field(got, "sample")
				started, err := time.Parse(time.RFC3339Nano, sample["started_at_utc"].(string))
				if err != nil {
					t.Fatal(err)
				}
				finished, err := time.Parse(time.RFC3339Nano, sample["finished_at_utc"].(string))
				if err != nil {
					t.Fatal(err)
				}
				validated := observePressure(t, object{"sample": sample, "root": root, "identity": identity, "path": host, "before": sampleTimestamp(started), "after": sampleTimestamp(finished), "boot": sampleBoot, "systemd": sampleSystemd}, `from pathlib import Path
m.CGROUP_ROOT = Path(a["root"])
result = m.validate_memory_usage_sample(a["sample"], identity=a["identity"], guest_role="host", expected_service_cgroup=a["path"], expected_boot_id=a["boot"], expected_systemd_version=a["systemd"], not_before=m.parse_timestamp(a["before"], "before"), not_after=m.parse_timestamp(a["after"], "after"))`)
				if validated["error"] != nil {
					t.Fatal(validated)
				}
				assertEqual(t, field(field(validated, "scopes"), "host_service")["memory_current_raw"], "123\n")
				assertEqual(t, field(field(validated, "scopes"), "system_slice")["memory_peak_bytes"], 900)
				assertContains(t, fmt.Sprint(validated["system_slice_direct_child_cgroups"]), filepath.Base(host))
			case "bound":
				assertRuntimeError(t, got, "QualificationError", "evidence bound")
				if got["visited"].(float64) >= 303 {
					t.Fatalf("enumerated all children: %v", got)
				}
			case "replacement":
				assertRuntimeError(t, got, "QualificationError", "changed before capture")
				assertEqual(t, got["replaced"], true)
			}
		})
	}
}

// A rejected observation must retain the implementation's domain error type.
// An unrelated adapter failure is not evidence that a security guard ran.
func assertRuntimeError(t *testing.T, got object, errorType, reason string) {
	t.Helper()
	if got["error_type"] != errorType {
		t.Fatalf("want %s containing %q, got %#v", errorType, reason, got)
	}
	assertContains(t, fmt.Sprint(got["error"]), reason)
}
func assertPressureError(t *testing.T, got object, reason string) {
	t.Helper()
	assertRuntimeError(t, got, "HarnessError", reason)
}

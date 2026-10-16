package runtimepriority

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rp "github.com/TerraScale/ts-orchestrator/internal/runtimepriority"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

const hostServicePath = "/sys/fs/cgroup/system.slice/terrascale-orchestrator-host.service"
const controllerServicePath = "/sys/fs/cgroup/system.slice/terrascale-orchestrator-controller.service"
const sampleBoot = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const sampleSystemd = "systemd 255 (test)"

func exampleManifest(t *testing.T) object {
	t.Helper()
	return decodeObject(t, script.Read(t, filepath.Join(script.Root(t), "tests/runtime_priority/example-dry-run.json")))
}
func cloneObject(t *testing.T, o object) object { t.Helper(); return decodeObject(t, jsonWire(t, o)) }
func errorObservation(err error) object {
	if err == nil {
		return object{}
	}
	return object{"error": err.Error(), "error_type": rp.ErrorType(err)}
}
func normalize(t *testing.T, value any) object {
	t.Helper()
	return decodeObject(t, jsonWire(t, value))
}
func validateManifest(t *testing.T, m object, dry, allocations bool) object {
	t.Helper()
	reasons, err := rp.ValidateManifest(m, dry, allocations)
	if err != nil {
		return errorObservation(err)
	}
	return normalize(t, object{"reasons": reasons})
}
func reasonsText(o object) string { return fmt.Sprint(o["reasons"]) }
func TestPressureDryRunAndUnqualifiedEvidence(t *testing.T) {
	manifest := exampleManifest(t)
	got := validateManifest(t, manifest, true, false)
	for _, reason := range []string{"OCI owner has not explicitly authorized live pressure", "host_service memory floors are allocations, not measured floors", "operator executable pin"} {
		assertContains(t, reasonsText(got), reason)
	}
	manifestPath := filepath.Join(script.Root(t), "tests/runtime_priority/example-dry-run.json")
	wire := script.Read(t, manifestPath)
	plan, err := rp.DryRun(manifest, digest(wire))
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, plan["schema"], manifest["schema"])
	assertEqual(t, plan["qualification_status"], "UNQUALIFIED")
	assertEqual(t, plan["commands_executed"], false)
	assertEqual(t, plan["pressure_started"], false)
	evidence := filepath.Join(t.TempDir(), "evidence")
	spawns := 0
	var out bytes.Buffer
	status, err := rp.RunQualification(t.Context(), manifest, wire, digest(wire), evidence, func(context.Context, rp.Object) (rp.Object, error) {
		spawns++
		return nil, fmt.Errorf("unexpected adapter")
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, status, 1)
	assertEqual(t, spawns, 0)
	summary := decodeObject(t, script.Read(t, filepath.Join(evidence, "summary.json")))
	assertEqual(t, summary["qualification_status"], "UNQUALIFIED")
	assertEqual(t, summary["commands_executed"], false)
	assertEqual(t, summary["pressure_started"], false)
	assertEqual(t, string(script.Read(t, filepath.Join(evidence, "manifest.json"))), string(wire))
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
	auth := field(manifest, "authorization")
	auth["live_stress_authorized"] = true
	pinnedFile(t, auth, "owner_handoff_path", "owner_handoff_sha256", filepath.Join(root, "owner-handoff.json"), []byte("owner-authorized qualification handoff\n"), 0600)
	adapterPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	adapterHash := digest(script.Read(t, adapterPath))
	contract := field(manifest, "adapter_contract")
	contract["id"] = "frozen-alpha-d15-test"
	contract["frozen"] = true
	contract["source_path"] = adapterPath
	contract["source_sha256"] = adapterHash
	adapter := field(manifest, "adapter")
	adapter["executable_path"] = adapterPath
	adapter["executable_sha256"] = adapterHash
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
	runtime["stress_launcher_sha256"] = adapterHash
	qualifier := script.Read(t, adapterPath)
	runtime["qualify_sha256"] = digest(qualifier)
	runtime["qualify_path"] = fmt.Sprintf("/run/terrascale-d15/probes/%s/%s/qualify", manifest["repository_revision"], digest(qualifier))
	runtime["remote_executable_path"] = runtime["qualify_path"]
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
	roles := []string{}
	var out bytes.Buffer
	status, err := rp.RunQualification(t.Context(), manifest, wire, digest(wire), evidence, func(_ context.Context, request rp.Object) (rp.Object, error) {
		roles = append(roles, request["role"].(string))
		return nil, fmt.Errorf("test stop after run preflight")
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	got = normalize(t, object{"roles": roles, "status": status})
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
			status, reasons := rp.EvaluateRunStatus(nil, true, tc.complete, tc.scenario, tc.recovery, tc.phases)
			got := normalize(t, object{"status": status, "reasons": reasons})
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
	value, err := rp.ValidateMemorySample(sample, rp.MemoryValidation{Identity: identity, GuestRole: role, ServiceCgroup: path, BootID: sampleBoot, SystemdVersion: sampleSystemd, NotBefore: started.Add(-time.Second), NotAfter: finished.Add(time.Second)})
	if err != nil {
		return errorObservation(err)
	}
	return normalize(t, value)
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
	runner := rp.NewRunner(manifest, args["hash"].(string), args["evidence_dir"].(string))
	runner.State["host_snapshot"], runner.State["service_snapshot"] = args["host_snapshot"], args["service_snapshot"]
	observed := []object{}
	for _, call := range args["calls"].([]object) {
		err := runner.ValidateQualifier(field(call, "evidence"), request, args["observed"].(string), call["phase"].(string))
		item := errorObservation(err)
		item["samples"] = append([]any{}, runner.State["memory_usage_samples"].([]any)...)
		observed = append(observed, item)
	}
	got := normalize(t, object{"observations": observed})
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
			visited, replaced := 0, false
			probe := rp.Qualifier{Args: identity, CgroupRoot: root, ProcRoot: proc}
			if mode == "bound" {
				probe.ChildVisited = func(string) { visited++ }
			}
			if mode == "replacement" {
				probe.AfterDirectoryOpen = func(path string) {
					if path == host && !replaced {
						if err := os.Rename(host, filepath.Join(system, "replaced-host.service")); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(host, 0700); err != nil {
							t.Fatal(err)
						}
						replaced = true
					}
				}
			}
			sample, err := probe.CaptureMemorySample(map[string]string{"host_service": host, "system_slice": system}, sampleSystemd)
			got := errorObservation(err)
			if err == nil {
				got["sample"] = sample
			}
			got["visited"], got["replaced"] = visited, replaced
			got = normalize(t, got)
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
				value, err := rp.ValidateMemorySample(sample, rp.MemoryValidation{Identity: identity, GuestRole: "host", CgroupRoot: root, ServiceCgroup: host, BootID: sampleBoot, SystemdVersion: sampleSystemd, NotBefore: started, NotAfter: finished})
				validated := errorObservation(err)
				if err == nil {
					validated = normalize(t, value)
				}
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

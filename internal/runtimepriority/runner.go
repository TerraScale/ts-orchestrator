package runtimepriority

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

type Runner struct {
	Manifest, State Object
	EvidenceDir     string
	AdapterCall     func(context.Context, Object) (Object, error)
}

func NewRunner(manifest Object, hash, evidence string) *Runner {
	binary, _ := os.Executable()
	wire, _, _ := readNoFollow(binary, MaxProbeBytes)
	return &Runner{Manifest: manifest, EvidenceDir: evidence, State: Object{"manifest_hash": hash, "run_id": entityid.New(), "harness_sha256": sub(sub(manifest, "transport"), "runtime")["stress_launcher_sha256"], "runner_sha256": Hash(wire), "results": []any{}, "memory_usage_samples": []any{}, "previous_host_rows": Object{}, "baseline_host_rows": Object{}, "previous_services": Object{}, "baseline_services": Object{}, "probe_fingerprint": Object{}, "last_event_sequence_by_origin": Object{}, "pressure_processes": Object{}, "pressure_completed": false, "failure_observed": false, "recovery_observed": false, "oom_observed": false, "oom_restore_cleanup_verified": false}}
}
func (r *Runner) stateObject(k string) Object {
	if o, ok := r.State[k].(map[string]any); ok {
		return o
	}
	o := Object{}
	r.State[k] = o
	return o
}
func (r *Runner) appendState(k string, v any) { a, _ := r.State[k].([]any); r.State[k] = append(a, v) }
func (r *Runner) member() Object              { return sub(r.Manifest, "managed_member") }
func (r *Runner) pressure() Object            { return sub(r.Manifest, "pressure") }
func (r *Runner) qualification() Object       { return sub(r.Manifest, "qualification") }
func (r *Runner) snapshot() Object            { return obj(r.State["host_snapshot"], "current host snapshot") }
func pretty(v any) []byte {
	b, e := json.Marshal(v, json.Deterministic(true), jsontext.WithIndent("  "))
	if e != nil {
		fail("cannot encode evidence: %v", e)
	}
	return append(b, '\n')
}
func (r *Runner) ValidateQualifier(evidence, request Object, observed, phase string) (err error) {
	defer recoverError(&err)
	r.validateQualifier(evidence, request, observed, phase)
	return
}
func (r *Runner) validateQualifier(evidence, request Object, observed, phase string) {
	summary, probe := sub(evidence, "summary"), sub(evidence, "probe_evidence")
	if str(summary, "status") != "PASS" || probe["fresh_for_request_id"] != request["request_id"] {
		fail("qualify adapter must return fresh packaged probe PASS")
	}
	if Hash(pretty(summary)) != str(probe, "summary_sha256") || Hash([]byte(str(probe, "commands_log"))) != str(probe, "commands_sha256") {
		fail("qualify summary/commands log differs from exact content hashes")
	}
	role := str(request, "guest_role")
	if str(summary, "guest_role") != role {
		fail("qualifier guest role differs from pinned request")
	}
	identity, q, unit := sub(r.Manifest, "identity"), r.qualification(), HostUnit
	if role == "controller" {
		identity, q, unit = sub(r.Manifest, "controller_identity"), sub(r.Manifest, "controller_qualification"), ControllerUnit
	}
	units := sub(summary, "unit_sha256")
	if summary["qualifier_sha256"] != sub(sub(r.Manifest, "transport"), "runtime")["qualify_sha256"] || !exact(units, unit) || !hashRE.MatchString(str(units, unit)) {
		fail("qualify summary probe digest differs from CI pin or omits role unit hash")
	}
	fingerprint := Object{"qualifier_sha256": summary["qualifier_sha256"], "unit_sha256": units, "systemd_version": summary["systemd_version"]}
	fingerprints := r.stateObject("probe_fingerprint")
	if old := fingerprints[role]; old != nil && !same(old, fingerprint) {
		fail("%s qualifier or systemd unit identity changed during D15", role)
	}
	for _, k := range []string{"oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id"} {
		if summary[k] != identity[k] {
			fail("%s qualify summary %s differs from pinned target", role, k)
		}
	}
	profile := sub(summary, "memory_profile")
	prefix := "expected_memory_"
	if role == "controller" {
		prefix = "expected_controller_memory_"
	}
	expected := Object{role + "_memory_min_bytes": q[prefix+"min_bytes"], role + "_memory_low_bytes": q[prefix+"low_bytes"], "system_slice_memory_min_bytes": q["expected_system_slice_memory_min_bytes"], "system_slice_memory_low_bytes": q["expected_system_slice_memory_low_bytes"], "system_reserve_bytes": q["system_reserve_bytes"], "allocatable_memory_bytes": q["allocatable_memory_bytes"]}
	for k, w := range expected {
		if !same(profile[k], w) {
			fail("%s qualify summary %s differs from pinned profile values", role, k)
		}
	}
	services := r.stateObject("service_snapshot")
	service := obj(services[unit], role+" qualification current service witness")
	processes, cgroups := sub(summary, "processes"), sub(summary, "cgroups")
	processKey := "host_supervisor"
	if role == "controller" {
		processKey = "controller"
	}
	process := sub(processes, processKey)
	if !same(process["pid"], service["main_pid"]) || process["process_start_time"] != service["process_start"] {
		fail("%s qualifier process differs from witnessed unit process", role)
	}
	servicePath := text(cgroups[role+"_service"], role+" service cgroup")
	if servicePath != filepath.Join(CgroupRoot, str(service, "control_group")) {
		fail("%s qualifier cgroup differs from witnessed unit", role)
	}
	if role == "host" {
		current := sub(sub(sub(r.snapshot(), "members"), "source"), "managed_identity")
		database := sub(processes, "terrabase")
		if !same(database["pid"], current["pid"]) || database["cgroup"] != current["cgroup"] {
			fail("priority probe TerraBase identity differs from accepted host report")
		}
		native, db, dbRole := qualifiedRoleCgroups(str(cgroups, "native_runner"), str(database, "cgroup"))
		roles := sub(cgroups, "roles")
		if str(sub(sub(roles, dbRole), "memory"), "memory_max") != strconv.FormatInt(n(r.qualification(), "database_memory_max_bytes"), 10) {
			fail("TerraBase cgroup memory.max differs from signed profile cap")
		}
		if r.State["native_runner_path"] != nil && (r.State["native_runner_path"] != native || r.State["database_cgroup_path"] != db) {
			fail("native runner or TerraBase cgroup path changed during qualification")
		}
		r.State["native_runner_path"], r.State["database_cgroup_path"] = native, db
	} else {
		if !exact(processes, "controller") || !exact(cgroups, "controller_service", "controller_weights", "controller_cpu_max") || !strings.HasPrefix(str(cgroups, "controller_cpu_max"), "max ") {
			fail("controller qualifier must contain only controller role state")
		}
	}
	sent, start, finish, obs := timestamp(request["sent_at_utc"], "qualify sent"), timestamp(summary["started_at_utc"], "qualify start"), timestamp(summary["finished_at_utc"], "qualify finish"), timestamp(observed, "qualify observed")
	if sent.After(start) || start.After(finish) || finish.After(obs) {
		fail("priority probe stale or outside exact request window")
	}
	sample, e := ValidateMemorySample(sub(summary, "memory_usage_sample"), MemoryValidation{Identity: identity, GuestRole: role, ServiceCgroup: servicePath, BootID: str(service, "host_boot_id"), SystemdVersion: str(summary, "systemd_version"), NotBefore: sent, NotAfter: finish})
	if e != nil {
		panic(e)
	}
	fingerprints[role] = fingerprint
	r.appendState("memory_usage_samples", Object{"phase": phase, "guest_role": role, "request_id": request["request_id"], "sample_sha256": sample["sample_sha256"]})
}
func (r *Runner) FailureTarget() (target Object, err error) {
	defer recoverError(&err)
	target = r.failureTarget()
	return
}
func (r *Runner) terrabaseTarget() Object {
	snapshot := r.snapshot()
	row := sub(sub(snapshot, "members"), "source")
	w := sub(sub(snapshot, "process_witnesses"), "source")
	managed := sub(sub(row, "report"), "managed")
	return Object{"kind": "terrabase", "node": sub(r.member(), "source")["node"], "pid": managed["process_pid"], "process_start": managed["process_start"], "process_nonce": managed["process_boot_id"], "cgroup": managed["process_cgroup"], "host_boot_id": w["host_boot_id"], "stat_raw": w["stat_raw"], "cgroup_raw": w["cgroup_raw"]}
}
func (r *Runner) failureTarget() Object {
	scenario := str(r.pressure(), "scenario")
	source := sub(sub(r.snapshot(), "members"), "source")
	maxAge := time.Duration(n(sub(r.Manifest, "adapter_contract"), "target_witness_max_age_ms")) * time.Millisecond
	age := time.Since(reportTime(source, "report_time"))
	if age < 0 || age > maxAge {
		fail("accepted TerraBase report/process witness stale before SIGKILL")
	}
	if scenario == "terrabase_process" || scenario == "terrabase_oom" {
		if scenario == "terrabase_oom" {
			fail("TerraBase OOM observed from kernel; pressure workers are not injected victims")
		}
		target := r.terrabaseTarget()
		native, db, _ := qualifiedRoleCgroups(str(r.State, "native_runner_path"), str(target, "cgroup"))
		if native != str(r.State, "native_runner_path") || db != str(r.State, "database_cgroup_path") {
			fail("TerraBase SIGKILL target differs from the qualifier-pinned native role cgroup")
		}
		return target
	}
	if scenario != "host_manager_sigkill" {
		fail("failure target not approved scenario")
	}
	unit := sub(r.stateObject("service_snapshot"), HostUnit)
	unitAge := time.Since(reportTime(unit, "observed_at"))
	if unitAge < 0 || unitAge > maxAge {
		fail("host manager and accepted managed report witnesses stale before SIGKILL")
	}
	return Object{"kind": "host_manager", "unit": HostUnit, "pid": unit["main_pid"], "process_start": unit["process_start"], "cgroup": strings.TrimSuffix(str(unit, "control_group"), "/") + "/supervisor", "host_boot_id": source["host_boot_id"], "stat_raw": unit["process_stat_raw"], "cgroup_raw": unit["process_cgroup_raw"]}
}
func (r *Runner) ValidateRole(role, phase string, request, response Object) (err error) {
	defer recoverError(&err)
	r.validateRole(role, phase, request, response)
	return
}
func (r *Runner) validateRole(role, phase string, request, response Object) {
	evidence := sub(response, "evidence")
	observed := str(response, "observed_at_utc")
	if e := r.ValidateActiveObservation(role, phase, observed); e != nil {
		panic(e)
	}
	switch role {
	case "target_identity":
		r.validateTarget(evidence)
	case "host_status":
		snapshot, e := ValidateReportEvidence(evidence, request, observed, r.member(), r.stateObject("previous_host_rows"))
		if e != nil {
			panic(e)
		}
		members := sub(snapshot, "members")
		previous := r.stateObject("previous_host_rows")
		for label, v := range members {
			if old, ok := previous[label].(map[string]any); ok {
				validatePrevious(snapshot, label, old, request)
			}
			previous[label] = v
		}
		if len(r.stateObject("baseline_host_rows")) == 0 {
			r.State["baseline_host_rows"] = clone(members)
		}
		r.State["host_snapshot"] = snapshot
		if event, ok := r.State["last_event"].(map[string]any); ok {
			assertEventCovered(snapshot, r.member(), event, n(sub(r.State, "last_database_receipt"), "event_sequence"))
			r.State["last_event"] = nil
		}
	case "service_state":
		r.validateServices(evidence, request, observed, phase)
	case "qualify":
		r.validateQualifier(evidence, request, observed, phase)
	case "database_progress":
		receipt, e := ValidateDatabaseWire(evidence, request, r.member())
		if e != nil {
			panic(e)
		}
		event := sub(receipt, "event")
		origin := strings.Join([]string{str(event, "database"), str(event, "shard"), str(event, "replica"), str(event, "incarnation")}, "/")
		sequences := r.stateObject("last_event_sequence_by_origin")
		old := int64(0)
		if sequences[origin] != nil {
			old = num(sequences[origin], "prior event sequence", 0)
		}
		if n(receipt, "event_sequence") <= old {
			fail("ObjectDurable event sequence did not advance for exact origin/scope")
		}
		sequences[origin] = receipt["event_sequence"]
		r.State["last_database_receipt"], r.State["last_event"] = receipt, event
	case "pressure_start", "pressure_status":
		r.validatePressure(role, evidence, response, request)
	case "failure_inject":
		action := sub(evidence, "action_receipt")
		if !exact(action, "target_process", "signal", "requested_at_utc", "completed_at_utc", "exit_status") || !same(action["target_process"], request["target_process"]) || str(action, "signal") != "SIGKILL" || n(action, "exit_status") != 0 {
			fail("failure action did not target exact current TerraBase/host manager process")
		}
		sent, asked, done, obs := timestamp(request["sent_at_utc"], "failure sent"), timestamp(action["requested_at_utc"], "failure request"), timestamp(action["completed_at_utc"], "failure complete"), timestamp(observed, "failure observation")
		if sent.After(asked) || asked.After(done) || done.After(obs) {
			fail("failure timestamps outside exact request window")
		}
		r.State["failure_injection_at"], r.State["failure_observed"] = done, true
	case "kernel_oom_evidence":
		r.validateOOM(evidence, request, observed)
	case "pressure_stop":
		if evidence["handle"] != r.State["handle"] || !same(evidence["pressure_cgroup_process_pids"], []any{}) || str(evidence, "pressure_cgroup_procs_raw") != "" {
			fail("pressure stop did not prove exact workload cgroup empty")
		}
	case "cleanup_verify":
		cleanup := sub(evidence, "cleanup")
		if str(cleanup, "pressure_cgroup_procs_raw") != "" || !same(cleanup["pressure_child_cgroups"], []any{}) || !same(cleanup["scratch_paths"], []any{}) {
			fail("cleanup did not prove empty workload cgroup and removed scratch paths")
		}
		if intent, ok := r.State["oom_restore_intent"].(map[string]any); ok {
			restored := cleanup["oom_restore_verified"] == true && same(cleanup["oom_restore_target"], intent["target"]) && same(cleanup["oom_restore_cgroup_inode"], intent["cgroup_inode"]) && same(cleanup["current_database_memory_max_bytes"], r.qualification()["database_memory_max_bytes"])
			if !restored {
				reason := str(cleanup, "oom_restore_unresolved_reason")
				if reason == "" {
					reason = "cleanup could not verify exact native role cap"
				}
				r.State["oom_restore_unresolved_reason"] = reason
				fail("cleanup left native OOM restore obligation unresolved")
			}
			r.State["oom_restore_cleanup_verified"], r.State["oom_restore_unresolved_reason"] = true, nil
		}
	default:
		fail("unsupported adapter role %s", role)
	}
}
func (r *Runner) validateTarget(e Object) {
	if !exact(e, "operator_hosts_json", "operator_hosts_sha256", "architecture_by_member", "source_oci_metadata", "controller_oci_metadata") {
		fail("target identity evidence does not match alpha source schema")
	}
	hosts, ok := rawJSON(text(e["operator_hosts_json"], "target hosts JSON"), "target identity hosts JSON", str(e, "operator_hosts_sha256"), 1<<20).([]any)
	if !ok {
		fail("target identity HostStatus evidence must be array")
	}
	if !same(e["architecture_by_member"], Object{"source": "aarch64", "peer": "aarch64", "controller": "aarch64"}) {
		fail("SSH targets do not report pinned aarch64 architecture")
	}
	targets := sub(sub(sub(r.Manifest, "transport"), "ssh"), "targets")
	regs := Object{}
	regions := catalog.Map()
	for _, label := range []string{"source", "peer"} {
		want := sub(r.member(), label)
		count := 0
		for _, v := range hosts {
			host := obj(v, "target HostStatus")
			reg, ok := host["registration"].(map[string]any)
			if !ok {
				continue
			}
			binding, ok := reg["managed_member"].(map[string]any)
			if ok && reg["cell"] == want["cell"] && reg["node"] == want["node"] && reg["environment"] == want["environment"] && same(binding["scope"], want["scope"]) {
				if host["verified"] != false {
					fail("target identity lacks read-only admitted HostStatus")
				}
				oci := sub(reg, "managed_oci")
				if oci["instance_id"] != sub(targets, label)["oci_instance_id"] || regions[str(oci, "region")] == "" {
					fail("%s HostStatus does not match pinned OCI instance/region", label)
				}
				regs[label] = reg
				count++
			}
		}
		if count != 1 {
			fail("target identity lacks one read-only admitted %s HostStatus", label)
		}
	}
	region := regions[str(sub(sub(regs, "source"), "managed_oci"), "region")]
	for label, idKey := range map[string]string{"source": "identity", "controller": "controller_identity"} {
		metadata := sub(e, label+"_oci_metadata")
		id := sub(r.Manifest, idKey)
		if !exact(metadata, "instance_id", "image_id", "region", "shape") || metadata["instance_id"] != id["oci_instance_id"] || metadata["image_id"] != id["image_id"] || str(metadata, "region") != region || str(metadata, "shape") == "" {
			fail("live OCI metadata does not match the pinned %s instance, image and region", label)
		}
	}
}
func validatePrevious(snapshot Object, label string, old, request Object) {
	current := sub(sub(snapshot, "members"), label)
	scenario, phase := str(sub(request, "pressure"), "scenario"), str(request, "phase")
	if label == "source" && phase == "post_recovery" && (scenario == "terrabase_process" || scenario == "terrabase_oom") {
		a, b := sub(old, "managed_identity"), sub(current, "managed_identity")
		if same(a["pid"], b["pid"]) && a["start"] == b["start"] && a["nonce"] == b["nonce"] {
			fail("TerraBase recovery report did not advance actual process identity")
		}
		if a["cgroup"] != b["cgroup"] {
			fail("TerraBase recovery changed expected native workload role cgroup")
		}
	}
}
func (r *Runner) validateServices(evidence, request Object, observed, phase string) {
	role := str(evidence, "guest_role")
	if role != str(request, "guest_role") || (role != "host" && role != "controller") {
		fail("service_state guest role differs from request")
	}
	unit := HostUnit
	if role == "controller" {
		unit = ControllerUnit
	}
	if !exact(evidence, "guest_role", "units", "host_boot_id") || !exact(sub(evidence, "units"), unit) || !uuidRE.MatchString(str(evidence, "host_boot_id")) {
		fail("service_state evidence must contain exact systemd snapshots and boot ID")
	}
	boot := str(evidence, "host_boot_id")
	if role == "host" && r.State["host_snapshot"] != nil && sub(sub(r.snapshot(), "members"), "source")["host_boot_id"] != boot {
		fail("systemd and managed report witnesses disagree on source boot ID")
	}
	row := sub(sub(evidence, "units"), unit)
	if !exact(row, "systemctl_show_raw", "process_stat_raw", "process_cgroup_raw") {
		fail("service evidence must retain raw systemctl and /proc identity")
	}
	props := parseProperties(str(row, "systemctl_show_raw"), unit)
	for _, k := range []string{"ActiveState", "MainPID", "ControlGroup", "NRestarts"} {
		if _, ok := props[k]; !ok {
			fail("systemctl output omits required property")
		}
	}
	pid, rest := integerText(str(props, "MainPID"), "MainPID"), integerText(str(props, "NRestarts"), "NRestarts")
	if str(props, "ActiveState") != "active" || pid <= 1 || !safePath(str(props, "ControlGroup")) {
		fail("service not active in exact systemd cgroup")
	}
	actual, start := procStatIdentity(str(row, "process_stat_raw"))
	group := procCgroupPath(str(row, "process_cgroup_raw"))
	expected := str(props, "ControlGroup")
	if role == "host" {
		expected += "/supervisor"
	}
	if actual != pid || group != expected {
		fail("raw /proc identity differs from systemd MainPID/ControlGroup")
	}
	current := Object{"active_state": "active", "main_pid": pid, "control_group": props["ControlGroup"], "n_restarts": rest, "process_start": start, "process_stat_raw": row["process_stat_raw"], "process_cgroup_raw": row["process_cgroup_raw"], "host_boot_id": boot, "observed_at": timestamp(observed, "service observed")}
	baseline, previous := r.stateObject("baseline_services"), r.stateObject("previous_services")
	if old, ok := previous[unit].(map[string]any); ok {
		if old["control_group"] != current["control_group"] || old["host_boot_id"] != boot {
			fail("systemd cgroup or boot ID changed during D15")
		}
		restarted := unit == HostUnit && str(r.pressure(), "scenario") == "host_manager_sigkill" && slices.Contains([]string{"post_recovery", "after", "after_write"}, phase) && r.State["failure_observed"] == true
		if restarted {
			base := sub(baseline, unit)
			if rest <= n(base, "n_restarts") || (pid == n(base, "main_pid") && start == str(base, "process_start")) {
				fail("host manager restart count/process identity did not advance")
			}
		} else if pid != n(old, "main_pid") || start != str(old, "process_start") || rest != n(old, "n_restarts") {
			fail("service process identity/restart counter changed outside target scenario")
		}
	} else {
		baseline[unit] = current
	}
	previous[unit] = current
	r.stateObject("service_snapshot")[unit] = current
}
func EvaluateRunStatus(failures []string, started, completed bool, scenario string, recovery bool, phases []string) (string, []string) {
	if len(failures) > 0 {
		return "FAIL", failures
	}
	if !started {
		return "UNQUALIFIED", []string{"pressure did not start"}
	}
	if !completed {
		return "FAIL", []string{"all load workers did not complete the full configured duration"}
	}
	if scenario != "management_stability" && !recovery {
		return "FAIL", []string{"recovery evidence is incomplete"}
	}
	missing := []string{}
	for _, role := range []string{"host", "controller"} {
		for _, phase := range []string{"before", "during", "after"} {
			if !slices.Contains(phases, role+":"+phase) {
				missing = append(missing, role+":"+phase)
			}
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return "UNQUALIFIED", []string{"role-bound guest memory usage samples are missing phases: " + strings.Join(missing, ", ")}
	}
	return "PASS", []string{}
}

func (r *Runner) CompareServices(current Object, phase string) (err error) {
	defer recoverError(&err)
	for unit, value := range current {
		now := obj(value, "service snapshot")
		old := sub(r.stateObject("previous_services"), unit)
		if old["control_group"] != now["control_group"] {
			fail("%s systemd cgroup changed during D15 scenario", unit)
		}
		restart := unit == HostUnit && str(r.pressure(), "scenario") == "host_manager_sigkill" && slices.Contains([]string{"post_recovery", "after", "after_write"}, phase) && r.State["failure_observed"] == true
		if restart {
			baseline := sub(r.stateObject("baseline_services"), unit)
			if n(now, "n_restarts") <= n(baseline, "n_restarts") || (same(now["main_pid"], baseline["main_pid"]) && now["process_start"] == baseline["process_start"]) {
				fail("host manager systemd restart count/process identity did not advance")
			}
		} else if !same(now["main_pid"], old["main_pid"]) || now["process_start"] != old["process_start"] || !same(now["n_restarts"], old["n_restarts"]) {
			fail("%s process identity/restart counter changed outside its target scenario", unit)
		}
	}
	return
}

func (r *Runner) ValidateActiveObservation(role, phase, observed string) (err error) {
	defer recoverError(&err)
	activeWrite := role == "host_status" && phase == "after_write" && r.State["pressure_started_at"] != nil && r.State["pressure_completed"] != true
	if (phase == "during" && slices.Contains([]string{"service_state", "host_status", "qualify", "database_progress"}, role)) || activeWrite {
		obs := timestamp(observed, "pressure observation")
		if r.State["pressure_started_at"] == nil {
			fail("%s observation did not complete during active pressure", role)
		}
		start := reportTime(r.State, "pressure_started_at")
		if obs.Before(start) || !obs.Before(start.Add(time.Duration(n(r.pressure(), "duration_seconds"))*time.Second)) {
			fail("%s observation did not complete during active pressure", role)
		}
	}
	return
}

package runtimepriority

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func (r *Runner) ValidatePressure(role string, evidence, response, request Object) (err error) {
	defer recoverError(&err)
	r.validatePressure(role, evidence, response, request)
	return
}
func (r *Runner) validatePressure(role string, evidence, response, request Object) {
	initial := role == "pressure_start"
	if initial {
		if evidence["worker_harness_sha256"] != r.State["harness_sha256"] {
			fail("pressure start did not execute pinned stress worker binary")
		}
		r.State["handle"] = text(evidence["handle"], "pressure handle")
	} else if evidence["handle"] != r.State["handle"] {
		fail("pressure status not bound to active workload handle")
	}
	observed, expected := sub(evidence, "pressure_cgroup"), sub(r.pressure(), "workload_cgroup")
	for _, k := range []string{"cpu_max", "io_device", "memory_max_bytes", "io_weight"} {
		if !same(observed[k], expected[k]) {
			fail("pressure cgroup effective %s differs from pinned workload role", k)
		}
	}
	if n(observed, "memory_min_bytes") != 0 || n(observed, "memory_low_bytes") != 0 {
		fail("pressure cgroup must keep memory.min and memory.low at zero")
	}
	backing, e := ValidateBlockBackingEvidence(observed["io_backing"], str(expected, "io_device"))
	if e != nil {
		panic(e)
	}
	if old := r.State["pressure_backing"]; old != nil && !same(old, backing) {
		fail("pressure scratch block backing changed during run")
	}
	r.State["pressure_backing"] = backing
	path := text(observed["path"], "pressure scope cgroup path")
	parent := str(expected, "parent_path")
	native, db := str(r.State, "native_runner_path"), str(r.State, "database_cgroup_path")
	if !safePath(path) || filepath.Dir(path) != parent || path == native || (native != "" && inside(path, native)) || path == db || (db != "" && inside(db, path)) {
		fail("pressure systemd scope outside pinned slice or overlaps native role tree")
	}
	if old := r.State["pressure_path"]; old != nil && old != path {
		fail("pressure cgroup path changed during run")
	}
	r.State["pressure_path"] = path
	scope := sub(observed, "systemd_scope")
	if !exact(scope, "unit", "slice", "control_group", "parent_control_group", "active_state", "cgroup_present", "systemctl_show_raw") {
		fail("pressure scope evidence differs from exact transient-unit schema")
	}
	runtime := sub(sub(r.Manifest, "transport"), "runtime")
	if str(scope, "unit") != "terrascale-d15-"+str(r.State, "run_id")+".scope" || scope["slice"] != runtime["workload_slice"] || str(scope, "parent_control_group") != strings.TrimPrefix(parent, CgroupRoot) || str(scope, "control_group") != strings.TrimPrefix(path, CgroupRoot) {
		fail("pressure systemd unit placement differs from pinned workload slice")
	}
	completed := request["expect_pressure_completed"] == true
	if (!completed && (str(scope, "active_state") != "active" || scope["cgroup_present"] != true)) || (completed && (!slices.Contains([]string{"inactive", "failed"}, str(scope, "active_state")) || scope["cgroup_present"] != false)) {
		fail("pressure systemd scope lifecycle does not match phase")
	}
	props := parseProperties(text(scope["systemctl_show_raw"], "scope systemctl raw"), "scope")
	for k, want := range map[string]string{"ActiveState": str(scope, "active_state"), "ControlGroup": str(scope, "control_group"), "Slice": str(scope, "slice"), "MemoryMax": strconv.FormatInt(n(expected, "memory_max_bytes"), 10), "MemoryMin": "0", "MemoryLow": "0", "IOWeight": strconv.FormatInt(n(expected, "io_weight"), 10)} {
		if str(props, k) != want {
			fail("systemd scope properties differ from pinned limits or placement")
		}
	}
	f := strings.Fields(str(expected, "cpu_max"))
	quota := integerText(f[0], "CPU quota") * 1000000 / integerText(f[1], "CPU period")
	if str(props, "CPUQuotaPerSecUSec") != strconv.FormatInt(quota, 10) {
		fail("systemd scope CPU quota differs from pinned cpu.max")
	}
	raw := text(observed["worker_state_record"], "pressure worker state record")
	state := obj(rawJSON(raw, "pressure worker state", str(observed, "worker_state_sha256"), 16384), "worker state")
	if str(state, "schema") != "terrascale.d15.pressure-worker-state/v2" || state["run_id"] != r.State["run_id"] || !exact(state, "schema", "run_id", "status", "started_at_utc", "started_monotonic_ns", "observed_at_utc", "elapsed_monotonic_ns", "worker_pids", "worker_roles", "active_worker_pids", "finished_at_utc", "finished_monotonic_ns") {
		fail("pressure worker state not bound to run/version or contains obsolete fields")
	}
	stateObserved, responseObserved := timestamp(state["observed_at_utc"], "worker state observation"), timestamp(response["observed_at_utc"], "pressure response observation")
	if stateObserved.After(responseObserved) {
		fail("pressure worker state future-dated")
	}
	started := timestamp(state["started_at_utc"], "worker state start")
	if initial {
		if str(state, "status") != "RUNNING" {
			fail("pressure worker did not report RUNNING at start")
		}
		r.State["pressure_started_at"], r.State["pressure_started_monotonic"] = started, time.Now()
	} else if !reportTime(r.State, "pressure_started_at").Equal(started) {
		fail("pressure worker start time changed after startup")
	}
	processes, ok := observed["processes"].([]any)
	if !ok {
		fail("pressure cgroup lacks actual process inventory")
	}
	pids := intList(observed["process_pids"], "pressure process pids")
	workers := intList(observed["worker_process_pids"], "pressure worker pids")
	rawProcs := str(observed, "cgroup_procs_raw")
	parsed := []int64{}
	for line := range strings.SplitSeq(strings.TrimSpace(rawProcs), "\n") {
		if line != "" {
			parsed = append(parsed, integerText(line, "cgroup.procs"))
		}
	}
	slices.Sort(parsed)
	if !same(parsed, pids) {
		fail("pressure raw cgroup.procs differs from PID list")
	}
	current := Object{}
	counts := map[string]int{}
	workerRoles := []any{}
	listedWorkers := []int64{}
	for _, v := range processes {
		row := obj(v, "pressure process")
		if !exact(row, "pid", "process_start_time", "role", "process_stat_raw", "process_cgroup_raw") {
			fail("pressure process inventory lacks exact raw /proc identity")
		}
		pid := num(row["pid"], "pressure process PID", 2)
		start, roleName := str(row, "process_start_time"), str(row, "role")
		if !slices.Contains([]string{"pressure_runner", "cpu_worker", "memory_worker", "io_worker"}, roleName) {
			fail("pressure process role not load worker")
		}
		actual, actualStart := procStatIdentity(str(row, "process_stat_raw"))
		group := procCgroupPath(str(row, "process_cgroup_raw"))
		if actual != pid || actualStart != start || filepath.Join(CgroupRoot, group) != path {
			fail("pressure worker raw identity differs from cgroup inventory")
		}
		key := strconv.FormatInt(pid, 10)
		if _, ok := current[key]; ok {
			fail("pressure process inventory repeats PID")
		}
		current[key] = []any{start, roleName}
		counts[roleName]++
		if roleName != "pressure_runner" {
			listedWorkers = append(listedWorkers, pid)
			workerRoles = append(workerRoles, Object{"pid": pid, "role": roleName})
		}
		if snapshot, ok := r.State["host_snapshot"].(map[string]any); ok && pid == n(sub(sub(sub(snapshot, "members"), "source"), "managed_identity"), "pid") {
			fail("pressure cgroup includes TerraBase or management process")
		}
		if service, ok := r.stateObject("service_snapshot")[HostUnit].(map[string]any); ok && pid == n(service, "main_pid") {
			fail("pressure cgroup includes TerraBase or management process")
		}
	}
	currentPids := []int64{}
	for k := range current {
		currentPids = append(currentPids, integerText(k, "PID"))
	}
	slices.Sort(currentPids)
	slices.Sort(listedWorkers)
	slices.SortFunc(workerRoles, func(a, b any) int {
		aa, bb := n(obj(a, "worker role"), "pid"), n(obj(b, "worker role"), "pid")
		if aa < bb {
			return -1
		}
		if aa > bb {
			return 1
		}
		return 0
	})
	if !same(pids, currentPids) || !same(workers, listedWorkers) || Hash(Canonical(processes)) != str(observed, "process_inventory_sha256") {
		fail("pressure process inventory hash or IDs differ from raw records")
	}
	if initial {
		if counts["pressure_runner"] != 1 || int64(counts["cpu_worker"]) != n(r.pressure(), "cpu_workers") || counts["memory_worker"] != 1 || int64(counts["io_worker"]) != n(r.pressure(), "io_workers") {
			fail("pressure startup inventory differs from configured load workers")
		}
		r.State["pressure_processes"] = current
		r.State["pressure_worker_roles"] = workerRoles
		if !same(state["worker_roles"], workerRoles) {
			fail("pressure worker roles differ from startup inventory")
		}
	} else if completed {
		if len(pids) != 0 || len(processes) != 0 || rawProcs != "" || len(workers) != 0 {
			fail("completed pressure left process in cgroup")
		}
	} else {
		if !same(current, r.State["pressure_processes"]) {
			fail("pressure worker disappeared or changed identity before full duration")
		}
		if !same(state["worker_roles"], r.expectedWorkerRoles()) {
			fail("pressure worker state roles changed during duration")
		}
	}
	if completed {
		elapsed, startNS, finishNS := num(state["elapsed_monotonic_ns"], "worker elapsed", 0), num(state["started_monotonic_ns"], "worker start", 0), num(state["finished_monotonic_ns"], "worker finish", 0)
		finish := timestamp(state["finished_at_utc"], "worker finish time")
		if str(state, "status") != "COMPLETED" || !same(state["worker_pids"], []any{}) || !same(state["active_worker_pids"], []any{}) || !same(state["worker_roles"], r.expectedWorkerRoles()) || finishNS <= startNS || elapsed < n(r.pressure(), "duration_seconds")*1000000000 || finish.Before(started.Add(time.Duration(n(r.pressure(), "duration_seconds"))*time.Second)) {
			fail("pressure completion did not prove all workers survived full duration")
		}
		r.State["pressure_completed"] = true
	} else if str(state, "status") != "RUNNING" || !same(state["worker_pids"], listedWorkers) || !same(state["active_worker_pids"], listedWorkers) {
		fail("pressure workers not all running through duration")
	}
}
func intList(v any, label string) []int64 {
	values, ok := v.([]any)
	if !ok {
		if x, ok := v.([]int64); ok {
			return x
		}
		if x, ok := v.([]int); ok {
			out := make([]int64, len(x))
			for i, n := range x {
				out[i] = int64(n)
			}
			return out
		}
		fail("%s must be PID list", label)
	}
	out := make([]int64, len(values))
	for i, x := range values {
		out[i] = num(x, label, 2)
	}
	return out
}
func (r *Runner) expectedWorkerRoles() []any {
	if rows, ok := r.State["pressure_worker_roles"].([]any); ok {
		return rows
	}
	rows := []any{}
	for pid, value := range r.stateObject("pressure_processes") {
		a, ok := value.([]any)
		if !ok || len(a) != 2 {
			fail("invalid pressure process identity")
		}
		role, _ := a[1].(string)
		if role != "pressure_runner" {
			rows = append(rows, Object{"pid": integerText(pid, "worker PID"), "role": role})
		}
	}
	slices.SortFunc(rows, func(a, b any) int { return int(n(obj(a, "worker"), "pid") - n(obj(b, "worker"), "pid")) })
	return rows
}
func targetIdentity(target Object) Object {
	o := Object{}
	for _, k := range []string{"kind", "pid", "process_start", "process_nonce", "cgroup", "host_boot_id"} {
		o[k] = target[k]
	}
	return o
}
func (r *Runner) ValidateOOM(evidence, request Object, observed string) (err error) {
	defer recoverError(&err)
	r.validateOOM(evidence, request, observed)
	return
}
func (r *Runner) validateOOM(evidence, request Object, observed string) {
	events, ok := evidence["events"].([]any)
	if !ok || len(events) > 4096 {
		fail("OOM evidence must retain bounded array of raw kernel records")
	}
	if str(request, "phase") == "before" {
		if len(events) > 0 {
			fail("pre-pressure OOM watermark must not contain pre-existing events")
		}
		raw := text(evidence["journal_watermark_raw_record"], "OOM watermark record")
		rawJSON(raw, "OOM watermark", str(evidence, "journal_watermark_raw_record_sha256"), 65536)
		parsed, e := ParseJournalRecord(raw, "kernel")
		if e != nil {
			panic(e)
		}
		watermark := Object{"boot_id": parsed["boot_id"], "cursor": parsed["cursor"], "raw_record": raw, "raw_record_sha256": evidence["journal_watermark_raw_record_sha256"]}
		target := r.terrabaseTarget()
		if !same(request["oom_target"], target) {
			fail("pre-mutation OOM target differs from accepted witness")
		}
		intent := sub(evidence, "oom_restore_intent")
		if !exact(intent, "target", "native_runner_cgroup_path", "database_cgroup_path", "cgroup_inode", "prior_memory_max_bytes", "temporary_memory_max_bytes") {
			fail("OOM pre-mutation restore intent unexpected shape")
		}
		native, db, _ := qualifiedRoleCgroups(str(intent, "native_runner_cgroup_path"), str(target, "cgroup"))
		if !same(intent["target"], targetIdentity(target)) || native != str(r.State, "native_runner_path") || db != str(r.State, "database_cgroup_path") || str(intent, "database_cgroup_path") != db || n(intent, "cgroup_inode") <= 0 || !same(intent["prior_memory_max_bytes"], r.qualification()["database_memory_max_bytes"]) || !same(intent["temporary_memory_max_bytes"], sub(r.pressure(), "oom_fault")["target_memory_max_bytes"]) {
			fail("OOM pre-mutation restore intent differs from exact signed target/cap")
		}
		if e := writeJSON(filepath.Join(r.EvidenceDir, "oom-restore-intent.json"), intent, true); e != nil {
			fail("could not durably persist native OOM restore obligation")
		}
		dir, e := os.Open(r.EvidenceDir)
		if e != nil {
			fail("cannot open restore obligation directory")
		}
		e = dir.Sync()
		dir.Close()
		if e != nil {
			fail("cannot durably sync native OOM restore obligation")
		}
		r.State["oom_watermark"], r.State["oom_restore_intent"], r.State["oom_target"] = watermark, intent, target
		return
	}
	watermark := sub(r.State, "oom_watermark")
	if !same(watermark, request["journal_watermark"]) {
		fail("OOM evidence does not retain pre-pressure kernel cursor/target")
	}
	start := reportTime(r.State, "pressure_started_at")
	target := r.terrabaseTarget()
	if !same(request["oom_target"], target) {
		fail("OOM fault target differs from latest accepted native witness")
	}
	fault := str(request, "phase") == "during" && request["wait_for_event"] == true
	if fault {
		intent := sub(r.State, "oom_restore_intent")
		if !same(request["oom_restore_intent"], intent) {
			fail("OOM mutation missing durable pre-mutation restore obligation")
		}
		sent, report := timestamp(request["sent_at_utc"], "OOM fault sent"), timestamp(request["target_report_observed_at_utc"], "OOM target report")
		age := sent.Sub(report)
		if age < 0 || age > time.Duration(n(sub(r.Manifest, "adapter_contract"), "target_witness_max_age_ms"))*time.Millisecond {
			fail("OOM fault accepted report/process witness stale")
		}
		receipt := sub(evidence, "memory_limit_receipt")
		if !exact(receipt, "target", "prior_memory_max_bytes", "temporary_memory_max_bytes", "observed_memory_current_bytes", "target_cgroup_members_before", "target_child_cgroups_before", "target_cgroup_inode_before", "restored_memory_max_bytes", "restore_method", "restore_verified") {
			fail("OOM memory receipt differs from bounded native-role fault schema")
		}
		cap := n(sub(r.pressure(), "oom_fault"), "target_memory_max_bytes")
		if !same(receipt["target"], targetIdentity(target)) || !same(receipt["prior_memory_max_bytes"], r.qualification()["database_memory_max_bytes"]) || n(receipt, "temporary_memory_max_bytes") != cap || n(receipt, "observed_memory_current_bytes") <= cap || !same(receipt["target_cgroup_members_before"], []any{target["pid"]}) || !same(receipt["target_child_cgroups_before"], []any{}) || !same(receipt["target_cgroup_inode_before"], intent["cgroup_inode"]) || !same(receipt["restored_memory_max_bytes"], r.qualification()["database_memory_max_bytes"]) || !slices.Contains([]string{"same_cgroup_fd", "native_role_recreated"}, str(receipt, "restore_method")) || receipt["restore_verified"] != true {
			fail("OOM memory cap was not safely lowered and restored on the exact native role")
		}
		r.State["oom_restore_receipt"] = receipt
	}
	threshold := start.Add(time.Duration(n(r.pressure(), "scenario_event_after_seconds")) * time.Second)
	collected := timestamp(observed, "OOM evidence observation")
	window := time.Duration(n(sub(r.Manifest, "adapter_contract"), "oom_event_window_seconds")) * time.Second
	for _, v := range events {
		row := obj(v, "OOM event")
		raw := text(row["raw_record"], "OOM raw event")
		rawJSON(raw, "OOM event", str(row, "raw_record_sha256"), 65536)
		parsed, e := ParseKernelOOMRecord(raw)
		if e != nil {
			panic(e)
		}
		when := timestamp(parsed["event_at_utc"], "OOM event timestamp")
		if str(row, "source") == "kernel" && parsed["boot_id"] == watermark["boot_id"] && parsed["journal_cursor"] != watermark["cursor"] && same(parsed["victim_pid"], target["pid"]) && str(parsed, "cgroup_path") == cgroupFilePath(str(target, "cgroup")) && !when.Before(threshold) && !when.After(collected) && when.Sub(threshold) <= window {
			r.State["failure_injection_at"], r.State["failure_observed"], r.State["oom_observed"] = when, true, true
			return
		}
	}
	if str(request, "phase") == "after" {
		fail("kernel OOM records do not identify exact pre-pressure TerraBase process/cgroup")
	}
}

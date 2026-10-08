package runtimepriority

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"golang.org/x/sys/unix"
)

func (r *Runner) Call(ctx context.Context, role, phase string, fields Object) (response Object, err error) {
	defer recoverError(&err)
	if fields == nil {
		fields = Object{}
	}
	sequence := int64(1)
	if r.State["sequence"] != nil {
		sequence = n(r.State, "sequence") + 1
	}
	r.State["sequence"] = sequence
	directory := filepath.Join(r.EvidenceDir, fmt.Sprintf("%04d-%s-%s", sequence, role, phase))
	if e := os.Mkdir(directory, 0700); e != nil {
		return nil, e
	}
	adapter := sub(r.Manifest, "adapter")
	deadline := n(sub(adapter, "deadlines_seconds"), role)
	sent := time.Now().UTC()
	request := Object{"schema": AdapterInputSchema, "request_id": entityid.New(), "run_id": r.State["run_id"], "run_manifest_sha256": r.State["manifest_hash"], "harness_sha256": r.State["harness_sha256"], "contract_id": sub(r.Manifest, "adapter_contract")["id"], "role": role, "phase": phase, "sent_at_utc": sent.Format("2006-01-02T15:04:05.000Z"), "deadline_seconds": deadline, "deadline_at_utc": sent.Add(time.Duration(deadline) * time.Second).Format("2006-01-02T15:04:05.000Z"), "identity": r.Manifest["identity"], "probe_source_revision": r.Manifest["repository_revision"], "controller_identity": r.Manifest["controller_identity"], "managed_member": r.Manifest["managed_member"], "transport": r.Manifest["transport"], "adapter_source_path": adapter["executable_path"], "adapter_source_sha256": adapter["executable_sha256"], "qualification": r.Manifest["qualification"], "controller_qualification": r.Manifest["controller_qualification"], "memory_floor_evidence": r.Manifest["memory_floor_evidence"], "pressure": r.Manifest["pressure"], "evidence_dir": r.EvidenceDir}
	for k, v := range fields {
		request[k] = v
	}
	if role == "database_progress" {
		request["transaction_id"] = Object{"expires_at_unix_ms": strconv.FormatInt(time.Now().UnixMilli()+600000, 10), "nonce": strings.ReplaceAll(uuid.New().String(), "-", "")}
		request["document_id"] = entityid.New()
		request["value"] = time.Now().UnixNano() % 2000000000
	}
	if role == "qualify" || role == "service_state" {
		if !slices.Contains([]string{"host", "controller"}, str(request, "guest_role")) {
			fail("%s requires explicit guest role", role)
		}
	}
	if role == "qualify" && str(request, "guest_role") == "host" && r.State["host_snapshot"] != nil {
		request["managed_process"] = sub(sub(sub(r.snapshot(), "members"), "source"), "managed_identity")
	}
	if role == "host_status" && r.State["last_event"] != nil {
		request["pending_object_durable_event"] = r.State["last_event"]
	}
	if role == "pressure_start" || role == "failure_inject" || role == "kernel_oom_evidence" {
		request["native_runner_cgroup_path"], request["protected_database_cgroup_path"] = r.State["native_runner_path"], r.State["database_cgroup_path"]
	}
	if role == "pressure_start" {
		request["pressure_manifest"] = r.Manifest
	}
	if role == "failure_inject" {
		request["target_process"] = r.failureTarget()
	}
	if role == "kernel_oom_evidence" {
		request["oom_target"] = r.terrabaseTarget()
		request["target_report_observed_at_utc"] = reportTime(sub(sub(r.snapshot(), "members"), "source"), "report_time").UTC().Format("2006-01-02T15:04:05.000Z")
		if r.State["oom_watermark"] != nil {
			request["journal_watermark"] = r.State["oom_watermark"]
		}
		if r.State["oom_restore_intent"] != nil {
			request["oom_restore_intent"] = r.State["oom_restore_intent"]
		}
	}
	if role == "cleanup_verify" && r.State["oom_restore_intent"] != nil {
		intent := sub(r.State, "oom_restore_intent")
		request["oom_restore_intent"] = intent
		request["native_runner_cgroup_path"], request["protected_database_cgroup_path"] = intent["native_runner_cgroup_path"], intent["database_cgroup_path"]
	}
	wire := pretty(request)
	if len(wire) > 1<<20 {
		fail("adapter request exceeds fixed input limit")
	}
	budget := int64(48 << 20)
	if phase == "cleanup" || phase == "after" {
		budget = 64 << 20
	}
	account := func(count int) {
		old := int64(0)
		if r.State["adapter_bytes"] != nil {
			old = n(r.State, "adapter_bytes")
		}
		if old+int64(count) > budget {
			fail("run adapter request/evidence budget exhausted")
		}
		r.State["adapter_bytes"] = old + int64(count)
	}
	account(len(wire))
	if e := os.WriteFile(filepath.Join(directory, "request.json"), wire, 0600); e != nil {
		return nil, e
	}
	command := Object{"argv": []string{str(adapter, "executable_path"), "runtime-priority", "adapter"}, "executable": adapter["executable_path"], "executable_sha256": adapter["executable_sha256"], "deadline_seconds": deadline, "input_contract": AdapterInputSchema, "result_schema": AdapterResultSchema, "purpose": "pinned native alpha adapter for " + role}
	commandWire := pretty(command)
	account(len(commandWire))
	if e := os.WriteFile(filepath.Join(directory, "command.json"), commandWire, 0600); e != nil {
		return nil, e
	}
	start := time.Now()
	if r.AdapterCall != nil {
		response, err = r.AdapterCall(ctx, request)
	} else {
		if e := VerifyPinnedFile(str(adapter, "executable_path"), str(adapter, "executable_sha256"), "native adapter", true); e != nil {
			return nil, e
		}
		fd, e := unix.Open(str(adapter, "executable_path"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		binary := os.NewFile(uintptr(fd), "adapter")
		defer binary.Close()
		raw, e := io.ReadAll(io.LimitReader(binary, MaxProbeBytes+1))
		if e != nil || Hash(raw) != str(adapter, "executable_sha256") {
			fail("adapter executable changed before descriptor execution")
		}
		binary.Seek(0, 0)
		callCtx, cancel := context.WithTimeout(ctx, time.Duration(deadline)*time.Second)
		defer cancel()
		cmd := exec.CommandContext(callCtx, "/proc/self/fd/3", "runtime-priority", "adapter")
		cmd.ExtraFiles = []*os.File{binary}
		cmd.Stdin = strings.NewReader(string(Canonical(request)))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return unix.Kill(-cmd.Process.Pid, unix.SIGKILL) }
		cmd.WaitDelay = time.Second
		stdout, stderr := &boundedOutput{maximum: 1 << 20}, &boundedOutput{maximum: 1 << 20}
		cmd.Stdout, cmd.Stderr = stdout, stderr
		err = cmd.Run()
		account(stdout.Len() + stderr.Len())
		os.WriteFile(filepath.Join(directory, "stdout.log"), stdout.Bytes(), 0600)
		os.WriteFile(filepath.Join(directory, "stderr.log"), stderr.Bytes(), 0600)
		if err == nil && (stdout.exceeded || stderr.exceeded || stdout.Len()+stderr.Len() > 1<<20) {
			err = &DomainError{"HarnessError", "adapter output exceeds fixed evidence bound"}
		}
		if err == nil {
			err = jsonUnmarshal(stdout.Bytes(), &response)
		}
	}
	if err == nil {
		if !exact(response, "schema", "request_id", "contract_id", "role", "status", "observed_at_utc", "evidence") || str(response, "schema") != AdapterResultSchema || str(response, "role") != role || response["request_id"] != request["request_id"] || response["contract_id"] != request["contract_id"] {
			err = &DomainError{"HarnessError", "adapter result stale or differs from pinned result schema"}
		} else if str(response, "status") != "PASS" {
			err = &DomainError{"HarnessError", "adapter reported FAIL"}
		} else {
			err = r.ValidateRole(role, phase, request, response)
		}
	}
	observation := Object{"sequence": sequence, "role": role, "phase": phase, "request_id": request["request_id"], "started_at_utc": request["sent_at_utc"], "finished_at_utc": utcNow(), "elapsed_seconds": time.Since(start).Seconds(), "evidence_path": directory, "status": "PASS", "failure": nil}
	if err != nil {
		observation["status"], observation["failure"] = "FAIL", err.Error()
	}
	account(len(pretty(observation)))
	if e := writeJSON(filepath.Join(directory, "observation.json"), observation, false); e != nil {
		return nil, e
	}
	r.appendState("results", observation)
	if err != nil {
		return nil, fmt.Errorf("%s/%s: %w", role, phase, err)
	}
	return
}
func (r *Runner) recovery(ctx context.Context) error {
	for _, row := range []struct{ role, phase, guest string }{{"host_status", "post_recovery", ""}, {"service_state", "post_recovery", "host"}, {"service_state", "post_recovery", "controller"}, {"qualify", "post_recovery", "host"}, {"qualify", "post_recovery", "controller"}, {"database_progress", "post_recovery", ""}, {"host_status", "after_write", ""}} {
		fields := Object{}
		if row.guest != "" {
			fields["guest_role"] = row.guest
		}
		if _, e := r.Call(ctx, row.role, row.phase, fields); e != nil {
			return e
		}
	}
	scenario := str(r.pressure(), "scenario")
	if scenario == "terrabase_process" || scenario == "terrabase_oom" {
		before := sub(sub(r.stateObject("baseline_host_rows"), "source"), "managed_identity")
		after := sub(sub(sub(r.snapshot(), "members"), "source"), "managed_identity")
		if same(before["pid"], after["pid"]) && before["start"] == after["start"] && before["nonce"] == after["nonce"] {
			return &DomainError{"HarnessError", "TerraBase recovery did not replace target process identity"}
		}
		if before["cgroup"] != after["cgroup"] {
			return &DomainError{"HarnessError", "TerraBase recovery did not return to exact managed role"}
		}
	}
	r.State["recovery_observed"] = true
	return nil
}
func RunQualification(ctx context.Context, manifest Object, wire []byte, hash, evidence string, adapter func(context.Context, Object) (Object, error), out io.Writer) (status int, err error) {
	defer recoverError(&err)
	missing, e := ValidateManifest(manifest, true, true)
	if e != nil {
		return 1, e
	}
	if len(missing) == 0 {
		if _, e := ValidateManifest(manifest, false, true); e != nil {
			return 1, e
		}
	}
	if e := os.Mkdir(evidence, 0700); e != nil {
		return 1, e
	}
	started := utcNow()
	r := NewRunner(manifest, hash, evidence)
	r.AdapterCall = adapter
	failures := []string{}
	attempted, pressureStarted := false, false
	call := func(role, phase string, fields Object) error { _, e := r.Call(ctx, role, phase, fields); return e }
	qualifyBoth := func(phase string) error {
		for _, role := range []string{"host", "controller"} {
			if e := call("qualify", phase, Object{"guest_role": role}); e != nil {
				return e
			}
		}
		return nil
	}
	servicesBoth := func(phase string) error {
		for _, role := range []string{"host", "controller"} {
			if e := call("service_state", phase, Object{"guest_role": role}); e != nil {
				return e
			}
		}
		return nil
	}
	if len(missing) == 0 {
		workErr := func() error {
			for _, row := range []struct{ role, phase string }{{"target_identity", "preflight"}, {"host_status", "before"}} {
				if e := call(row.role, row.phase, nil); e != nil {
					return e
				}
			}
			if e := servicesBoth("before"); e != nil {
				return e
			}
			if e := qualifyBoth("before"); e != nil {
				return e
			}
			if e := call("database_progress", "before", nil); e != nil {
				return e
			}
			if e := call("host_status", "after_write", nil); e != nil {
				return e
			}
			scenario := str(sub(manifest, "pressure"), "scenario")
			if scenario == "terrabase_oom" {
				if e := call("kernel_oom_evidence", "before", nil); e != nil {
					return e
				}
			}
			attempted = true
			if e := call("pressure_start", "start", nil); e != nil {
				return e
			}
			pressureStarted = true
			if e := call("pressure_status", "during", Object{"sample_number": 0, "pressure_handle": r.State["handle"]}); e != nil {
				return e
			}
			p := sub(manifest, "pressure")
			start := time.Now()
			deadline := start.Add(time.Duration(n(p, "duration_seconds")) * time.Second)
			next := start.Add(time.Duration(n(p, "sample_interval_seconds")) * time.Second)
			faultAt := time.Time{}
			if scenario != "management_stability" {
				faultAt = start.Add(time.Duration(n(p, "scenario_event_after_seconds")) * time.Second)
			}
			for time.Now().Before(deadline) {
				now := time.Now()
				if !faultAt.IsZero() && !now.Before(faultAt) {
					if e := call("pressure_status", "pre_injection", Object{"pressure_handle": r.State["handle"]}); e != nil {
						return e
					}
					if e := servicesBoth("pre_failure"); e != nil {
						return e
					}
					if e := call("host_status", "pre_failure", nil); e != nil {
						return e
					}
					if scenario == "terrabase_oom" {
						if e := call("kernel_oom_evidence", "during", Object{"wait_for_event": true}); e != nil {
							return e
						}
					} else if e := call("failure_inject", "during", Object{"mode": scenario}); e != nil {
						return e
					}
					if e := r.recovery(ctx); e != nil {
						return e
					}
					faultAt = time.Time{}
				}
				if !now.Before(next) && time.Now().Before(deadline) {
					if e := call("pressure_status", "during", Object{"pressure_handle": r.State["handle"]}); e != nil {
						return e
					}
					if e := servicesBoth("during"); e != nil {
						return e
					}
					if e := call("host_status", "during", nil); e != nil {
						return e
					}
					if e := qualifyBoth("during"); e != nil {
						return e
					}
					if e := call("database_progress", "during", nil); e != nil {
						return e
					}
					if e := call("host_status", "after_write", nil); e != nil {
						return e
					}
					next = next.Add(time.Duration(n(p, "sample_interval_seconds")) * time.Second)
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(100 * time.Millisecond):
				}
			}
			if e := call("pressure_status", "complete", Object{"expect_pressure_completed": true, "pressure_handle": r.State["handle"]}); e != nil {
				return e
			}
			return nil
		}()
		if workErr != nil {
			failures = append(failures, workErr.Error())
		}
		if attempted {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
			for _, role := range []string{"pressure_stop", "cleanup_verify"} {
				_, e := r.Call(cleanupCtx, role, "cleanup", Object{"pressure_handle": r.State["handle"]})
				if e != nil {
					failures = append(failures, e.Error())
				}
			}
			cancel()
			if pressureStarted {
				for _, f := range []func() error{func() error { return servicesBoth("after") }, func() error { return call("host_status", "after", nil) }, func() error { return qualifyBoth("after") }, func() error { return call("database_progress", "after", nil) }, func() error { return call("host_status", "after_write", nil) }} {
					if e := f(); e != nil {
						failures = append(failures, e.Error())
						break
					}
				}
				if str(sub(manifest, "pressure"), "scenario") == "terrabase_oom" {
					if e := call("kernel_oom_evidence", "after", Object{"wait_for_event": false}); e != nil {
						failures = append(failures, e.Error())
					}
				}
			}
		}
	}
	phases := []string{}
	samples, _ := r.State["memory_usage_samples"].([]any)
	for _, v := range samples {
		s := obj(v, "memory sample record")
		phases = append(phases, str(s, "guest_role")+":"+str(s, "phase"))
	}
	slices.Sort(phases)
	phases = slices.Compact(phases)
	state, reasons := EvaluateRunStatus(failures, pressureStarted, r.State["pressure_completed"] == true, str(sub(manifest, "pressure"), "scenario"), r.State["recovery_observed"] == true, phases)
	if len(missing) > 0 {
		state = "UNQUALIFIED"
		reasons = missing
	}
	floors, controllerFloors := Object{}, Object{}
	for k, v := range sub(manifest, "memory_floor_evidence") {
		floors[k] = obj(v, "floor")["basis"]
	}
	for k, v := range sub(manifest, "controller_memory_floor_evidence") {
		controllerFloors[k] = obj(v, "floor")["basis"]
	}
	baselineSamples := Object{"host": nil, "controller": nil}
	for _, v := range samples {
		s := obj(v, "memory sample record")
		if str(s, "phase") == "before" && baselineSamples[str(s, "guest_role")] == nil {
			baselineSamples[str(s, "guest_role")] = s["sample_sha256"]
		}
	}
	summary := Object{"schema": Schema, "qualification_status": state, "started_at_utc": started, "finished_at_utc": utcNow(), "repository_revision": manifest["repository_revision"], "manifest_sha256": hash, "run_id": r.State["run_id"], "harness_sha256": r.State["harness_sha256"], "commands_executed": len(r.State["results"].([]any)) > 0, "pressure_attempted": attempted, "pressure_started": pressureStarted, "pressure_completed": r.State["pressure_completed"], "failure_observed": r.State["failure_observed"], "recovery_observed": r.State["recovery_observed"], "object_durable_oom_observed": r.State["oom_observed"], "observations": r.State["results"], "failures": reasons, "missing_or_unqualified": missing, "memory_usage_sampling": Object{"schema": MemorySampleSchema, "baseline_sample_sha256_by_guest": baselineSamples, "sample_count": len(samples), "samples": samples, "sample_phases": phases, "floor_basis_by_scope": floors, "controller_floor_basis_by_scope": controllerFloors}}
	for _, k := range []string{"authorization", "identity", "controller_identity", "managed_member", "qualification", "controller_qualification", "pressure", "memory_floor_evidence", "controller_memory_floor_evidence", "adapter_contract"} {
		summary[k] = manifest[k]
	}
	if r.State["oom_restore_intent"] != nil {
		summary["oom_restore_cleanup"] = Object{"intent": r.State["oom_restore_intent"], "verified": r.State["oom_restore_cleanup_verified"], "unresolved_reason": r.State["oom_restore_unresolved_reason"]}
	}
	if e := writeJSON(filepath.Join(evidence, "summary.json"), summary, false); e != nil {
		return 1, e
	}
	if e := os.WriteFile(filepath.Join(evidence, "manifest.json"), wire, 0600); e != nil {
		return 1, e
	}
	if e := os.WriteFile(filepath.Join(evidence, "manifest.sha256"), []byte(hash+"  manifest.json\n"), 0600); e != nil {
		return 1, e
	}
	if e := writeChecksums(evidence); e != nil {
		return 1, e
	}
	fmt.Fprintf(out, "%s: %s\n", state, filepath.Join(evidence, "summary.json"))
	if state == "PASS" {
		return 0, nil
	}
	return 1, nil
}
func writeChecksums(directory string) error {
	paths := []string{}
	e := filepath.WalkDir(directory, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && filepath.Base(path) != "checksums.sha256" {
			paths = append(paths, path)
		}
		return nil
	})
	if e != nil {
		return e
	}
	slices.Sort(paths)
	var out strings.Builder
	for _, path := range paths {
		wire, _, e := readNoFollow(path, 64<<20)
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(directory, path)
		if e != nil {
			return e
		}
		fmt.Fprintf(&out, "%s  %s\n", Hash(wire), rel)
	}
	return os.WriteFile(filepath.Join(directory, "checksums.sha256"), []byte(out.String()), 0600)
}

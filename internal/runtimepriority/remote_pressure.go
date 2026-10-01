package runtimepriority

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func (m *Remote) pressureObservation(ctx context.Context, request Object) (Object, error) {
	settings := sub(sub(request, "transport"), "runtime")
	p, cg := sub(request, "pressure"), sub(sub(request, "pressure"), "workload_cgroup")
	parent := str(cg, "parent_path")
	_, slice := m.properties(ctx, request, str(settings, "workload_slice"), []string{"ControlGroup", "ActiveState"})
	if str(slice, "ActiveState") != "active" || filepath.Join(CgroupRoot, str(slice, "ControlGroup")) != parent {
		fail("configured workload slice differs from exact live cgroup")
	}
	unit := "terrascale-d15-" + str(request, "run_id") + ".scope"
	raw, scope := m.properties(ctx, request, unit, []string{"ActiveState", "ControlGroup", "Slice", "CPUQuotaPerSecUSec", "MemoryMax", "MemoryMin", "MemoryLow", "IOWeight"})
	path := m.scopePath(request)
	if filepath.Join(m.CgroupRoot, str(scope, "ControlGroup")) != path || scope["Slice"] != settings["workload_slice"] {
		fail("transient scope outside pinned slice or different unit path")
	}
	active := str(scope, "ActiveState") == "active"
	completed := request["expect_pressure_completed"] == true
	if active == completed {
		fail("pressure scope lifecycle differs from expected phase")
	}
	statePath := filepath.Join(str(p, "io_directory"), "terrascale-d15-"+str(request, "run_id"), "runner-status.json")
	state, wire, e := LoadJSON(statePath, 16384)
	if e != nil {
		return nil, e
	}
	info, e := os.Lstat(statePath)
	if e != nil {
		return nil, e
	}
	if info.Mode().Perm()&0077 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		fail("pressure worker state not bounded private root-owned regular file")
	}
	if state["run_id"] != request["run_id"] || str(state, "schema") != "terrascale.d15.pressure-worker-state/v2" {
		fail("pressure worker state stale or mismatched")
	}
	wantStatus := "RUNNING"
	if completed {
		wantStatus = "COMPLETED"
	}
	if str(state, "status") != wantStatus {
		fail("pressure worker state does not match phase")
	}
	present := false
	if info, e := os.Lstat(path); e == nil {
		present = info.IsDir() && info.Mode()&os.ModeSymlink == 0
	}
	if active != present {
		fail("scope active state and cgroup presence disagree")
	}
	inventory := Object{"process_pids": []any{}, "processes": []any{}, "worker_process_pids": []any{}, "cgroup_procs_raw": "", "process_inventory_sha256": Hash([]byte("[]"))}
	if active {
		roles := map[int]string{}
		for _, v := range array(state["worker_roles"], "worker roles") {
			row := obj(v, "worker role")
			if !exact(row, "pid", "role") {
				fail("worker role record invalid shape")
			}
			pid := int(num(row["pid"], "worker role PID", 2))
			if _, ok := roles[pid]; ok {
				fail("worker role record repeated PID")
			}
			role := str(row, "role")
			if role != "cpu_worker" && role != "memory_worker" && role != "io_worker" {
				fail("worker role invalid")
			}
			roles[pid] = role
		}
		pids := []int{}
		runners := 0
		for _, s := range strings.Fields(m.readCgroupProcs(path)) {
			pid := int(integerText(s, "scope PID"))
			pids = append(pids, pid)
			if _, ok := roles[pid]; !ok {
				roles[pid] = "pressure_runner"
				runners++
			}
		}
		if runners != 1 {
			fail("pressure scope unknown or missing runner process")
		}
		inventory, e = PressureCgroupInventory(path, pids, roles, m.ProcRoot)
		if e != nil {
			return nil, e
		}
		if cpuMax(path) != str(cg, "cpu_max") || number(filepath.Join(path, "memory.max")) != n(cg, "memory_max_bytes") || number(filepath.Join(path, "memory.min")) != 0 || number(filepath.Join(path, "memory.low")) != 0 || cgroupIOWeight(path, str(cg, "io_device")) != n(cg, "io_weight") {
			fail("effective pressure scope limits differ from request")
		}
	}
	backing, e := ProveBlockBacking(str(p, "io_directory"), "/proc/self/mountinfo", "/sys", nil)
	if e != nil {
		return nil, e
	}
	observation := Object{"path": filepath.Join(CgroupRoot, str(scope, "ControlGroup")), "parent_path": parent, "cpu_max": cg["cpu_max"], "memory_max_bytes": cg["memory_max_bytes"], "memory_min_bytes": 0, "memory_low_bytes": 0, "io_weight": cg["io_weight"], "io_device": cg["io_device"], "io_backing": backing, "scratch_directory": filepath.Dir(statePath), "status_file_path": statePath, "worker_state_record": string(wire), "worker_state_sha256": Hash(wire), "systemd_scope": Object{"unit": unit, "slice": scope["Slice"], "control_group": scope["ControlGroup"], "parent_control_group": strings.TrimPrefix(parent, CgroupRoot), "active_state": scope["ActiveState"], "cgroup_present": present, "systemctl_show_raw": raw}}
	for k, v := range inventory {
		observation[k] = v
	}
	executable := str(settings, "stress_launcher_path")
	binary, _, e := readNoFollow(executable, MaxProbeBytes)
	if e != nil {
		return nil, e
	}
	if Hash(binary) != str(settings, "stress_launcher_sha256") {
		fail("pressure worker executable differs from pin")
	}
	return Object{"handle": unit, "worker_harness_sha256": Hash(binary), "pressure_cgroup": observation}, nil
}
func (m *Remote) pressureStart(ctx context.Context, request Object) (result Object, err error) {
	defer recoverError(&err)
	settings := sub(sub(request, "transport"), "runtime")
	executable := str(settings, "stress_launcher_path")
	verifyPin(executable, str(settings, "stress_launcher_sha256"), "pressure worker executable", true)
	meta, e := os.Lstat(executable)
	if e != nil {
		return nil, e
	}
	if meta.Sys().(*syscall.Stat_t).Uid != 0 {
		fail("pressure worker executable must be immutable root-owned")
	}
	unit := "terrascale-d15-" + str(request, "run_id") + ".scope"
	p := sub(request, "pressure")
	cg := sub(p, "workload_cgroup")
	parent := str(cg, "parent_path")
	_, slice := m.properties(ctx, request, str(settings, "workload_slice"), []string{"ControlGroup", "ActiveState"})
	if str(slice, "ActiveState") != "active" || filepath.Join(CgroupRoot, str(slice, "ControlGroup")) != parent {
		fail("configured workload slice differs from live cgroup")
	}
	var manifest Object
	if e := jsonUnmarshal(Canonical(request["pressure_manifest"]), &manifest); e != nil {
		return nil, e
	}
	assigned := filepath.Join(parent, unit)
	sub(sub(manifest, "pressure"), "workload_cgroup")["path"] = assigned
	file, e := os.CreateTemp(m.RunRoot, "terrascale-d15-*.json")
	if e != nil {
		return nil, e
	}
	name := file.Name()
	defer os.Remove(name)
	if e := file.Chmod(0600); e != nil {
		file.Close()
		return nil, e
	}
	_, e = file.Write(Canonical(manifest))
	if e == nil {
		e = file.Sync()
	}
	file.Close()
	if e != nil {
		return nil, e
	}
	fields := strings.Fields(str(cg, "cpu_max"))
	percent := float64(integerText(fields[0], "pressure quota")) * 100 / float64(integerText(fields[1], "pressure period"))
	argv := []string{str(settings, "systemd_run_path"), "--scope", "--quiet", "--unit", unit, "--slice", str(settings, "workload_slice"), "--property=CPUQuota=" + strconv.FormatFloat(percent, 'f', 3, 64) + "%", "--property=MemoryMax=" + strconv.FormatInt(n(cg, "memory_max_bytes"), 10), "--property=MemoryMin=0", "--property=MemoryLow=0", "--property=IOWeight=" + strconv.FormatInt(n(cg, "io_weight"), 10), executable, "runtime-priority", "pressure", "stress-worker", "--manifest", name, "--expected-native-runner-cgroup", str(request, "native_runner_cgroup_path"), "--protected-database-cgroup", str(request, "protected_database_cgroup_path"), "--assigned-pressure-cgroup", assigned, "--run-id", str(request, "run_id"), "--retain-evidence"}
	return m.admitScope(ctx, request, argv, m.pressureObservation)
}

// admitScope transfers an owned launcher to the pressure lifecycle only after
// the production observer has admitted its complete RUNNING evidence.
func (m *Remote) admitScope(ctx context.Context, request Object, argv []string, observe func(context.Context, Object) (Object, error)) (result Object, err error) {
	defer recoverError(&err)
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	settings := sub(sub(request, "transport"), "runtime")
	unit := "terrascale-d15-" + str(request, "run_id") + ".scope"
	// A scope launcher waits for its worker command. Start it in a separate
	// session and admit only the exact bounded RUNNING inventory below.
	_, load := m.properties(ctx, request, unit, []string{"LoadState"})
	if str(load, "LoadState") != "not-found" {
		fail("pressure scope unit already exists; refusing to adopt or stop it")
	}
	stop, done, e := m.launchScope(argv)
	if e != nil {
		return nil, e
	}
	admitted := false
	defer func() {
		if admitted {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, scopeErr := m.command(cleanupCtx, []string{str(settings, "systemctl_path"), "stop", unit}, nil, 20*time.Second, 65536)
		launcherErr := stop(cleanupCtx)
		err = errors.Join(err, scopeErr, launcherErr)
	}()
	deadline := time.Now().Add(min(10*time.Second, time.Duration(n(request, "deadline_seconds")-1)*time.Second))
	var last error
	for time.Now().Before(deadline) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		reply, e := func() (o Object, err error) { defer recoverError(&err); return observe(ctx, request) }()
		if e == nil {
			if e := ctx.Err(); e != nil {
				return nil, e
			}
			admitted = true
			return reply, nil
		}
		last = e
		select {
		case launchErr := <-done:
			return nil, fmt.Errorf("pressure launcher exited before owned RUNNING admission: %v", launchErr)
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("pressure scope did not report bounded RUNNING inventory: %w", last)
}
func (m *Remote) pressureStop(ctx context.Context, request Object) (Object, error) {
	settings := sub(sub(request, "transport"), "runtime")
	unit := "terrascale-d15-" + str(request, "run_id") + ".scope"
	_, _ = m.command(ctx, []string{str(settings, "systemctl_path"), "stop", unit}, nil, 20*time.Second, 65536)
	path := m.scopePath(request)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, e := os.Lstat(path); os.IsNotExist(e) {
			break
		}
		raw := m.readCgroupProcs(path)
		entries, e := os.ReadDir(path)
		if e != nil {
			return nil, e
		}
		children := false
		for _, entry := range entries {
			children = children || entry.IsDir()
		}
		if strings.TrimSpace(raw) == "" && !children {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if _, e := os.Lstat(path); e == nil {
		if strings.TrimSpace(m.readCgroupProcs(path)) != "" {
			fail("pressure scope did not stop empty")
		}
		entries, e := os.ReadDir(path)
		if e != nil {
			return nil, e
		}
		for _, entry := range entries {
			if entry.IsDir() {
				fail("pressure scope contains child cgroup")
			}
		}
	}
	scratch := filepath.Join(str(sub(request, "pressure"), "io_directory"), "terrascale-d15-"+str(request, "run_id"))
	if info, e := os.Lstat(scratch); e == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			fail("pressure scratch became unsafe/unowned path")
		}
		if e := os.RemoveAll(scratch); e != nil {
			return nil, e
		}
	}
	return Object{"handle": unit, "pressure_cgroup_process_pids": []any{}, "pressure_cgroup_procs_raw": ""}, nil
}

func (m *Remote) launchScope(argv []string) (stop func(context.Context) error, done <-chan error, err error) {
	if m.ScopeLauncher != nil {
		return m.ScopeLauncher(argv)
	}
	null, e := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if e != nil {
		return nil, nil, e
	}
	defer null.Close()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if e := cmd.Start(); e != nil {
		return nil, nil, e
	}
	completed := make(chan error, 1)
	go func() { completed <- cmd.Wait(); close(completed) }()
	stop = func(ctx context.Context) error {
		select {
		case <-completed:
			return nil
		default:
		}
		if e := unix.Kill(-cmd.Process.Pid, unix.SIGTERM); e != nil && e != unix.ESRCH {
			return e
		}
		select {
		case <-completed:
			return nil
		case <-ctx.Done():
			_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if e := unix.Kill(-cmd.Process.Pid, unix.SIGKILL); e != nil && e != unix.ESRCH {
			return e
		}
		select {
		case <-completed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return stop, completed, nil
}

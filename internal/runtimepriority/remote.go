package runtimepriority

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Remote executes the fixed guest actions. Root paths and hooks are dependencies
// of the Go library; they are never accepted from the wire request.
type Remote struct {
	CgroupRoot, ProcRoot, ProbeBase, RunRoot string
	Witness                                  func(int64) (Object, error)
	Signal                                   func(int64) error
	BeforeOpenFile                           func(string, bool)
	WriteLimit                               func(int, int64) error
	ScopeLauncher                            func([]string) (func(context.Context) error, <-chan error, error)
	Command                                  func(context.Context, []string, []byte, time.Duration, int) ([]byte, error)
}

func (m *Remote) roots() {
	if m.CgroupRoot == "" {
		m.CgroupRoot = CgroupRoot
	}
	if m.ProcRoot == "" {
		m.ProcRoot = "/proc"
	}
	if m.ProbeBase == "" {
		m.ProbeBase = "/run/terrascale-d15"
	}
	if m.RunRoot == "" {
		m.RunRoot = "/run"
	}
}
func (m *Remote) command(ctx context.Context, argv []string, wire []byte, timeout time.Duration, max int) ([]byte, error) {
	if m.Command != nil {
		return m.Command(ctx, argv, wire, timeout, max)
	}
	return RunBounded(ctx, argv, wire, timeout, max)
}
func (m *Remote) witness(pid int64) (Object, error) {
	if m.Witness != nil {
		return m.Witness(pid)
	}
	root := filepath.Join(m.ProcRoot, strconv.FormatInt(pid, 10))
	stat, e := os.ReadFile(filepath.Join(root, "stat"))
	if e != nil {
		return nil, e
	}
	cg, e := os.ReadFile(filepath.Join(root, "cgroup"))
	if e != nil {
		return nil, e
	}
	boot, e := os.ReadFile(filepath.Join(m.ProcRoot, "sys/kernel/random/boot_id"))
	if e != nil {
		return nil, e
	}
	return Object{"pid": pid, "stat_raw": string(stat), "cgroup_raw": string(cg), "host_boot_id": strings.TrimSpace(string(boot))}, nil
}
func (m *Remote) actualPath(qualified string) string {
	return filepath.Join(m.CgroupRoot, strings.TrimPrefix(qualified, CgroupRoot))
}
func (m *Remote) nativeTarget(target Object, native, db string) string {
	a, b, _ := qualifiedRoleCgroups(native, str(target, "cgroup"))
	if a != native || b != db {
		fail("failure target differs from qualifier-pinned native role cgroup")
	}
	return m.actualPath(b)
}
func (m *Remote) assertWitness(target Object) Object {
	w, e := m.witness(n(target, "pid"))
	if e != nil {
		fail("target process witness unavailable: %v", e)
	}
	pid, start := procStatIdentity(str(w, "stat_raw"))
	group := procCgroupPath(str(w, "cgroup_raw"))
	targetGroup := str(target, "cgroup")
	targetGroup = strings.TrimPrefix(targetGroup, CgroupRoot)
	if pid != n(target, "pid") || start != str(target, "process_start") || group != targetGroup || w["host_boot_id"] != target["host_boot_id"] {
		fail("target PID reused, moved, or differs from immediate accepted witness")
	}
	return w
}
func (m *Remote) openDir(path string) (int, os.FileInfo) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		fail("cannot open exact native role cgroup: %v", e)
	}
	var opened unix.Stat_t
	if e := unix.Fstat(fd, &opened); e != nil {
		unix.Close(fd)
		fail("cannot inspect exact native cgroup")
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Ino != opened.Ino || uint64(info.Sys().(*syscall.Stat_t).Dev) != uint64(opened.Dev) {
		unix.Close(fd)
		fail("exact native cgroup changed during directory open")
	}
	return fd, info
}
func dirIdentity(path string, meta os.FileInfo) bool {
	named, e := os.Lstat(path)
	return e == nil && os.SameFile(meta, named)
}
func (m *Remote) openAt(fd int, name string, write bool) int {
	if m.BeforeOpenFile != nil {
		m.BeforeOpenFile(name, write)
	}
	flags := unix.O_RDONLY
	if write {
		flags = unix.O_WRONLY
	}
	f, e := unix.Openat(fd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		fail("cannot open native role %s: %v", name, e)
	}
	return f
}
func (m *Remote) readAt(fd int, name string) string {
	f := m.openAt(fd, name, false)
	file := os.NewFile(uintptr(f), name)
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, 4097))
	if e != nil || len(raw) > 4096 {
		fail("native cgroup file exceeds read bound")
	}
	return string(raw)
}
func setLimit(fd int, value int64) {
	raw := []byte(strconv.FormatInt(value, 10))
	if _, e := unix.Seek(fd, 0, 0); e != nil {
		fail("cannot seek memory.max: %v", e)
	}
	if written, e := unix.Write(fd, raw); e != nil || written != len(raw) {
		fail("native memory.max write incomplete")
	}
	_ = unix.Ftruncate(fd, int64(len(raw)))
}
func (m *Remote) cleanup(request Object) Object {
	runtime := sub(sub(request, "transport"), "runtime")
	_ = runtime
	path := m.scopePath(request)
	raw := ""
	if info, e := os.Lstat(path); e == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			fail("pressure cgroup path invalid")
		}
		raw = m.readCgroupProcs(path)
		children, e := os.ReadDir(path)
		if e != nil {
			fail("cannot inspect pressure cgroup cleanup")
		}
		for _, c := range children {
			if c.IsDir() {
				fail("pressure cgroup remains populated")
			}
		}
		if strings.TrimSpace(raw) != "" {
			fail("pressure cgroup remains populated")
		}
	}
	scratch := filepath.Join(str(sub(request, "pressure"), "io_directory"), "terrascale-d15-"+str(request, "run_id"))
	if _, e := os.Lstat(scratch); e == nil || !os.IsNotExist(e) {
		fail("run-scoped pressure scratch remains")
	}
	cleanup := Object{"pressure_cgroup_procs_raw": raw, "pressure_child_cgroups": []any{}, "scratch_paths": []any{}}
	if intent, ok := request["oom_restore_intent"].(map[string]any); ok {
		cleanup["oom_restore_verified"] = false
		cleanup["oom_restore_target"] = intent["target"]
		cleanup["oom_restore_cgroup_inode"] = nil
		cleanup["current_database_memory_max_bytes"] = nil
		cleanup["oom_restore_unresolved_reason"] = "cleanup did not reconcile pre-mutation restore intent"
		e := func() (err error) {
			defer recoverError(&err)
			target := sub(intent, "target")
			path := m.nativeTarget(target, str(intent, "native_runner_cgroup_path"), str(intent, "database_cgroup_path"))
			if str(target, "kind") != "terrabase" || intent["database_cgroup_path"] != request["protected_database_cgroup_path"] || intent["native_runner_cgroup_path"] != request["native_runner_cgroup_path"] || !same(intent["prior_memory_max_bytes"], sub(request, "qualification")["database_memory_max_bytes"]) {
				fail("restore intent differs from qualifier-pinned native target/cap")
			}
			w, e := m.witness(n(target, "pid"))
			if e == nil {
				pid, start := procStatIdentity(str(w, "stat_raw"))
				if pid != n(target, "pid") || start != str(target, "process_start") || procCgroupPath(str(w, "cgroup_raw")) != strings.TrimPrefix(str(target, "cgroup"), CgroupRoot) || w["host_boot_id"] != target["host_boot_id"] {
					fail("OOM restore target PID reused or moved to another cgroup")
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
			fd, meta := m.openDir(path)
			defer unix.Close(fd)
			inode := meta.Sys().(*syscall.Stat_t).Ino
			if inode != uint64(n(intent, "cgroup_inode")) || !dirIdentity(path, meta) {
				fail("exact TerraBase cgroup identity changed before cleanup")
			}
			current := integerText(m.readAt(fd, "memory.max"), "memory.max")
			prior, temp := n(intent, "prior_memory_max_bytes"), n(intent, "temporary_memory_max_bytes")
			cleanup["oom_restore_cgroup_inode"], cleanup["current_database_memory_max_bytes"] = inode, current
			if current == temp {
				if !dirIdentity(path, meta) {
					fail("exact TerraBase cgroup path changed before cap restore")
				}
				memoryFD := m.openAt(fd, "memory.max", true)
				func() { defer unix.Close(memoryFD); setLimit(memoryFD, prior) }()
				current = integerText(m.readAt(fd, "memory.max"), "memory.max")
				if !dirIdentity(path, meta) || current != prior {
					fail("exact TerraBase role memory.max restore could not be verified")
				}
				cleanup["current_database_memory_max_bytes"] = current
			} else if current != prior {
				fail("exact TerraBase role has an unknown cap or changed cgroup identity")
			} else if !dirIdentity(path, meta) {
				fail("exact TerraBase cgroup path changed during cap verification")
			}
			cleanup["oom_restore_verified"], cleanup["oom_restore_unresolved_reason"] = true, nil
			return
		}()
		if e != nil {
			reason := strings.NewReplacer("\n", " ", "\r", " ").Replace(e.Error())
			if len(reason) > 256 {
				reason = reason[:256]
			}
			cleanup["oom_restore_unresolved_reason"] = reason
		}
	}
	return Object{"cleanup": cleanup}
}
func (m *Remote) scopePath(request Object) string {
	p := sub(sub(request, "pressure"), "workload_cgroup")
	parent := str(p, "parent_path")
	if !safePath(parent) || !inside(parent, CgroupRoot) {
		fail("unsafe pressure workload slice")
	}
	id := str(request, "run_id")
	if !tokenRE.MatchString(id) {
		fail("unsafe pressure run ID")
	}
	return m.actualPath(filepath.Join(parent, "terrascale-d15-"+id+".scope"))
}
func (m *Remote) readCgroupProcs(path string) string {
	return readText(filepath.Join(path, "cgroup.procs"), 16384)
}
func (m *Remote) properties(ctx context.Context, request Object, unit string, keys []string) (string, Object) {
	argv := []string{str(sub(sub(request, "transport"), "runtime"), "systemctl_path"), "show", unit}
	for _, k := range keys {
		argv = append(argv, "--property="+k)
	}
	raw, e := m.command(ctx, argv, nil, 30*time.Second, 65536)
	if e != nil {
		fail("cannot inspect systemd properties")
	}
	return string(raw), parseProperties(string(raw), unit)
}
func (m *Remote) journal(ctx context.Context, request Object, cursor string) []any {
	runtime := sub(sub(request, "transport"), "runtime")
	argv := []string{str(runtime, "journalctl_path"), "--dmesg", "--output=json", "--no-pager", "--lines=4096"}
	if cursor != "" {
		argv = append(argv, "--after-cursor="+cursor)
	}
	raw, e := m.command(ctx, argv, nil, 20*time.Second, 1<<20)
	if e != nil {
		fail("cannot collect bounded kernel journal")
	}
	rows := []any{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		parsed, e := ParseKernelOOMRecord(line)
		if e != nil {
			continue
		}
		rows = append(rows, Object{"source": "kernel", "raw_record": line, "raw_record_sha256": Hash([]byte(line)), "parsed": parsed})
	}
	return rows
}
func (m *Remote) Dispatch(ctx context.Context, request Object, action string) (result Object, err error) {
	defer recoverError(&err)
	m.roots()
	payload, _ := request["remote_payload"].(map[string]any)
	runtimeSettings := sub(sub(request, "transport"), "runtime")
	switch action {
	case "proc_witness":
		return m.witness(n(payload, "pid"))
	case "uname":
		arch := runtime.GOARCH
		if arch == "arm64" {
			arch = "aarch64"
		}
		return Object{"architecture": arch}, nil
	case "oci_metadata":
		client := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		metadata := Object{}
		for key, path := range map[string]string{"instance_id": "id", "image_id": "image", "region": "regionInfo/regionIdentifier", "shape": "shape"} {
			req, e := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/opc/v2/instance/"+path, nil)
			if e != nil {
				return nil, e
			}
			req.Header.Set("Authorization", "Bearer Oracle")
			reply, e := client.Do(req)
			if e != nil {
				return nil, e
			}
			wire, e := io.ReadAll(io.LimitReader(reply.Body, 4097))
			reply.Body.Close()
			if e != nil || len(wire) > 4096 || reply.StatusCode != 200 {
				fail("OCI metadata unavailable or oversized")
			}
			metadata[key] = strings.TrimSpace(string(wire))
		}
		return Object{"oci_metadata": metadata}, nil
	case "service_state":
		role := str(request, "guest_role")
		if role != "host" && role != "controller" {
			fail("service state has no pinned guest role")
		}
		unit := str(sub(runtimeSettings, "service_names"), role)
		raw, props := m.properties(ctx, request, unit, []string{"ActiveState", "MainPID", "ControlGroup", "NRestarts"})
		pid := integerText(str(props, "MainPID"), "service MainPID")
		if pid <= 1 {
			fail("service has no active main process")
		}
		w, e := m.witness(pid)
		if e != nil {
			return nil, e
		}
		return Object{"guest_role": role, "units": Object{unit: Object{"systemctl_show_raw": raw, "process_stat_raw": w["stat_raw"], "process_cgroup_raw": w["cgroup_raw"]}}, "host_boot_id": w["host_boot_id"]}, nil
	case "qualify":
		return m.qualify(ctx, request)
	case "failure_inject":
		target := sub(request, "target_process")
		kind := str(target, "kind")
		if kind != "terrabase" && kind != "host_manager" {
			fail("failure target not approved SIGKILL scenario")
		}
		if kind == "terrabase" {
			m.nativeTarget(target, str(request, "native_runner_cgroup_path"), str(request, "protected_database_cgroup_path"))
		}
		if m.Signal == nil {
			pidfd, e := unix.PidfdOpen(int(n(target, "pid")), 0)
			if e != nil {
				return nil, e
			}
			defer unix.Close(pidfd)
			m.assertWitness(target)
			if kind == "host_manager" {
				_, props := m.properties(ctx, request, str(target, "unit"), []string{"ActiveState", "MainPID", "ControlGroup"})
				if str(props, "ActiveState") != "active" || integerText(str(props, "MainPID"), "manager MainPID") != n(target, "pid") || str(props, "ControlGroup")+"/supervisor" != str(target, "cgroup") {
					fail("host-manager unit no longer identifies witnessed PID")
				}
			}
			asked := utcNow()
			if e := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); e != nil {
				return nil, e
			}
			return Object{"action_receipt": Object{"target_process": target, "signal": "SIGKILL", "requested_at_utc": asked, "completed_at_utc": utcNow(), "exit_status": 0}}, nil
		}
		m.assertWitness(target)
		asked := utcNow()
		if e := m.Signal(n(target, "pid")); e != nil {
			return nil, e
		}
		return Object{"action_receipt": Object{"target_process": target, "signal": "SIGKILL", "requested_at_utc": asked, "completed_at_utc": utcNow(), "exit_status": 0}}, nil
	case "cleanup_verify":
		return m.cleanup(request), nil
	case "oom_watermark":
		target := sub(request, "oom_target")
		path := m.nativeTarget(target, str(request, "native_runner_cgroup_path"), str(request, "protected_database_cgroup_path"))
		m.assertWitness(target)
		prior := number(filepath.Join(path, "memory.max"))
		if prior != n(sub(request, "qualification"), "database_memory_max_bytes") {
			fail("native TerraBase role cap differs from signed pre-mutation cap")
		}
		argv := []string{str(runtimeSettings, "journalctl_path"), "--dmesg", "--output=json", "--no-pager", "--lines=1"}
		wire, e := m.command(ctx, argv, nil, 20*time.Second, 65536)
		if e != nil {
			return nil, e
		}
		raw := strings.TrimSpace(string(wire))
		if _, e := ParseJournalRecord(raw, "kernel"); e != nil {
			return nil, e
		}
		meta, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		intent := Object{"target": targetIdentity(target), "native_runner_cgroup_path": request["native_runner_cgroup_path"], "database_cgroup_path": request["protected_database_cgroup_path"], "cgroup_inode": meta.Sys().(*syscall.Stat_t).Ino, "prior_memory_max_bytes": prior, "temporary_memory_max_bytes": sub(sub(request, "pressure"), "oom_fault")["target_memory_max_bytes"]}
		return Object{"journal_watermark_raw_record": raw, "journal_watermark_raw_record_sha256": Hash([]byte(raw)), "events": []any{}, "oom_restore_intent": intent}, nil
	case "oom_collect":
		rows := m.journal(ctx, request, str(sub(request, "journal_watermark"), "cursor"))
		for _, v := range rows {
			delete(obj(v, "journal row"), "parsed")
		}
		return Object{"events": rows}, nil
	case "oom_fault":
		return m.oomFault(ctx, request)
	case "pressure_start":
		return m.pressureStart(ctx, request)
	case "pressure_status":
		return m.pressureObservation(ctx, request)
	case "pressure_stop":
		return m.pressureStop(ctx, request)
	default:
		fail("unsupported fixed remote action")
	}
	return
}
func (m *Remote) qualify(ctx context.Context, request Object) (Object, error) {
	settings := sub(sub(request, "transport"), "runtime")
	probe, e := OpenPinnedProbe(m.ProbeBase, str(request, "probe_source_revision"), str(settings, "qualify_sha256"), str(settings, "qualify_path"), 0)
	if e != nil {
		return nil, e
	}
	defer probe.Close()
	temp, e := os.MkdirTemp(m.RunRoot, "terrascale-d15-qualify-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(temp)
	evidence := filepath.Join(temp, "evidence")
	role := str(request, "guest_role")
	id, q := sub(request, "identity"), sub(request, "qualification")
	if role == "controller" {
		id, q = sub(request, "controller_identity"), sub(request, "controller_qualification")
	}
	argv := []string{"runtime-priority", "qualify", "qualify", "--role", role, "--evidence-dir", evidence}
	for _, k := range []string{"artifact_id", "config_id", "image_id", "oci_instance_id", "profile_id"} {
		argv = append(argv, "--"+strings.ReplaceAll(k, "_", "-"), str(id, k))
	}
	for _, k := range []string{"expected_system_slice_memory_min_bytes", "expected_system_slice_memory_low_bytes", "system_reserve_bytes", "allocatable_memory_bytes"} {
		argv = append(argv, "--"+strings.ReplaceAll(k, "_", "-"), strconv.FormatInt(n(q, k), 10))
	}
	if role == "host" {
		for _, k := range []string{"expected_memory_min_bytes", "expected_memory_low_bytes", "database_memory_max_bytes"} {
			argv = append(argv, "--"+strings.ReplaceAll(k, "_", "-"), strconv.FormatInt(n(q, k), 10))
		}
		argv = append(argv, "--database-pid", strconv.FormatInt(n(sub(request, "managed_process"), "pid"), 10))
	} else {
		for _, k := range []string{"expected_controller_memory_min_bytes", "expected_controller_memory_low_bytes"} {
			argv = append(argv, "--"+strings.ReplaceAll(k, "_", "-"), strconv.FormatInt(n(q, k), 10))
		}
	}
	deadline, cancel := context.WithTimeout(ctx, time.Duration(n(request, "deadline_seconds"))*time.Second)
	defer cancel()
	cmd := exec.CommandContext(deadline, "/proc/self/fd/3", argv...)
	cmd.ExtraFiles = []*os.File{probe}
	output := &boundedOutput{maximum: 1 << 20}
	cmd.Stdout, cmd.Stderr = output, output
	if e := cmd.Run(); e != nil {
		return nil, &DomainError{"HarnessError", "pinned native qualifier failed"}
	}
	summary, _, e := LoadJSON(filepath.Join(evidence, "summary.json"), 65536)
	if e != nil {
		return nil, e
	}
	commands, _, e := readNoFollow(filepath.Join(evidence, "commands.log"), 262144)
	if e != nil {
		return nil, e
	}
	if summary["qualifier_sha256"] != settings["qualify_sha256"] {
		fail("executed D15 probe reported different binary digest")
	}
	return Object{"summary": summary, "commands_log": string(commands)}, nil
}
func (m *Remote) oomFault(ctx context.Context, request Object) (result Object, err error) {
	defer recoverError(&err)
	target, intent := sub(request, "oom_target"), sub(request, "oom_restore_intent")
	path := m.nativeTarget(target, str(request, "native_runner_cgroup_path"), str(request, "protected_database_cgroup_path"))
	prior, temp := n(sub(request, "qualification"), "database_memory_max_bytes"), n(sub(sub(request, "pressure"), "oom_fault"), "target_memory_max_bytes")
	if !same(intent["target"], targetIdentity(target)) || intent["native_runner_cgroup_path"] != request["native_runner_cgroup_path"] || intent["database_cgroup_path"] != request["protected_database_cgroup_path"] || n(intent, "prior_memory_max_bytes") != prior || n(intent, "temporary_memory_max_bytes") != temp {
		fail("OOM mutation lacks exact pre-mutation native role restore intent")
	}
	m.assertWitness(target)
	fd, meta := m.openDir(path)
	defer unix.Close(fd)
	inode := meta.Sys().(*syscall.Stat_t).Ino
	if inode != uint64(n(intent, "cgroup_inode")) || !dirIdentity(path, meta) {
		fail("exact TerraBase cgroup path changed before OOM cap mutation")
	}
	memoryFD := m.openAt(fd, "memory.max", true)
	defer unix.Close(memoryFD)
	if !dirIdentity(path, meta) {
		fail("exact TerraBase cgroup path changed before OOM cap mutation")
	}
	m.assertWitness(target)
	current := integerText(m.readAt(fd, "memory.current"), "memory.current")
	members := []int64{}
	for _, s := range strings.Fields(m.readAt(fd, "cgroup.procs")) {
		members = append(members, integerText(s, "cgroup PID"))
	}
	slices.Sort(members)
	entries, e := os.ReadDir(path)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if entry.IsDir() {
			fail("native OOM target has child cgroups")
		}
	}
	if integerText(m.readAt(fd, "memory.max"), "memory.max") != prior || temp >= prior || current <= temp || !same(members, []any{target["pid"]}) {
		fail("native role not single-process bounded OOM target above requested cap")
	}
	mutation := false
	restoreVerified := false
	restoreMethod := ""
	defer func() {
		if !mutation {
			return
		}
		method, restoreErr := m.restoreNativeCap(path, meta, fd, memoryFD, prior)
		if restoreErr == nil {
			restoreVerified = true
			restoreMethod = method
		}
		if restoreErr != nil {
			err = errors.Join(err, restoreErr)
		}
		if result != nil {
			receipt := sub(result, "memory_limit_receipt")
			receipt["restore_verified"], receipt["restore_method"], receipt["restored_memory_max_bytes"] = restoreVerified, restoreMethod, prior
		}
	}()
	mutation = true
	setLimit(memoryFD, temp)
	if !dirIdentity(path, meta) {
		fail("exact TerraBase cgroup path changed during OOM cap mutation")
	}
	deadline := time.Now().Add(time.Duration(n(sub(sub(request, "pressure"), "oom_fault"), "deadline_seconds")) * time.Second)
	var events []any
	matched := false
	for time.Now().Before(deadline) {
		events = m.journal(ctx, request, str(sub(request, "journal_watermark"), "cursor"))
		for _, v := range events {
			parsed := sub(obj(v, "journal row"), "parsed")
			if n(parsed, "victim_pid") == n(target, "pid") && str(parsed, "cgroup_path") == cgroupFilePath(str(target, "cgroup")) {
				matched = true
			}
		}
		if matched {
			w, e := m.witness(n(target, "pid"))
			if errors.Is(e, os.ErrNotExist) {
				break
			}
			if e == nil {
				_, start := procStatIdentity(str(w, "stat_raw"))
				if start != str(target, "process_start") {
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	if !matched {
		fail("kernel journal did not identify TerraBase bounded OOM victim")
	}
	if w, e := m.witness(n(target, "pid")); e == nil {
		_, start := procStatIdentity(str(w, "stat_raw"))
		if start == str(target, "process_start") {
			fail("kernel OOM record arrived before exact TerraBase process exited")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	for _, v := range events {
		delete(obj(v, "journal row"), "parsed")
	}
	result = Object{"events": events, "memory_limit_receipt": Object{"target": targetIdentity(target), "prior_memory_max_bytes": prior, "temporary_memory_max_bytes": temp, "observed_memory_current_bytes": current, "target_cgroup_members_before": members, "target_child_cgroups_before": []any{}, "target_cgroup_inode_before": inode}}
	return
}

func (m *Remote) restoreNativeCap(path string, original os.FileInfo, directoryFD, memoryFD int, prior int64) (method string, err error) {
	defer recoverError(&err)
	sameFD := func() (err error) {
		defer recoverError(&err)
		if m.WriteLimit != nil {
			if e := m.WriteLimit(memoryFD, prior); e != nil {
				return e
			}
		} else {
			setLimit(memoryFD, prior)
		}
		restored := integerText(m.readAt(directoryFD, "memory.max"), "restored memory.max")
		if restored != prior || !dirIdentity(path, original) {
			fail("original TerraBase role no longer matches its cgroup descriptor")
		}
		return
	}()
	if sameFD == nil {
		return "same_cgroup_fd", nil
	}
	recreated := func() (err error) {
		defer recoverError(&err)
		fd, meta := m.openDir(path)
		defer unix.Close(fd)
		if meta.Sys().(*syscall.Stat_t).Ino == original.Sys().(*syscall.Stat_t).Ino || !dirIdentity(path, meta) {
			fail("native role was not recreated at the exact qualified path")
		}
		if integerText(m.readAt(fd, "memory.max"), "recreated role memory.max") != prior || !dirIdentity(path, meta) {
			fail("recreated native role lacks its signed memory cap")
		}
		return
	}()
	if recreated == nil {
		return "native_role_recreated", nil
	}
	fail("exact TerraBase role memory.max could not be restored and verified")
	return
}

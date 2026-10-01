package runtimepriority

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Qualifier dependencies default to the live guest. Tests supply isolated roots
// and a command executor, without replacing any qualification decision.
type Qualifier struct {
	Args                                                    Object
	BakedProfile                                            func() (Object, error)
	CgroupRoot, ProcRoot, ProfilePath, UnitRoot, Executable string
	Command                                                 func(context.Context, []string) (string, error)
	AfterDirectoryOpen                                      func(string)
	ChildVisited                                            func(string)
	Log                                                     []string
}

func (p *Qualifier) roots() {
	if p.CgroupRoot == "" {
		p.CgroupRoot = CgroupRoot
	}
	if p.ProcRoot == "" {
		p.ProcRoot = "/proc"
	}
	if p.ProfilePath == "" {
		p.ProfilePath = "/etc/terrascale-orchestrator/runtime-priority.json"
	}
	if p.UnitRoot == "" {
		p.UnitRoot = "/etc/systemd/system"
	}
	if p.Executable == "" {
		p.Executable, _ = os.Executable()
	}
}
func (p *Qualifier) command(ctx context.Context, argv []string) string {
	var raw string
	var e error
	if p.Command != nil {
		raw, e = p.Command(ctx, argv)
	} else {
		childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(childCtx, argv[0], argv[1:]...)
		var b []byte
		b, e = cmd.CombinedOutput()
		raw = string(b)
	}
	p.Log = append(p.Log, fmt.Sprintf("$ %s\nstdout:\n%sstderr/error:\n%v", strings.Join(argv, " "), raw, e))
	if e != nil {
		qfail("command failed: %s: %v", strings.Join(argv, " "), e)
	}
	return strings.TrimSpace(raw)
}

var unitProperties = []string{"ActiveState", "MainPID", "ControlGroup", "Nice", "OOMScoreAdjust", "CPUWeight", "IOWeight", "CPUSchedulingPolicy", "IOSchedulingClass", "IOSchedulingPriority", "ManagedOOMPreference", "Delegate", "DelegateSubgroup", "MemoryMin", "MemoryLow"}

func (p *Qualifier) unit(ctx context.Context, name string) Object {
	argv := []string{"systemctl", "show", name}
	for _, k := range unitProperties {
		argv = append(argv, "--property="+k)
	}
	o := parseProperties(p.command(ctx, argv), name)
	for _, k := range unitProperties {
		if _, ok := o[k]; !ok {
			qfail("%s: systemd lacks required property %s", name, k)
		}
	}
	return o
}
func unitPriority(name string, o Object, host bool) int64 {
	expected := Object{"ActiveState": "active", "Nice": "-20", "OOMScoreAdjust": "-1000", "CPUWeight": "10000", "IOWeight": "10000", "CPUSchedulingPolicy": "other", "IOSchedulingPriority": "0", "ManagedOOMPreference": "omit"}
	ioClass := str(o, "IOSchedulingClass")
	if ioClass != "2" && ioClass != "best-effort" {
		qfail("%s: IOSchedulingClass must be best-effort", name)
	}
	if host {
		expected["Delegate"] = "yes"
		expected["DelegateSubgroup"] = "supervisor"
	}
	for k, w := range expected {
		if str(o, k) != w {
			qfail("%s: systemctl show %s=%q, expected %q", name, k, str(o, k), w)
		}
	}
	pid, e := strconv.ParseInt(str(o, "MainPID"), 10, 64)
	if e != nil || pid <= 1 {
		qfail("%s: no running MainPID", name)
	}
	if !safePath(str(o, "ControlGroup")) || str(o, "ControlGroup") == "/" {
		qfail("%s: empty/unsafe ControlGroup", name)
	}
	return pid
}
func ProcStatIdentity(raw string) (pid int64, start string, err error) {
	defer recoverError(&err)
	pid, start = procStatIdentity(raw)
	return
}
func procStatIdentity(raw string) (int64, string) {
	before, after, ok := strings.CutLast(raw, ")")
	if !ok {
		fail("invalid /proc stat identity")
	}
	pidPart, _, ok := strings.Cut(before, " (")
	if !ok {
		fail("invalid /proc stat process name")
	}
	pid, e := strconv.ParseInt(pidPart, 10, 64)
	fields := strings.Fields(after)
	if e != nil || pid <= 1 || len(fields) < 20 || !decimalRE.MatchString(fields[19]) {
		fail("invalid /proc stat PID/start time")
	}
	return pid, fields[19]
}
func ProcCgroupPath(raw string) (path string, err error) {
	defer recoverError(&err)
	path = procCgroupPath(raw)
	return
}
func procCgroupPath(raw string) string {
	var path string
	count := 0
	for line := range strings.SplitSeq(strings.TrimSpace(raw), "\n") {
		if s, ok := strings.CutPrefix(line, "0::"); ok {
			count++
			path = s
		}
	}
	if count != 1 || !safePath(path) || path == "/" {
		fail("process cgroup must be one safe cgroup-root-relative path")
	}
	return path
}
func (p *Qualifier) process(ctx context.Context, pid int64, label string, protected bool) Object {
	proc := filepath.Join(p.ProcRoot, strconv.FormatInt(pid, 10))
	raw := readText(filepath.Join(proc, "stat"), 16384)
	actual, start := procStatIdentity(raw)
	_, after, _ := strings.CutLast(raw, ")")
	fields := strings.Fields(after)
	if actual != pid || len(fields) < 39 {
		qfail("cannot inspect scheduling values for PID %d", pid)
	}
	nice, e := strconv.Atoi(fields[16])
	if e != nil {
		qfail("invalid process nice")
	}
	policy, e := strconv.Atoi(fields[38])
	if e != nil {
		qfail("invalid scheduler policy")
	}
	oom, e := strconv.Atoi(strings.TrimSpace(readText(filepath.Join(proc, "oom_score_adj"), 128)))
	if e != nil {
		qfail("invalid OOM score")
	}
	wantNice, wantOOM, wantIO := 0, 0, 4
	if protected {
		wantNice, wantOOM, wantIO = -20, -1000, 0
	}
	if nice != wantNice || oom != wantOOM || policy != 0 {
		qfail("%s PID %d scheduling/OOM priorities differ from protected=%t", label, pid, protected)
	}
	ionice := p.command(ctx, []string{"ionice", "-p", strconv.FormatInt(pid, 10)})
	m := regexp.MustCompile(`(none|realtime|best-effort|idle):\s*prio\s+(\d+)`).FindStringSubmatch(ionice)
	if len(m) != 3 || m[1] != "best-effort" || m[2] != strconv.Itoa(wantIO) {
		qfail("%s PID %d: unexpected ionice %q", label, pid, ionice)
	}
	cg := procCgroupPath(readText(filepath.Join(proc, "cgroup"), 16384))
	return Object{"pid": pid, "nice": nice, "scheduler_policy": policy, "oom_score_adj": oom, "process_start_time": start, "io_class": "best-effort", "io_priority": wantIO, "cgroup": filepath.Join(p.CgroupRoot, cg)}
}
func number(path string) int64 { return integerText(readText(path, 128), path) }
func ioWeight(path, device string) int64 {
	for line := range strings.SplitSeq(strings.TrimSpace(readText(filepath.Join(path, "io.weight"), 16384)), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && (f[0] == device || f[0] == "default") {
			return integerText(f[1], "io.weight")
		}
	}
	qfail("%s missing numeric I/O weight", path)
	return 0
}
func priorityGroup(path string, cpu, io int64, label string) Object {
	actualCPU := number(filepath.Join(path, "cpu.weight"))
	actualIO := ioWeight(path, "default")
	if actualCPU != cpu || actualIO != io {
		qfail("%s: cpu.weight=%d io.weight=%d expected %d/%d", label, actualCPU, actualIO, cpu, io)
	}
	return Object{"cpu_weight": actualCPU, "io_weight": actualIO}
}
func cpuMax(path string) string {
	f := strings.Fields(readText(filepath.Join(path, "cpu.max"), 128))
	if len(f) != 2 {
		qfail("invalid cpu.max at %s", path)
	}
	return strings.Join(f, " ")
}
func xattr(path, name string) any {
	b := make([]byte, 128)
	n, e := unix.Getxattr(path, name, b)
	if e == unix.ENODATA {
		return nil
	}
	if e != nil {
		qfail("cannot inspect %s on %s: %v", name, path, e)
	}
	return string(b[:n])
}
func oomd(protected, workloads map[string]string) Object {
	o := Object{"omit": Object{}, "avoid": Object{}}
	for label, path := range protected {
		omit, avoid := xattr(path, "user.oomd_omit"), xattr(path, "user.oomd_avoid")
		if omit != "1" || avoid != nil {
			qfail("%s: expected systemd-oomd omit='1' only", label)
		}
		sub(o, "omit")[label] = omit
		sub(o, "avoid")[label] = avoid
	}
	for label, path := range workloads {
		omit, avoid := xattr(path, "user.oomd_omit"), xattr(path, "user.oomd_avoid")
		if omit != nil || avoid != nil {
			qfail("%s workload must stay eligible for systemd-oomd", label)
		}
		sub(o, "omit")[label] = omit
		sub(o, "avoid")[label] = avoid
	}
	return o
}
func ValidateBakedProfile(wire []byte, mode os.FileMode, uid, gid uint32, links uint64, profile string, reserve int64) (result Object, err error) {
	defer recoverError(&err)
	if !mode.IsRegular() || mode.Perm() != 0644 || uid != 0 || gid != 0 || links != 1 {
		qfail("baked runtime-priority profile must be a root-owned regular 0644 file with one link")
	}
	if len(wire) == 0 || len(wire) > 4096 {
		qfail("baked runtime-priority profile has invalid size")
	}
	var o Object
	if e := jsonUnmarshal(wire, &o); e != nil {
		qfail("baked runtime-priority profile is invalid JSON: %v", e)
	}
	if !exact(o, "version", "profile_id", "system_reserve_bytes") {
		qfail("baked runtime-priority profile has an unsupported schema")
	}
	expected := Object{"version": 1, "profile_id": profile, "system_reserve_bytes": reserve}
	if !same(o, expected) {
		qfail("baked runtime-priority profile ID/reserve differs from the requested signed placement profile")
	}
	canonical := fmt.Sprintf(`{"version":1,"profile_id":%s,"system_reserve_bytes":%d}`, Canonical(profile), reserve)
	if string(wire) != canonical {
		qfail("baked runtime-priority profile is not canonical JSON")
	}
	result = expected
	result["sha256"] = Hash(wire)
	return
}
func (p *Qualifier) VerifyBakedProfile() (Object, error) {
	p.roots()
	b, m, e := readNoFollow(p.ProfilePath, 4096)
	if e != nil {
		return nil, &DomainError{"QualificationError", fmt.Sprintf("cannot inspect baked runtime-priority profile: %v", e)}
	}
	st := m.Sys().(*syscall.Stat_t)
	o, e := ValidateBakedProfile(b, m.Mode(), st.Uid, st.Gid, uint64(st.Nlink), str(p.Args, "profile_id"), n(p.Args, "system_reserve_bytes"))
	if e == nil {
		o["path"] = p.ProfilePath
	}
	return o, e
}
func PackagedSourceIdentity() (any, string) { return nil, "/etc/systemd/system" }
func (p *Qualifier) memoryBudget(values Object, service string) Object {
	role := str(p.Args, "role")
	prefix := "expected_memory_"
	if role == "controller" {
		prefix = "expected_controller_memory_"
	}
	mi, lo := n(p.Args, prefix+"min_bytes"), n(p.Args, prefix+"low_bytes")
	smi, slo, reserve, alloc := n(p.Args, "expected_system_slice_memory_min_bytes"), n(p.Args, "expected_system_slice_memory_low_bytes"), n(p.Args, "system_reserve_bytes"), n(p.Args, "allocatable_memory_bytes")
	for _, v := range []int64{mi, lo, smi, slo, reserve, alloc} {
		if v <= 0 || v%int64(os.Getpagesize()) != 0 {
			qfail("memory profile values must be positive, page-aligned bytes")
		}
	}
	if mi > lo || smi < mi || slo < lo || smi > slo || slo > reserve {
		qfail("%s and system.slice memory floors exceed the signed reserve", role)
	}
	if str(values, "MemoryMin") != strconv.FormatInt(mi, 10) || str(values, "MemoryLow") != strconv.FormatInt(lo, 10) {
		qfail("%s unit memory floors differ from profile", role)
	}
	system := filepath.Dir(service)
	if filepath.Base(system) != "system.slice" {
		qfail("%s unit is not a child of system.slice", role)
	}
	actual := Object{role + "_memory_min_bytes": number(filepath.Join(service, "memory.min")), role + "_memory_low_bytes": number(filepath.Join(service, "memory.low")), "system_slice_memory_min_bytes": number(filepath.Join(system, "memory.min")), "system_slice_memory_low_bytes": number(filepath.Join(system, "memory.low"))}
	if n(actual, role+"_memory_min_bytes") != mi || n(actual, role+"_memory_low_bytes") != lo || n(actual, "system_slice_memory_min_bytes") != smi || n(actual, "system_slice_memory_low_bytes") != slo {
		qfail("%s/system.slice memory protections differ from profile", role)
	}
	if role == "host" {
		super := filepath.Join(service, "supervisor")
		actual["supervisor_memory_min_bytes"] = number(filepath.Join(super, "memory.min"))
		actual["supervisor_memory_low_bytes"] = number(filepath.Join(super, "memory.low"))
		if n(actual, "supervisor_memory_min_bytes") != mi || n(actual, "supervisor_memory_low_bytes") != lo {
			qfail("host supervisor lacks service memory floors")
		}
	}
	ancestors := []any{}
	for cursor := system; cursor != p.CgroupRoot; cursor = filepath.Dir(cursor) {
		if !inside(cursor, p.CgroupRoot) {
			qfail("cgroup ancestor escaped unified root")
		}
		a, b := number(filepath.Join(cursor, "memory.min")), number(filepath.Join(cursor, "memory.low"))
		if a < mi || b < lo {
			qfail("ancestor %s below required service reservation", cursor)
		}
		ancestors = append(ancestors, Object{"service": role, "cgroup": cursor, "memory_min_bytes": a, "memory_low_bytes": b})
	}
	mem := regexp.MustCompile(`(?m)^MemTotal:\s+(\d+)\s+kB`).FindStringSubmatch(readText(filepath.Join(p.ProcRoot, "meminfo"), 16384))
	if len(mem) != 2 {
		qfail("cannot read physical memory total")
	}
	available := integerText(mem[1], "MemTotal") * 1024
	for cursor := service; ; cursor = filepath.Dir(cursor) {
		if cursor != p.CgroupRoot && !inside(cursor, p.CgroupRoot) {
			qfail("cgroup ancestor escaped unified root")
		}
		s := strings.TrimSpace(readText(filepath.Join(cursor, "memory.max"), 128))
		if s != "max" {
			available = min(available, integerText(s, "ancestor memory.max"))
		}
		if cursor == p.CgroupRoot {
			break
		}
	}
	if alloc > available-reserve {
		qfail("signed allocatable+reserve exceeds physical/ancestor limit")
	}
	actual["allocatable_memory_bytes"] = alloc
	actual["system_reserve_bytes"] = reserve
	actual["available_physical_and_ancestor_memory_bytes"] = available
	actual["ancestor_protections"] = ancestors
	return actual
}
func deriveQuota(service, root string, cpus int) int64 {
	if cpus <= 0 || cpus > 1024 {
		qfail("invalid CPU affinity count")
	}
	available := int64(cpus) * 100000
	for cursor := service; ; cursor = filepath.Dir(cursor) {
		if cursor != root && !inside(cursor, root) {
			qfail("CPU quota path escaped unified root")
		}
		f := strings.Fields(cpuMax(cursor))
		period := integerText(f[1], "CPU period")
		if period <= 0 {
			qfail("invalid CPU period")
		}
		if f[0] != "max" {
			quota := integerText(f[0], "CPU quota")
			if quota <= 0 {
				qfail("invalid ancestor CPU quota")
			}
			available = min(available, quota*100000/period)
		}
		if cursor == root {
			break
		}
	}
	result := available * 3 / 4
	if result < 1000 || result >= available {
		qfail("native workload CPU cap leaves no manager headroom")
	}
	return result
}
func (p *Qualifier) hostRuntime(ctx context.Context, pid int64, service string, process, weights Object) (Object, Object, Object) {
	for _, file := range []string{"cgroup.controllers", "cgroup.subtree_control"} {
		fields := strings.Fields(readText(filepath.Join(service, file), 1024))
		for _, want := range []string{"cpu", "io", "memory"} {
			if !slices.Contains(fields, want) {
				qfail("host service lacks delegated/enabled %s controller", want)
			}
		}
	}
	if !strings.HasPrefix(cpuMax(service), "max ") {
		qfail("host service has a CPU quota")
	}
	super := filepath.Join(service, "supervisor")
	superWeights := priorityGroup(super, 10000, 10000, "supervisor")
	roots, e := filepath.Glob(filepath.Join(service, "terrascale-host-*"))
	if e != nil || len(roots) != 1 {
		qfail("expected one native workload runner cgroup under %s", service)
	}
	runner := roots[0]
	runnerWeights := priorityGroup(runner, 1000, 1000, "native runner")
	var affinity unix.CPUSet
	if e := unix.SchedGetaffinity(int(pid), &affinity); e != nil {
		qfail("cannot inspect host CPU affinity: %v", e)
	}
	quota := deriveQuota(service, p.CgroupRoot, affinity.Count())
	expected := fmt.Sprintf("%d 100000", quota)
	if cpuMax(runner) != expected {
		qfail("native runner CPU cap differs from derived cap")
	}
	runnerMemory := Object{"memory_min_bytes": number(filepath.Join(runner, "memory.min")), "memory_low_bytes": number(filepath.Join(runner, "memory.low"))}
	if n(runnerMemory, "memory_min_bytes") != 0 || n(runnerMemory, "memory_low_bytes") != 0 {
		qfail("native runner inherited manager memory protection")
	}
	entries, e := os.ReadDir(runner)
	if e != nil {
		qfail("cannot inspect native roles: %v", e)
	}
	roles := Object{}
	workloads := map[string]string{"native_runner": runner}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(runner, entry.Name())
		if cpuMax(path) != expected {
			qfail("native role CPU cap differs from derived cap")
		}
		memory := Object{"memory_min_bytes": number(filepath.Join(path, "memory.min")), "memory_low_bytes": number(filepath.Join(path, "memory.low")), "memory_max": strings.TrimSpace(readText(filepath.Join(path, "memory.max"), 128))}
		if n(memory, "memory_min_bytes") != 0 || n(memory, "memory_low_bytes") != 0 {
			qfail("native role inherited manager memory protection")
		}
		roles[entry.Name()] = Object{"weights": priorityGroup(path, 1000, 1000, "native role"), "memory": memory}
		workloads["role:"+entry.Name()] = path
	}
	var database any
	if p.Args["database_pid"] != nil && n(p.Args, "database_pid") > 1 {
		db := p.process(ctx, n(p.Args, "database_pid"), "TerraBase", false)
		path := str(db, "cgroup")
		if !inside(path, runner) {
			qfail("TerraBase process outside native workload cgroup")
		}
		rel, _ := filepath.Rel(runner, path)
		role := strings.Split(rel, string(os.PathSeparator))[0]
		if _, ok := roles[role]; !ok {
			qfail("TerraBase process has no direct role cgroup")
		}
		if p.Args["database_memory_max_bytes"] != nil && str(sub(sub(roles, role), "memory"), "memory_max") != strconv.FormatInt(n(p.Args, "database_memory_max_bytes"), 10) {
			qfail("TerraBase memory.max differs from signed profile cap")
		}
		database = db
	} else if p.Args["database_memory_max_bytes"] != nil {
		qfail("--database-memory-max-bytes requires --database-pid")
	}
	return Object{"host_service": service, "host_service_weights": weights, "host_cpu_max": cpuMax(service), "host_supervisor_weights": superWeights, "native_runner": runner, "native_runner_weights": runnerWeights, "native_workload_cpu_max": expected, "native_runner_memory": runnerMemory, "roles": roles}, Object{"host_supervisor": process, "terrabase": database}, oomd(map[string]string{"host_service": service, "host_supervisor": super}, workloads)
}
func (p *Qualifier) Run(ctx context.Context) (result Object, err error) {
	defer recoverError(&err)
	p.roots()
	role := str(p.Args, "role")
	if role != "host" && role != "controller" {
		qfail("role must be host or controller")
	}
	name := HostUnit
	if role == "controller" {
		name = ControllerUnit
		if p.Args["database_pid"] != nil {
			qfail("controller guest cannot qualify a TerraBase PID")
		}
	}
	if v := str(p.Args, role+"_unit"); v != "" {
		name = v
	}
	version := strings.Split(p.command(ctx, []string{"systemctl", "--version"}), "\n")[0]
	match := regexp.MustCompile(`^systemd\s+(\d+)`).FindStringSubmatch(version)
	if len(match) != 2 || integerText(match[1], "systemd version") < 255 {
		qfail("target requires systemd 255 or newer")
	}
	values := p.unit(ctx, name)
	var profile Object
	var e error
	if p.BakedProfile != nil {
		profile, e = p.BakedProfile()
	} else {
		profile, e = p.VerifyBakedProfile()
	}
	if e != nil {
		panic(e)
	}
	pid := unitPriority(name, values, role == "host")
	service := filepath.Join(p.CgroupRoot, str(values, "ControlGroup"))
	process := p.process(ctx, pid, role, true)
	expected := service
	if role == "host" {
		expected = filepath.Join(service, "supervisor")
	}
	if str(process, "cgroup") != expected {
		qfail("%s process outside exact protected cgroup", role)
	}
	weights := priorityGroup(service, 10000, 10000, role+" service")
	memory := p.memoryBudget(values, service)
	var cgroups, processes, policy Object
	if role == "controller" {
		cap := cpuMax(service)
		if !strings.HasPrefix(cap, "max ") {
			qfail("controller service has a CPU quota")
		}
		cgroups = Object{"controller_service": service, "controller_weights": weights, "controller_cpu_max": cap}
		processes = Object{"controller": process}
		policy = oomd(map[string]string{"controller_service": service}, nil)
	} else {
		cgroups, processes, policy = p.hostRuntime(ctx, pid, service, process, weights)
	}
	sample, e := p.CaptureMemorySample(map[string]string{role + "_service": service, "system_slice": filepath.Dir(service)}, version)
	if e != nil {
		panic(e)
	}
	unitWire := readText(filepath.Join(p.UnitRoot, name), 1<<20)
	binary, _, e := readNoFollow(p.Executable, MaxProbeBytes)
	if e != nil {
		qfail("cannot hash qualifier binary: %v", e)
	}
	result = Object{"status": "PASS", "guest_role": role, "repository_revision": nil, "qualifier_sha256": Hash(binary), "baked_runtime_priority_profile": profile, "systemd_version": version, "units": Object{role: values}, "processes": processes, "cgroups": cgroups, "memory_usage_sample": sample, "memory_profile": memory, "systemd_oomd_policy": policy, "unit_sha256": Object{name: Hash([]byte(unitWire))}}
	for _, k := range []string{"oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id"} {
		result[k] = p.Args[k]
	}
	return
}
func RenderDropIns(args Object, out io.Writer) (err error) {
	defer recoverError(&err)
	keys := []string{"service_memory_min_bytes", "service_memory_low_bytes", "controller_memory_min_bytes", "controller_memory_low_bytes", "system_slice_memory_min_bytes", "system_slice_memory_low_bytes", "system_reserve_bytes"}
	for _, k := range keys {
		v := num(args[k], k, 1)
		if v%int64(os.Getpagesize()) != 0 {
			qfail("drop-in memory values must be positive, page-aligned bytes")
		}
	}
	mi, lo, cmi, clo, smi, slo, res := n(args, keys[0]), n(args, keys[1]), n(args, keys[2]), n(args, keys[3]), n(args, keys[4]), n(args, keys[5]), n(args, keys[6])
	if mi > lo || cmi > clo || smi > slo || slo > res {
		qfail("service/controller/system.slice floors must satisfy MemoryMin <= MemoryLow <= signed SystemReserveBytes")
	}
	if smi < mi+cmi || slo < lo+clo {
		qfail("system.slice floors must cover aggregate host and controller child floors")
	}
	id := str(args, "profile_id")
	if !tokenRE.MatchString(id) {
		qfail("profile ID must be a 1-128 character safe token")
	}
	root := str(args, "output_root")
	if !filepath.IsAbs(root) {
		qfail("--output-root must be an absolute image staging path")
	}
	resolved, e := filepath.EvalSymlinks(root)
	if e == nil {
		root = resolved
	}
	root = filepath.Clean(root)
	for _, path := range []string{"/", "/etc", "/usr", "/lib"} {
		if root == path || (path != "/" && inside(root, path)) {
			qfail("refusing to write systemd drop-ins into a live system directory")
		}
	}
	header := fmt.Sprintf("# Profile: %s\n# Signed SystemReserveBytes: %d\n# Explicit image-profile allocations; adequacy requires target pressure qualification.\n", id, res)
	for _, row := range []struct {
		unit, section string
		mi, lo        int64
	}{{"system.slice", "Slice", smi, slo}, {HostUnit, "Service", mi, lo}, {ControllerUnit, "Service", cmi, clo}} {
		path := filepath.Join(root, "etc/systemd/system", row.unit+".d/50-terrascale-memory-protection.conf")
		wire := []byte(fmt.Sprintf("%s[%s]\nMemoryMin=%d\nMemoryLow=%d\n", header, row.section, row.mi, row.lo))
		if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			return e
		}
		if old, e := os.ReadFile(path); e == nil {
			if string(old) != string(wire) {
				qfail("refusing to replace conflicting image profile drop-in: %s", path)
			}
		} else if os.IsNotExist(e) {
			f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if e != nil {
				return e
			}
			_, e = f.Write(wire)
			f.Close()
			if e != nil {
				return e
			}
		} else {
			return e
		}
		fmt.Fprintf(out, "%s sha256=%s\n", path, Hash(wire))
	}
	return
}
func (p *Qualifier) CaptureMemorySample(cgroups map[string]string, version string) (sample Object, err error) {
	defer recoverError(&err)
	p.roots()
	started := utcNow()
	rows := Object{}
	rootFD, e := unix.Open(p.CgroupRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		qfail("cannot anchor cgroup memory sample: %v", e)
	}
	defer unix.Close(rootFD)
	openDirectory := func(path string) (*os.File, error) {
		if !inside(path, p.CgroupRoot) {
			qfail("memory sample escaped cgroup root")
		}
		relative, e := filepath.Rel(p.CgroupRoot, path)
		if e != nil {
			return nil, e
		}
		fd, e := unix.Openat2(rootFD, relative, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if e != nil {
			return nil, e
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	sameDirectory := func(path string, meta os.FileInfo) bool {
		named, e := openDirectory(path)
		if e != nil {
			return false
		}
		defer named.Close()
		current, e := named.Stat()
		return e == nil && os.SameFile(meta, current)
	}
	var systemDir *os.File
	var systemMeta os.FileInfo
	for _, scope := range slices.Sorted(maps.Keys(cgroups)) {
		path := cgroups[scope]
		if !inside(path, p.CgroupRoot) {
			qfail("%s memory sample escaped cgroup root", scope)
		}
		dir, e := openDirectory(path)
		if e != nil {
			qfail("cannot capture %s cgroup memory: %v", scope, e)
		}
		defer dir.Close()
		fd := int(dir.Fd())
		func() {
			meta, e := dir.Stat()
			if e != nil {
				qfail("cannot inspect cgroup directory: %v", e)
			}
			if p.AfterDirectoryOpen != nil {
				p.AfterDirectoryOpen(path)
			}
			check := func(stage string) {
				if !sameDirectory(path, meta) {
					qfail("%s memory sample cgroup changed %s capture", scope, stage)
				}
			}
			check("before")
			read := func(name string, max int64) string {
				f, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if e != nil {
					qfail("cannot read cgroup %s: %v", name, e)
				}
				file := os.NewFile(uintptr(f), name)
				defer file.Close()
				b, e := io.ReadAll(io.LimitReader(file, max+1))
				if e != nil {
					qfail("cannot read cgroup %s: %v", name, e)
				}
				if int64(len(b)) > max {
					qfail("%s %s exceeds its fixed evidence bound", scope, name)
				}
				return string(b)
			}
			current, peak, stat := read("memory.current", 128), read("memory.peak", 128), read("memory.stat", 16384)
			check("during")
			rows[scope] = Object{"cgroup_path": path, "cgroup_inode": meta.Sys().(*syscall.Stat_t).Ino, "memory_current_raw": current, "memory_current_bytes": integerText(current, "memory.current"), "memory_peak_raw": peak, "memory_peak_bytes": integerText(peak, "memory.peak"), "memory_stat_raw": stat, "memory_stat_sha256": Hash([]byte(stat))}
			if scope == "system_slice" {
				systemDir, systemMeta = dir, meta
			}
		}()
	}
	system := cgroups["system_slice"]
	if systemDir == nil || !sameDirectory(system, systemMeta) {
		qfail("system.slice memory sample cgroup changed before child enumeration")
	}
	children := []string{}
	size := 0
	for {
		entries, e := systemDir.ReadDir(1)
		if e == io.EOF {
			break
		}
		if e != nil {
			qfail("cannot enumerate system.slice: %v", e)
		}
		entry := entries[0]
		if p.ChildVisited != nil {
			p.ChildVisited(entry.Name())
		}
		if entry.Type()&os.ModeSymlink != 0 {
			qfail("system.slice contains symlink while child scopes sampled")
		}
		if !entry.IsDir() {
			continue
		}
		size += len(entry.Name())
		if len(children) >= 256 || size > 16384 {
			qfail("system.slice child-cgroup list exceeds its fixed evidence bound")
		}
		children = append(children, entry.Name())
	}
	if !sameDirectory(system, systemMeta) {
		qfail("system.slice memory sample cgroup changed during child enumeration")
	}
	slices.Sort(children)
	var u unix.Utsname
	if e := unix.Uname(&u); e != nil {
		qfail("cannot read kernel release: %v", e)
	}
	release := string(u.Release[:])
	release, _, _ = strings.Cut(release, "\x00")
	sample = Object{"schema": MemorySampleSchema, "guest_role": str(p.Args, "role"), "host_boot_id": strings.TrimSpace(readText(filepath.Join(p.ProcRoot, "sys/kernel/random/boot_id"), 128)), "kernel_release": release, "systemd_version": version, "started_at_utc": started, "finished_at_utc": utcNow(), "scopes": rows, "system_slice_direct_child_cgroups": children}
	for _, k := range []string{"oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id"} {
		sample[k] = p.Args[k]
	}
	sample["sample_sha256"] = Hash(Canonical(sample))
	return
}

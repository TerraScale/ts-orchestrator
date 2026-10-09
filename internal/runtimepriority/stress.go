package runtimepriority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"golang.org/x/sys/unix"
)

const PressureWorkerStateSchema = "terrascale.d15.pressure-worker-state/v2"

var blockDeviceRE = regexp.MustCompile(`^[1-9][0-9]*:[0-9]+$`)

func pathWithin(path, parent string) bool { return path == parent || inside(path, parent) }
func resolve(path string) string {
	p, e := filepath.EvalSymlinks(path)
	if e != nil {
		fail("cannot resolve %s: %v", path, e)
	}
	p, e = filepath.Abs(p)
	if e != nil {
		fail("cannot resolve %s: %v", path, e)
	}
	return p
}
func rawText(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		fail("cannot read %s: %v", path, e)
	}
	return string(b)
}
func exists(path string) bool { _, e := os.Stat(path); return e == nil }

func blockChain(device, sysfs string, visiting map[string]bool) ([]any, []string) {
	if visiting[device] {
		fail("block-device backing graph contains a cycle at %s", device)
	}
	visiting[device] = true
	defer delete(visiting, device)
	node := resolve(filepath.Join(sysfs, "dev/block", device))
	devices := resolve(filepath.Join(sysfs, "devices"))
	if !pathWithin(node, devices) {
		fail("block device %s does not resolve inside sysfs devices", device)
	}
	if strings.TrimSpace(rawText(filepath.Join(node, "dev"))) != device {
		fail("block device %s has a mismatched sysfs device number", device)
	}
	sizeText := strings.TrimSpace(rawText(filepath.Join(node, "size")))
	size := integerText(sizeText, "sysfs device size")
	if size <= 0 {
		fail("block device %s has no positive sysfs size", device)
	}
	if filepath.Base(resolve(filepath.Join(node, "subsystem"))) != "block" {
		fail("device %s is not exposed by the sysfs block subsystem", device)
	}
	name := filepath.Base(node)
	if exists(filepath.Join(node, "loop")) || strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "zram") {
		fail("pseudo block device %s is not an eligible scratch backing", device)
	}
	slaveDir := filepath.Join(node, "slaves")
	slaveNames := []string{}
	if st, e := os.Stat(slaveDir); e == nil && st.IsDir() {
		entries, e := os.ReadDir(slaveDir)
		if e != nil {
			fail("cannot enumerate block-device backing for %s: %v", device, e)
		}
		for _, entry := range entries {
			slaveNames = append(slaveNames, entry.Name())
		}
		slices.Sort(slaveNames)
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		fail("cannot enumerate block-device backing for %s: %v", device, e)
	}
	var parent any
	if st, e := os.Stat(filepath.Join(node, "partition")); e == nil && st.Mode().IsRegular() {
		parent = strings.TrimSpace(rawText(filepath.Join(filepath.Dir(node), "dev")))
		if !blockDeviceRE.MatchString(parent.(string)) {
			fail("partition %s has an invalid parent block-device number", device)
		}
	}
	slaves := []string{}
	rootNode := Object{"device": device, "sysfs_path": node, "slaves": slaves, "partition_parent": parent, "size_sectors": size, "subsystem": "block", "virtual": pathWithin(node, filepath.Join(devices, "virtual")), "pseudo": false}
	chain, leaves := []any{rootNode}, []string{}
	for _, slave := range slaveNames {
		child := strings.TrimSpace(rawText(filepath.Join(slaveDir, slave, "dev")))
		if !blockDeviceRE.MatchString(child) {
			fail("block slave %s has an invalid device number", slave)
		}
		slaves = append(slaves, child)
		c, l := blockChain(child, sysfs, visiting)
		chain = append(chain, c...)
		leaves = append(leaves, l...)
	}
	slices.Sort(slaves)
	rootNode["slaves"] = slaves
	if len(slaveNames) == 0 {
		if parent != nil {
			c, l := blockChain(parent.(string), sysfs, visiting)
			chain = append(chain, c...)
			leaves = append(leaves, l...)
		} else {
			if pathWithin(node, filepath.Join(devices, "virtual/block")) {
				fail("virtual block device %s has no physical block backing", device)
			}
			leaves = append(leaves, device)
		}
	}
	return chain, leaves
}

// ProveBlockBacking binds the actual scratch filesystem to a physical sysfs backing graph.
func ProveBlockBacking(path, mountinfo, sysfs string, deviceOverride *uint64) (result Object, err error) {
	defer recoverError(&err)
	if mountinfo == "" {
		mountinfo = "/proc/self/mountinfo"
	}
	if sysfs == "" {
		sysfs = "/sys"
	}
	target := resolve(path)
	var st unix.Stat_t
	if e := unix.Stat(target, &st); e != nil {
		fail("cannot identify scratch filesystem mount: %v", e)
	}
	device := uint64(st.Dev)
	if deviceOverride != nil {
		device = *deviceOverride
	}
	actual := fmt.Sprintf("%d:%d", unix.Major(device), unix.Minor(device))
	unescape := func(s string) string {
		return regexp.MustCompile(`\\([0-7]{3})`).ReplaceAllStringFunc(s, func(s string) string { n, _ := strconv.ParseUint(s[1:], 8, 8); return string(rune(n)) })
	}
	var mount Object
	best := -1
	for index, line := range strings.Split(strings.TrimSuffix(rawText(mountinfo), "\n"), "\n") {
		before, after, ok := strings.Cut(line, " - ")
		left, right := strings.Fields(before), strings.Fields(after)
		if !ok || len(left) < 6 || len(right) < 3 {
			fail("/proc/self/mountinfo line %d is malformed", index+1)
		}
		point := unescape(left[4])
		if left[2] != actual || !pathWithin(target, point) {
			continue
		}
		depth := len(strings.Split(filepath.Clean(point), string(filepath.Separator)))
		if depth > best {
			best = depth
			mount = Object{"mount_id": left[0], "mountpoint": point, "filesystem_type": right[0], "filesystem_source": unescape(right[1]), "filesystem_device": left[2]}
		}
	}
	if mount == nil {
		fail("scratch path %s has no mountinfo entry matching filesystem device %s", target, actual)
	}
	if strings.HasPrefix(actual, "0:") {
		fail("scratch filesystem is not directly backed by a block device")
	}
	chain, leaves := blockChain(actual, sysfs, map[string]bool{})
	if len(leaves) == 0 {
		fail("scratch filesystem has no physical block-device backing")
	}
	slices.Sort(leaves)
	leaves = slices.Compact(leaves)
	mount["block_device_chain"] = chain
	mount["block_leaf_devices"] = leaves
	return mount, nil
}

func array(v any, label string) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	if a, ok := v.([]string); ok {
		b := make([]any, len(a))
		for i, s := range a {
			b[i] = s
		}
		return b
	}
	if a, ok := v.([]int); ok {
		b := make([]any, len(a))
		for i, s := range a {
			b[i] = s
		}
		return b
	}
	fail("%s must be a list", label)
	return nil
}

func ValidateBlockBackingEvidence(value any, expectedDevice string) (result Object, err error) {
	defer recoverError(&err)
	e := obj(value, "pressure_cgroup.io_backing")
	if e["filesystem_device"] != expectedDevice {
		fail("scratch mount device differs from the pinned pressure I/O device")
	}
	if !strings.HasPrefix(str(e, "mountpoint"), "/") {
		fail("scratch mount evidence has no absolute mountpoint")
	}
	if str(e, "filesystem_type") == "" {
		fail("scratch mount evidence omits its filesystem type")
	}
	chain, leaves := array(e["block_device_chain"], "block chain"), array(e["block_leaf_devices"], "block leaves")
	if len(chain) == 0 || len(leaves) == 0 {
		fail("scratch mount evidence has no sysfs block-device backing chain")
	}
	byDevice := map[string]Object{}
	for i, item := range chain {
		node := obj(item, fmt.Sprintf("pressure_cgroup.io_backing.block_device_chain[%d]", i))
		device, path := str(node, "device"), str(node, "sysfs_path")
		_, virtualOK := node["virtual"].(bool)
		parent := node["partition_parent"]
		parentOK := parent == nil
		if _, ok := parent.(string); ok {
			parentOK = true
		}
		if !blockDeviceRE.MatchString(device) || !strings.HasPrefix(path, "/sys/devices/") || node["subsystem"] != "block" || !virtualOK || node["pseudo"] != false || !parentOK {
			fail("scratch sysfs block-device node %d is malformed or ineligible", i)
		}
		for _, slave := range array(node["slaves"], "block slaves") {
			if _, ok := slave.(string); !ok {
				fail("scratch sysfs block-device node %d is malformed or ineligible", i)
			}
		}
		if num(node["size_sectors"], "size_sectors", 1) <= 0 {
			fail("scratch sysfs block-device node %d is malformed or ineligible", i)
		}
		if byDevice[device] != nil {
			fail("scratch sysfs block-device chain repeats a device")
		}
		byDevice[device] = node
	}
	if byDevice[expectedDevice] == nil {
		fail("scratch filesystem device is absent from its sysfs backing chain")
	}
	graphLeaves := []string{}
	for device, node := range byDevice {
		children := slices.Clone(array(node["slaves"], "block slaves"))
		if node["partition_parent"] != nil {
			children = append(children, node["partition_parent"])
		}
		for _, child := range children {
			if byDevice[child.(string)] == nil {
				fail("scratch sysfs backing chain omits a mapper or partition parent")
			}
		}
		if len(children) == 0 {
			if node["virtual"] == true || strings.Contains(str(node, "sysfs_path"), "/virtual/") {
				fail("scratch sysfs backing chain ends in a virtual block device")
			}
			graphLeaves = append(graphLeaves, device)
		}
	}
	claimed := []string{}
	for _, leaf := range leaves {
		claimed = append(claimed, text(leaf, "block leaf"))
	}
	slices.Sort(graphLeaves)
	slices.Sort(claimed)
	claimed = slices.Compact(claimed)
	if len(graphLeaves) == 0 || !slices.Equal(graphLeaves, claimed) {
		fail("scratch block leaves do not match the retained sysfs backing graph")
	}
	// Walk the full graph so disconnected nodes and cycles cannot fabricate a leaf proof.
	visiting, visited := map[string]bool{}, map[string]bool{}
	var walk func(string)
	walk = func(device string) {
		if visiting[device] {
			fail("scratch sysfs block-device backing graph contains a cycle")
		}
		if visited[device] {
			return
		}
		visiting[device] = true
		node := byDevice[device]
		for _, child := range array(node["slaves"], "slaves") {
			walk(child.(string))
		}
		if node["partition_parent"] != nil {
			walk(node["partition_parent"].(string))
		}
		delete(visiting, device)
		visited[device] = true
	}
	walk(expectedDevice)
	if len(visited) != len(byDevice) {
		fail("scratch sysfs backing chain contains disconnected devices")
	}
	return e, nil
}

func ParseJournalRecord(raw, transport string) (result Object, err error) {
	defer recoverError(&err)
	if len(raw) > 65536 {
		fail("raw journal record exceeds the 65536-byte limit")
	}
	var r Object
	if e := json.Unmarshal([]byte(raw), &r); e != nil {
		fail("raw journal record is not valid JSON: %v", e)
	}
	if r == nil {
		fail("raw journal record must be a JSON object")
	}
	for _, k := range []string{"__REALTIME_TIMESTAMP", "_BOOT_ID", "_CURSOR", "_TRANSPORT", "MESSAGE"} {
		if _, ok := r[k]; !ok {
			fail("raw journal record omits timestamp, boot ID, cursor, transport, or message")
		}
	}
	ts, boot, cursor, message := str(r, "__REALTIME_TIMESTAMP"), str(r, "_BOOT_ID"), str(r, "_CURSOR"), str(r, "MESSAGE")
	if !decimalRE.MatchString(ts) || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(boot) || cursor == "" || len([]rune(cursor)) > 4096 || r["_TRANSPORT"] != transport || message == "" || len(message) > 32768 {
		fail("raw journal record has an invalid timestamp/source/boot/cursor/message field")
	}
	micros, e := strconv.ParseInt(ts, 10, 64)
	if e != nil {
		fail("raw journal timestamp is outside the supported UTC range")
	}
	event := time.UnixMicro(micros).UTC()
	if event.Year() < 1 || event.Year() > 9999 {
		fail("raw journal timestamp is outside the supported UTC range")
	}
	return Object{"record": r, "boot_id": boot, "cursor": cursor, "message": message, "event_at_utc": event.Format("2006-01-02T15:04:05.000000Z")}, nil
}

func ParseKernelOOMRecord(raw string) (result Object, err error) {
	defer recoverError(&err)
	parsed, e := ParseJournalRecord(raw, "kernel")
	if e != nil {
		panic(e)
	}
	fields := map[string]string{}
	for field := range strings.SplitSeq(str(parsed, "message"), ",") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		if key == "pid" || key == "task_memcg" {
			if _, exists := fields[key]; exists {
				fail("kernel OOM journal record repeats the exact pid/cgroup field")
			}
			fields[key] = value
		}
	}
	if !decimalRE.MatchString(fields["pid"]) || !strings.HasPrefix(fields["task_memcg"], "/") {
		fail("kernel OOM journal record lacks one exact pid and task_memcg binding")
	}
	for _, part := range strings.Split(fields["task_memcg"], "/") {
		if part == ".." {
			fail("kernel OOM journal record has an unsafe task_memcg path")
		}
	}
	pid, e := strconv.ParseInt(fields["pid"], 10, 64)
	if e != nil {
		fail("kernel OOM journal PID is outside the supported range")
	}
	return Object{"victim_pid": pid, "cgroup_path": filepath.Join(CgroupRoot, strings.TrimLeft(fields["task_memcg"], "/")), "event_at_utc": parsed["event_at_utc"], "boot_id": parsed["boot_id"], "journal_cursor": parsed["cursor"]}, nil
}

func cgroupIOWeight(path, device string) int64 {
	weights := map[string]int64{}
	for line := range strings.SplitSeq(rawText(filepath.Join(path, "io.weight")), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && decimalRE.MatchString(fields[1]) {
			weights[fields[0]] = integerText(fields[1], "io.weight")
		}
	}
	if w, ok := weights[device]; ok {
		return w
	}
	if w, ok := weights["default"]; ok {
		return w
	}
	fail("%s/io.weight lacks a default weight", path)
	return 0
}

func AssertExclusiveCgroup(path string, expected []int) (result []int, err error) {
	defer recoverError(&err)
	want := slices.Clone(expected)
	slices.Sort(want)
	for i, pid := range want {
		if pid <= 1 || (i > 0 && want[i-1] == pid) {
			fail("expected pressure cgroup PIDs must be valid process IDs")
		}
	}
	entries, e := os.ReadDir(path)
	if e != nil {
		fail("cannot enumerate pressure cgroup %s: %v", path, e)
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			fail("pressure cgroup contains unexpected symlinks [%s]", entry.Name())
		}
		if entry.IsDir() {
			fail("pressure cgroup must be a leaf; found child cgroups [%s]", entry.Name())
		}
	}
	observed := []int{}
	for line := range strings.SplitSeq(strings.TrimSpace(rawText(filepath.Join(path, "cgroup.procs"))), "\n") {
		if line == "" {
			continue
		}
		pid, e := strconv.Atoi(line)
		if e != nil {
			fail("%s/cgroup.procs contains a malformed PID", path)
		}
		observed = append(observed, pid)
	}
	slices.Sort(observed)
	for i, pid := range observed {
		if pid <= 1 || (i > 0 && observed[i-1] == pid) {
			fail("%s/cgroup.procs contains invalid or duplicate PIDs", path)
		}
	}
	if !slices.Equal(observed, want) {
		fail("pressure cgroup process set %v differs from owned PIDs %v", observed, want)
	}
	return observed, nil
}

func PressureCgroupInventory(path string, expected []int, roles map[int]string, procRoot string) (result Object, err error) {
	defer recoverError(&err)
	pids, e := AssertExclusiveCgroup(path, expected)
	if e != nil {
		panic(e)
	}
	raw := rawText(filepath.Join(path, "cgroup.procs"))
	reread := []int{}
	for _, line := range strings.Fields(raw) {
		pid, e := strconv.Atoi(line)
		if e != nil {
			fail("cannot retain pressure cgroup process inventory: %v", e)
		}
		reread = append(reread, pid)
	}
	slices.Sort(reread)
	if !slices.Equal(reread, pids) {
		fail("pressure cgroup membership changed while inventory was captured")
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	processes := []any{}
	workers := []int{}
	for _, pid := range pids {
		stat := rawText(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
		cgroup := rawText(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
		rawPID, start := procStatIdentity(stat)
		if rawPID != int64(pid) {
			fail("raw /proc stat PID differs from pressure membership PID %d", pid)
		}
		role := roles[pid]
		if role == "" {
			role = "unknown"
			if pid == os.Getpid() {
				role = "pressure_runner"
			}
		}
		processes = append(processes, Object{"pid": pid, "process_start_time": start, "role": role, "process_stat_raw": stat, "process_cgroup_raw": cgroup})
		if slices.Contains([]string{"cpu_worker", "memory_worker", "io_worker"}, role) {
			workers = append(workers, pid)
		}
	}
	return Object{"process_pids": pids, "processes": processes, "worker_process_pids": workers, "cgroup_procs_raw": raw, "process_inventory_sha256": Hash(Canonical(processes))}, nil
}

func AssertPressureCgroup(config Object, nativeRunner, database string) (result Object, err error) {
	defer recoverError(&err)
	expected := sub(config, "workload_cgroup")
	relative := procCgroupPath(rawText(fmt.Sprintf("/proc/%d/cgroup", os.Getpid())))
	actual := resolve(filepath.Join(CgroupRoot, strings.TrimLeft(relative, "/")))
	expectedPath := resolve(str(expected, "path"))
	if actual != expectedPath {
		fail("pressure worker is in %s, expected %s", actual, expectedPath)
	}
	runnerPath, databasePath := resolve(nativeRunner), resolve(database)
	if pathWithin(databasePath, actual) {
		fail("pressure scope cannot share or contain TerraBase's native role cgroup")
	}
	if inside(actual, runnerPath) {
		fail("pressure scope must remain outside the manually owned native role tree")
	}
	parent := resolve(str(expected, "parent_path"))
	if filepath.Dir(actual) != parent {
		fail("pressure worker must run directly under its pinned systemd workload slice")
	}
	cpu, memory := strings.TrimSpace(rawText(filepath.Join(actual, "cpu.max"))), strings.TrimSpace(rawText(filepath.Join(actual, "memory.max")))
	backing, e := ProveBlockBacking(str(config, "io_directory"), "", "", nil)
	if e != nil {
		panic(e)
	}
	device := str(backing, "filesystem_device")
	if device != str(expected, "io_device") {
		fail("pressure filesystem device is %s, expected %s", device, str(expected, "io_device"))
	}
	weight := cgroupIOWeight(actual, device)
	if cpu != str(expected, "cpu_max") {
		fail("pressure cgroup cpu.max=%q, expected %q", cpu, str(expected, "cpu_max"))
	}
	if memory != strconv.FormatInt(n(expected, "memory_max_bytes"), 10) {
		fail("pressure cgroup memory.max=%q, expected %d", memory, n(expected, "memory_max_bytes"))
	}
	if weight != n(expected, "io_weight") {
		fail("pressure cgroup default io.weight=%d, expected %d", weight, n(expected, "io_weight"))
	}
	if !pathWithin(expectedPath, resolve(CgroupRoot)) {
		fail("pressure cgroup is outside the unified cgroup root")
	}
	inv, e := PressureCgroupInventory(expectedPath, []int{os.Getpid()}, nil, "")
	if e != nil {
		panic(e)
	}
	inv["path"] = actual
	inv["cpu_max"] = cpu
	inv["memory_max_bytes"] = integerText(memory, "memory.max")
	inv["io_weight"] = weight
	inv["io_device"] = device
	inv["io_backing"] = backing
	inv["pid"] = os.Getpid()
	return inv, nil
}

func ValidateStressWorkerManifest(manifest Object) (err error) {
	defer recoverError(&err)
	if manifest["schema"] != Schema {
		fail("stress manifest schema must be %q", Schema)
	}
	p := sub(manifest, "pressure")
	for _, key := range []string{"duration_seconds", "sample_interval_seconds", "cpu_workers", "memory_bytes", "memory_headroom_bytes", "io_workers", "io_file_bytes", "io_total_bytes", "io_bytes_per_second", "io_block_bytes"} {
		num(p[key], "stress pressure."+key, 1)
	}
	duration, cpus, ios, memory, headroom := n(p, "duration_seconds"), n(p, "cpu_workers"), n(p, "io_workers"), n(p, "memory_bytes"), n(p, "memory_headroom_bytes")
	if duration > 900 {
		fail("stress duration exceeds its harness bound")
	}
	if cpus > 64 || ios > 32 || memory > 16<<30 || headroom > 16<<30-memory {
		fail("stress worker count or memory request exceeds its harness bound")
	}
	file, total, rate, block := n(p, "io_file_bytes"), n(p, "io_total_bytes"), n(p, "io_bytes_per_second"), n(p, "io_block_bytes")
	if file > 2<<30 || file > 4<<30/ios || total > 64<<30 || rate > 128<<20 || total < rate*duration || block&(block-1) != 0 || file%block != 0 {
		fail("stress I/O request exceeds its finite worker bounds")
	}
	w := sub(p, "workload_cgroup")
	if !exact(w, "parent_path", "path", "cpu_max", "memory_max_bytes", "io_weight", "io_device") {
		fail("stress workload cgroup fields do not match the transient-scope contract")
	}
	for _, key := range []string{"parent_path", "path"} {
		value := text(w[key], "stress workload cgroup "+key)
		if !safePath(value) || value == CgroupRoot {
			fail("stress workload cgroup %s is not a safe cgroup path", key)
		}
	}
	fields := strings.Fields(str(w, "cpu_max"))
	if len(fields) != 2 || !decimalRE.MatchString(fields[0]) || !decimalRE.MatchString(fields[1]) || integerText(fields[0], "cpu.max") <= 0 || fields[1] != "100000" {
		fail("stress workload cpu_max must have an explicit finite 100000 period")
	}
	cap := num(w["memory_max_bytes"], "stress workload memory_max_bytes", 1)
	num(w["io_weight"], "stress workload io_weight", 1)
	if !blockDeviceRE.MatchString(str(w, "io_device")) {
		fail("stress workload I/O device must be a block device")
	}
	if memory > cap || headroom > cap-memory {
		fail("stress memory request exceeds its transient-scope memory.max")
	}
	if !filepath.IsAbs(str(p, "io_directory")) {
		fail("stress io_directory must be an absolute path")
	}
	return nil
}

func WritePressureWorkerState(path string, state Object) (wire, hash string, err error) {
	defer recoverError(&err)
	b := append(Canonical(state), '\n')
	if len(b) > 16<<10 {
		fail("pressure worker status record exceeds its fixed evidence bound")
	}
	tmp := path + ".tmp"
	if e := writeJSON(tmp, state, false); e != nil {
		return "", "", e
	}
	if e := os.Rename(tmp, path); e != nil {
		return "", "", e
	}
	return string(b), Hash(b), nil
}

var cpuSink atomic.Uint32

// RunResourceWorker executes a single bounded worker in the parent's cgroup.
// It is re-executed from the same binary so each role has a distinct Linux PID.
func RunResourceWorker(ctx context.Context, args []string, out io.Writer) (err error) {
	defer recoverError(&err)
	fs := flag.NewFlagSet("pressure resource-worker", flag.ContinueOnError)
	fs.SetOutput(out)
	kind := fs.String("kind", "", "worker role")
	directory := fs.String("directory", "", "scratch directory")
	memory := fs.Int64("memory", 0, "memory bytes")
	fileBytes := fs.Int64("file-bytes", 0, "scratch bytes")
	total := fs.Int64("total-bytes", 0, "byte budget")
	block := fs.Int64("block-bytes", 0, "write block bytes")
	rate := fs.Float64("rate", 0, "bytes per second")
	duration := fs.Int64("duration", 0, "duration seconds")
	id := fs.Int("id", 0, "worker ID")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected worker arguments")
	}
	if *duration < 1 || *duration > 900 {
		return fmt.Errorf("resource worker duration exceeds its harness bound")
	}
	// A lost parent cannot leave a resource worker running indefinitely.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*duration+10)*time.Second)
	defer cancel()
	switch *kind {
	case "cpu":
		var value uint32
		for ctx.Err() == nil {
			for range 65536 {
				value = value*33 + 7
			}
			cpuSink.Store(value)
		}
		return nil
	case "memory":
		if *memory <= 0 || *memory > 16<<30 {
			return fmt.Errorf("memory worker exceeds bound")
		}
		b, e := unix.Mmap(-1, 0, int(*memory), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
		if e != nil {
			return e
		}
		defer unix.Munmap(b)
		for offset := 0; offset < len(b); offset += os.Getpagesize() {
			if ctx.Err() != nil {
				return nil
			}
			b[offset] = 1
		}
		<-ctx.Done()
		return nil
	case "io":
		if !filepath.IsAbs(*directory) || *fileBytes <= 0 || *fileBytes > 2<<30 || *total <= 0 || *total > 64<<30 || *block <= 0 || *block > 2<<30 || *block > *fileBytes || *fileBytes%*block != 0 || *block&(*block-1) != 0 || *rate <= 0 || *rate > 128<<20 || math.IsNaN(*rate) || math.IsInf(*rate, 0) || *id < 0 || *id >= 32 {
			return fmt.Errorf("I/O worker exceeds finite bounds")
		}
		path := filepath.Join(*directory, fmt.Sprintf("io-%d.bin", *id))
		f, e := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		if e := f.Truncate(*fileBytes); e != nil {
			return e
		}
		payload := make([]byte, *block)
		written, offset := int64(0), int64(0)
		start := time.Now()
		deadline := start.Add(time.Duration(*duration) * time.Second)
		for ctx.Err() == nil && time.Now().Before(deadline) {
			if written >= *total {
				if e := stressPause(ctx, min(100*time.Millisecond, time.Until(deadline))); e != nil {
					break
				}
				continue
			}
			amount := min(*block, *total-written)
			count, e := f.WriteAt(payload[:amount], offset)
			if e != nil {
				return e
			}
			if int64(count) != amount {
				return io.ErrShortWrite
			}
			if e := unix.Fdatasync(int(f.Fd())); e != nil {
				return e
			}
			written += amount
			offset = (offset + amount) % *fileBytes
			next := start.Add(time.Duration(float64(written) / *rate * float64(time.Second)))
			if e := stressPause(ctx, time.Until(next)); e != nil {
				break
			}
		}
		if ctx.Err() == nil {
			<-ctx.Done()
		}
		_, e = fmt.Fprintln(out, string(Canonical(Object{"worker": *id, "bytes_written": written})))
		return e
	default:
		return fmt.Errorf("unknown pressure resource worker %q", *kind)
	}
}

func stressPause(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func monotonicNS() int64 {
	var t unix.Timespec
	if e := unix.ClockGettime(unix.CLOCK_MONOTONIC, &t); e != nil {
		fail("cannot read monotonic clock: %v", e)
	}
	return t.Nano()
}

type stressChild struct {
	cmd    *exec.Cmd
	done   chan error
	role   string
	stdout strings.Builder
	stderr strings.Builder
	reaped bool
	result error
}

func pinnedStressCommand(executable *os.File, args ...string) *exec.Cmd {
	cmd := exec.Command("/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{executable}
	return cmd
}

func RunStressWorker(ctx context.Context, manifest Object, nativeRunner, database, runID string, retain bool, out io.Writer) (err error) {
	defer recoverError(&err)
	if e := ValidateStressWorkerManifest(manifest); e != nil {
		return e
	}
	if !entityid.Valid(runID) {
		fail("stress worker requires the current qualification run ID")
	}
	p := sub(manifest, "pressure")
	cgroup, e := AssertPressureCgroup(p, nativeRunner, database)
	if e != nil {
		return e
	}
	target := str(p, "io_directory")
	st, e := os.Lstat(target)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		fail("pressure.io_directory must be an existing, non-symlink directory")
	}
	target = resolve(target)
	var stats unix.Statfs_t
	if e := unix.Statfs(target, &stats); e != nil {
		return e
	}
	available := uint64(stats.Bavail) * uint64(stats.Bsize)
	if uint64(n(p, "io_file_bytes"))*uint64(n(p, "io_workers")) > available {
		fail("pressure I/O working files exceed free bytes on the selected filesystem")
	}
	if e := unix.Access(target, unix.W_OK|unix.X_OK); e != nil {
		fail("pressure.io_directory is not writable by the workload identity")
	}
	work := filepath.Join(target, "terrascale-d15-"+runID)
	if e := os.Mkdir(work, 0700); e != nil {
		fail("run-scoped pressure scratch path already exists: %v", e)
	}
	children := []*stressChild{}
	completed := false
	statusPath := filepath.Join(work, "runner-status.json")
	defer func() {
		// Recover admission failures before cleanup so cleanup errors and retained
		// resource details remain joined to the original rejection.
		if recovered := recover(); recovered != nil {
			if domain, ok := recovered.(*DomainError); ok {
				err = domain
			} else {
				defer func() { panic(recovered) }()
			}
		}
		cleanup := []error{}
		for _, child := range children {
			if child.reaped {
				continue
			}
			_ = child.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case child.result = <-child.done:
				child.reaped = true
			case <-time.After(5 * time.Second):
				_ = child.cmd.Process.Kill()
				select {
				case child.result = <-child.done:
					child.reaped = true
				case <-time.After(5 * time.Second):
					cleanup = append(cleanup, fmt.Errorf("pressure child %d could not be reaped", child.cmd.Process.Pid))
				}
			}
		}
		if len(cleanup) > 0 {
			err = errors.Join(append([]error{err, fmt.Errorf("scratch retained at %s", work)}, cleanup...)...)
			return
		}
		if retain && completed {
			entries, e := os.ReadDir(work)
			if e != nil {
				cleanup = append(cleanup, e)
			}
			for _, entry := range entries {
				path := filepath.Join(work, entry.Name())
				if path != statusPath && !entry.IsDir() {
					if e := os.Remove(path); e != nil {
						cleanup = append(cleanup, e)
					}
				}
			}
		} else {
			if e := os.RemoveAll(work); e != nil {
				cleanup = append(cleanup, e)
			}
		}
		err = errors.Join(append([]error{err}, cleanup...)...)
	}()
	// /proc/self/exe intentionally follows the kernel's running executable
	// link. Retain that inode for every child rather than reopening a pathname
	// that could be replaced after its hash was recorded.
	executable, e := os.Open("/proc/self/exe")
	if e != nil {
		return e
	}
	defer executable.Close()
	digest := sha256.New()
	if _, e := io.Copy(digest, executable); e != nil {
		return e
	}
	harnessHash := hex.EncodeToString(digest.Sum(nil))
	roles := map[int]string{os.Getpid(): "pressure_runner"}
	started, startNS, start := utcNow(), monotonicNS(), time.Now()
	spawn := func(role string, args ...string) {
		child := &stressChild{role: role, done: make(chan error, 1)}
		argv := append([]string{"runtime-priority", "pressure", "resource-worker", "--kind", strings.TrimSuffix(role, "_worker")}, args...)
		child.cmd = pinnedStressCommand(executable, argv...)
		child.cmd.Stdout = &child.stdout
		child.cmd.Stderr = &child.stderr
		child.cmd.WaitDelay = 2 * time.Second
		if e := child.cmd.Start(); e != nil {
			fail("cannot start pressure %s: %v", role, e)
		}
		children = append(children, child)
		roles[child.cmd.Process.Pid] = role
		go func() { child.done <- child.cmd.Wait() }()
	}
	if n(p, "memory_bytes") > 0 {
		spawn("memory_worker", "--memory", strconv.FormatInt(n(p, "memory_bytes"), 10), "--duration", strconv.FormatInt(n(p, "duration_seconds"), 10))
	}
	for range n(p, "cpu_workers") {
		spawn("cpu_worker", "--duration", strconv.FormatInt(n(p, "duration_seconds"), 10))
	}
	ioWorkers, total := n(p, "io_workers"), n(p, "io_total_bytes")
	for index := range ioWorkers {
		budget := total / ioWorkers
		if index < total%ioWorkers {
			budget++
		}
		if budget == 0 {
			continue
		}
		spawn("io_worker", "--directory", work, "--file-bytes", strconv.FormatInt(n(p, "io_file_bytes"), 10), "--total-bytes", strconv.FormatInt(budget, 10), "--block-bytes", strconv.FormatInt(n(p, "io_block_bytes"), 10), "--rate", strconv.FormatFloat(float64(n(p, "io_bytes_per_second"))/float64(ioWorkers), 'f', -1, 64), "--duration", strconv.FormatInt(n(p, "duration_seconds"), 10), "--id", strconv.FormatInt(index, 10))
	}
	expected := []int{os.Getpid()}
	workerPIDs := []int{}
	roleRows := []any{}
	for _, child := range children {
		pid := child.cmd.Process.Pid
		relative := procCgroupPath(rawText(fmt.Sprintf("/proc/%d/cgroup", pid)))
		observed := resolve(filepath.Join(CgroupRoot, strings.TrimLeft(relative, "/")))
		if observed != str(cgroup, "path") {
			fail("pressure child PID %d escaped cgroup %s: %s", pid, str(cgroup, "path"), observed)
		}
		expected = append(expected, pid)
		workerPIDs = append(workerPIDs, pid)
	}
	slices.Sort(workerPIDs)
	for _, pid := range workerPIDs {
		roleRows = append(roleRows, Object{"pid": pid, "role": roles[pid]})
	}
	state := func(status string, finished any, finishedNS any) Object {
		active := workerPIDs
		if status == "COMPLETED" {
			active = []int{}
		}
		return Object{"schema": PressureWorkerStateSchema, "run_id": runID, "status": status, "started_at_utc": started, "started_monotonic_ns": startNS, "observed_at_utc": utcNow(), "elapsed_monotonic_ns": monotonicNS() - startNS, "worker_pids": active, "worker_roles": roleRows, "active_worker_pids": active, "finished_at_utc": finished, "finished_monotonic_ns": finishedNS}
	}
	record, hash, e := WritePressureWorkerState(statusPath, state("RUNNING", nil, nil))
	if e != nil {
		return e
	}
	startupInventory, e := PressureCgroupInventory(str(cgroup, "path"), expected, roles, "")
	if e != nil {
		return e
	}
	startup := clone(cgroup)
	for k, v := range startupInventory {
		startup[k] = v
	}
	startup["scratch_directory"] = work
	startup["status_file_path"] = statusPath
	startup["worker_state_record"] = record
	startup["worker_state_sha256"] = hash
	if _, e := fmt.Fprintln(out, string(Canonical(Object{"status": "STARTED", "harness_sha256": harnessHash, "pressure_cgroup": startup}))); e != nil {
		return e
	}
	deadline := start.Add(time.Duration(n(p, "duration_seconds")) * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, child := range children {
			select {
			case child.result = <-child.done:
				child.reaped = true
				fail("pressure worker PID %d exited before the configured duration", child.cmd.Process.Pid)
			default:
			}
		}
		if _, e := AssertExclusiveCgroup(str(cgroup, "path"), expected); e != nil {
			return e
		}
		if _, _, e := WritePressureWorkerState(statusPath, state("RUNNING", nil, nil)); e != nil {
			return e
		}
		if e := stressPause(ctx, min(250*time.Millisecond, time.Until(deadline))); e != nil {
			return e
		}
	}
	for _, child := range children {
		if e := child.cmd.Process.Signal(syscall.SIGTERM); e != nil {
			return e
		}
	}
	for _, child := range children {
		select {
		case child.result = <-child.done:
			child.reaped = true
			if child.result != nil {
				fail("pressure child PID %d did not finish within the configured duration: %v", child.cmd.Process.Pid, child.result)
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			fail("pressure child PID %d did not finish within the configured duration", child.cmd.Process.Pid)
		}
	}
	final, e := PressureCgroupInventory(str(cgroup, "path"), []int{os.Getpid()}, nil, "")
	if e != nil {
		return e
	}
	for k, v := range final {
		cgroup[k] = v
	}
	cgroup["owned_worker_pids"] = workerPIDs
	written := int64(0)
	for _, child := range children {
		if child.role != "io_worker" {
			continue
		}
		var count Object
		if e := json.Unmarshal([]byte(strings.TrimSpace(child.stdout.String())), &count); e != nil {
			fail("an I/O worker did not report its bounded byte count: %v", e)
		}
		written += n(count, "bytes_written")
	}
	elapsed := time.Since(start)
	if elapsed < time.Duration(n(p, "duration_seconds"))*time.Second {
		fail("pressure worker elapsed time is shorter than the configured duration")
	}
	finished, finishedNS := utcNow(), monotonicNS()
	record, hash, e = WritePressureWorkerState(statusPath, state("COMPLETED", finished, finishedNS))
	if e != nil {
		return e
	}
	cgroup["scratch_directory"] = work
	cgroup["status_file_path"] = statusPath
	cgroup["worker_state_record"] = record
	cgroup["worker_state_sha256"] = hash
	r := Object{"status": "PASS", "started_at_utc": started, "finished_at_utc": finished, "harness_sha256": harnessHash, "elapsed_seconds": float64(elapsed.Round(time.Millisecond)) / float64(time.Second), "pressure_cgroup": cgroup, "pressure_worker_state_record": record, "pressure_worker_state_sha256": hash, "cpu_workers": p["cpu_workers"], "memory_payload_bytes": p["memory_bytes"], "io_bytes_written": written, "io_total_bytes_limit": p["io_total_bytes"], "io_bytes_per_second_limit": p["io_bytes_per_second"], "io_file_bytes_per_worker": p["io_file_bytes"]}
	if _, e := fmt.Fprintln(out, string(Canonical(r))); e != nil {
		return e
	}
	completed = true
	return nil
}

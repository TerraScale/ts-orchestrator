package runtimepriority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func stressWrite(t *testing.T, path, text string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
}
func stressLink(t *testing.T, target, path string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, path); e != nil {
		t.Fatal(e)
	}
}

func TestPhysicalBlockBackingUsesMountDeviceAndRejectsPseudoDevice(t *testing.T) {
	root := t.TempDir()
	scratch := filepath.Join(root, "scratch with spaces")
	if e := os.Mkdir(scratch, 0700); e != nil {
		t.Fatal(e)
	}
	sysfs := filepath.Join(root, "sys")
	block := filepath.Join(sysfs, "devices/pci0000:00/block/sda")
	stressWrite(t, filepath.Join(block, "dev"), "8:0\n")
	stressWrite(t, filepath.Join(block, "size"), "12345\n")
	subsystem := filepath.Join(sysfs, "class/block")
	if e := os.MkdirAll(subsystem, 0755); e != nil {
		t.Fatal(e)
	}
	stressLink(t, subsystem, filepath.Join(block, "subsystem"))
	stressLink(t, block, filepath.Join(sysfs, "dev/block/8:0"))
	mountinfo := filepath.Join(root, "mountinfo")
	stressWrite(t, mountinfo, "36 25 8:0 / "+strings.ReplaceAll(scratch, " ", `\040`)+" rw - ext4 /dev/sda rw\n")
	device := unix.Mkdev(8, 0)
	evidence, e := ProveBlockBacking(scratch, mountinfo, sysfs, &device)
	if e != nil {
		t.Fatal(e)
	}
	if evidence["mountpoint"] != scratch || evidence["filesystem_device"] != "8:0" || evidence["filesystem_type"] != "ext4" {
		t.Fatal(evidence)
	}
	if !slices.Equal(evidence["block_leaf_devices"].([]string), []string{"8:0"}) {
		t.Fatal(evidence)
	}
	if e := os.Mkdir(filepath.Join(block, "loop"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := ProveBlockBacking(scratch, mountinfo, sysfs, &device); e == nil || !strings.Contains(e.Error(), "pseudo block device") {
		t.Fatal(e)
	}
}

func TestRetainedBlockGraphRejectsCycleAndMissingParent(t *testing.T) {
	leaf := Object{"device": "8:0", "sysfs_path": "/sys/devices/pci/block/sda", "slaves": []any{}, "partition_parent": nil, "subsystem": "block", "virtual": false, "pseudo": false, "size_sectors": 123}
	root := Object{"device": "253:0", "sysfs_path": "/sys/devices/virtual/block/dm-0", "slaves": []any{"8:0"}, "partition_parent": nil, "subsystem": "block", "virtual": true, "pseudo": false, "size_sectors": 123}
	evidence := Object{"filesystem_device": "253:0", "mountpoint": "/scratch", "filesystem_type": "ext4", "block_device_chain": []any{root, leaf}, "block_leaf_devices": []any{"8:0"}}
	if _, e := ValidateBlockBackingEvidence(evidence, "253:0"); e != nil {
		t.Fatal(e)
	}
	root["slaves"] = []any{"9:0"}
	if _, e := ValidateBlockBackingEvidence(evidence, "253:0"); e == nil || !strings.Contains(e.Error(), "omits") {
		t.Fatal(e)
	}
	root["slaves"] = []any{"253:0", "8:0"}
	if _, e := ValidateBlockBackingEvidence(evidence, "253:0"); e == nil || !strings.Contains(e.Error(), "cycle") {
		t.Fatal(e)
	}
}

func TestJournalOOMBindingsAndDuplicateFields(t *testing.T) {
	r := Object{"__REALTIME_TIMESTAMP": "1770000000123456", "_BOOT_ID": strings.Repeat("a", 32), "_CURSOR": "cursor", "_TRANSPORT": "kernel", "MESSAGE": "oom-kill:constraint=CONSTRAINT_MEMCG,pid=123,task_memcg=/workload/pressure.scope"}
	parsed, e := ParseKernelOOMRecord(string(Canonical(r)))
	if e != nil {
		t.Fatal(e)
	}
	if parsed["victim_pid"] != int64(123) || parsed["cgroup_path"] != "/sys/fs/cgroup/workload/pressure.scope" || parsed["boot_id"] != r["_BOOT_ID"] {
		t.Fatal(parsed)
	}
	r["MESSAGE"] = str(r, "MESSAGE") + ",pid=999"
	if _, e := ParseKernelOOMRecord(string(Canonical(r))); e == nil || !strings.Contains(e.Error(), "repeats") {
		t.Fatal(e)
	}
	r["MESSAGE"] = "pid=123,task_memcg=/workload/../database"
	if _, e := ParseKernelOOMRecord(string(Canonical(r))); e == nil || !strings.Contains(e.Error(), "unsafe") {
		t.Fatal(e)
	}
	if _, e := ParseJournalRecord(`{"MESSAGE":"one","MESSAGE":"two"}`, "kernel"); e == nil {
		t.Fatal("accepted duplicate fields")
	}
}

func TestCgroupInventoryRejectsUnexpectedProcessesAndCapturesRawIdentity(t *testing.T) {
	root := t.TempDir()
	group := filepath.Join(root, "group")
	stressWrite(t, filepath.Join(group, "cgroup.procs"), "123\n")
	proc := filepath.Join(root, "proc")
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[19] = "3456"
	stat := "123 (worker (name)) " + strings.Join(fields, " ")
	stressWrite(t, filepath.Join(proc, "123/stat"), stat)
	stressWrite(t, filepath.Join(proc, "123/cgroup"), "0::/workload/pressure.scope\n")
	r, e := PressureCgroupInventory(group, []int{123}, map[int]string{123: "cpu_worker"}, proc)
	if e != nil {
		t.Fatal(e)
	}
	process := r["processes"].([]any)[0].(Object)
	if process["process_start_time"] != "3456" || process["process_stat_raw"] != stat || r["process_inventory_sha256"] != Hash(Canonical(r["processes"])) {
		t.Fatal(r)
	}
	stressWrite(t, filepath.Join(group, "cgroup.procs"), "123\n999\n")
	if _, e := AssertExclusiveCgroup(group, []int{123}); e == nil || !strings.Contains(e.Error(), "differs from owned") {
		t.Fatal(e)
	}
	stressWrite(t, filepath.Join(group, "cgroup.procs"), "123\n")
	stressLink(t, root, filepath.Join(group, "unexpected"))
	if _, e := AssertExclusiveCgroup(group, []int{123}); e == nil || !strings.Contains(e.Error(), "symlinks") {
		t.Fatal(e)
	}
}

func TestIOResourceWorkerWritesOnlyItsFiniteByteBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	time.AfterFunc(150*time.Millisecond, cancel)
	dir := t.TempDir()
	var out bytes.Buffer
	e := RunResourceWorker(ctx, []string{"--kind", "io", "--directory", dir, "--file-bytes", "8192", "--total-bytes", "4096", "--block-bytes", "4096", "--rate", "131072", "--duration", "1", "--id", "0"}, &out)
	if e != nil {
		t.Fatal(e)
	}
	var count Object
	if e := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &count); e != nil {
		t.Fatal(e)
	}
	if n(count, "bytes_written") != 4096 {
		t.Fatal(count)
	}
	st, e := os.Stat(filepath.Join(dir, "io-0.bin"))
	if e != nil || st.Size() != 8192 || st.Mode().Perm() != 0600 {
		t.Fatalf("stat=%v error=%v", st, e)
	}
	if e := RunResourceWorker(t.Context(), []string{"--kind", "io", "--directory", dir, "--file-bytes", "8192", "--total-bytes", "4096", "--block-bytes", "4096", "--rate", "131072", "--duration", "1", "--id", "0"}, &out); e == nil {
		t.Fatal("overwrote an existing worker file")
	}
}

func TestWorkerStateRetainsExactHashAndBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	wire, hash, e := WritePressureWorkerState(path, Object{"status": "RUNNING", "pid": 123})
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if string(b) != wire || hash != Hash(b) {
		t.Fatal("retained worker state/hash differs")
	}
	if _, _, e := WritePressureWorkerState(path, Object{"payload": strings.Repeat("x", 16<<10)}); e == nil {
		t.Fatal("accepted unbounded worker evidence")
	}
}

func TestStressManifestRejectsUnboundedIOAndMemoryBeforeExecution(t *testing.T) {
	p := Object{"duration_seconds": 1, "sample_interval_seconds": 1, "cpu_workers": 1, "memory_bytes": 1, "memory_headroom_bytes": 1, "io_workers": 1, "io_file_bytes": 4096, "io_total_bytes": 4096, "io_bytes_per_second": 4096, "io_block_bytes": 4096, "io_directory": "/scratch", "workload_cgroup": Object{"parent_path": "/sys/fs/cgroup/workload.slice", "path": "/sys/fs/cgroup/workload.slice/pressure.scope", "cpu_max": "10000 100000", "memory_max_bytes": 4096, "io_weight": 100, "io_device": "8:0"}}
	m := Object{"schema": Schema, "pressure": p}
	if e := ValidateStressWorkerManifest(m); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"io_total_bytes", "io_workers", "memory_headroom_bytes"} {
		old := p[key]
		p[key] = int64(1) << 62
		if e := ValidateStressWorkerManifest(m); e == nil {
			t.Fatal("accepted oversized " + key)
		}
		p[key] = old
	}
	p["io_workers"] = 0
	if e := ValidateStressWorkerManifest(m); e == nil {
		t.Fatal("accepted zero I/O workers")
	}
}

func TestStressPinnedExecutableFixture(t *testing.T) {
	if os.Getenv("TS_STRESS_EXECUTABLE_FIXTURE") != "1" {
		t.Skip("subprocess fixture")
	}
	fmt.Println("pinned-executable-fixture")
}

func TestStressReexecRetainsAdmittedInodeAfterPathReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "worker")
	wire, e := os.ReadFile("/proc/self/exe")
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, wire, 0700); e != nil {
		t.Fatal(e)
	}
	executable, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer executable.Close()
	if e := os.WriteFile(path+".replacement", []byte("unadmitted replacement"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(path+".replacement", path); e != nil {
		t.Fatal(e)
	}
	cmd := pinnedStressCommand(executable, "-test.run=^TestStressPinnedExecutableFixture$")
	cmd.Env = append(os.Environ(), "TS_STRESS_EXECUTABLE_FIXTURE=1", "GORACE=atexit_sleep_ms=0")
	cmd.WaitDelay = time.Second
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("reexec opened replaced pathname: %v; %s", e, output)
	}
	if !bytes.Contains(output, []byte("pinned-executable-fixture")) {
		t.Fatal(string(output))
	}
}

package runtimepriority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
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
	for _, value := range evidence["block_device_chain"].([]any) {
		node := value.(Object)
		node["sysfs_path"] = "/sys/" + strings.TrimPrefix(str(node, "sysfs_path"), sysfs+"/")
	}
	statePath := filepath.Join(root, "backing.json")
	if _, _, err := WritePressureWorkerState(statePath, evidence); err != nil {
		t.Fatal(err)
	}
	retained, _, err := LoadJSON(statePath, 16384)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateBlockBackingEvidence(retained, "8:0"); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{"9:0", "8:0"} {
		node := retained["block_device_chain"].([]any)[0].(Object)
		node["partition_parent"] = parent
		if _, _, err := WritePressureWorkerState(statePath, retained); err != nil {
			t.Fatal(err)
		}
		corrupt, _, err := LoadJSON(statePath, 16384)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateBlockBackingEvidence(corrupt, "8:0"); err == nil {
			t.Fatalf("retained missing or cyclic parent %s admitted", parent)
		}
	}
	slave := filepath.Join(block, "slaves", "self")
	stressLink(t, block, slave)
	if _, err := ProveBlockBacking(scratch, mountinfo, sysfs, &device); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("block cycle admitted: %v", err)
	}
	if err := os.Remove(slave); err != nil {
		t.Fatal(err)
	}
	stressWrite(t, filepath.Join(block, "slaves", "missing", "dev"), "9:0\n")
	if _, err := ProveBlockBacking(scratch, mountinfo, sysfs, &device); err == nil {
		t.Fatal("missing block backing admitted")
	}
	if err := os.RemoveAll(filepath.Join(block, "slaves")); err != nil {
		t.Fatal(err)
	}
	if e := os.Mkdir(filepath.Join(block, "loop"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := ProveBlockBacking(scratch, mountinfo, sysfs, &device); e == nil || !strings.Contains(e.Error(), "pseudo block device") {
		t.Fatal(e)
	}
}

func TestJournalCollectionRejectsMalformedOOMRecords(t *testing.T) {
	record := Object{"__REALTIME_TIMESTAMP": "1770000000123456", "_BOOT_ID": strings.Repeat("a", 32), "_CURSOR": "cursor", "_TRANSPORT": "kernel", "MESSAGE": "oom-kill:constraint=CONSTRAINT_MEMCG,pid=123,task_memcg=/workload/pressure.scope"}
	valid := string(Canonical(record))
	record["MESSAGE"] = str(record, "MESSAGE") + ",pid=999"
	duplicatePID := string(Canonical(record))
	record["MESSAGE"] = "pid=123,task_memcg=/workload/../database"
	unsafePath := string(Canonical(record))
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	stressWrite(t, path, strings.Join([]string{valid, duplicatePID, unsafePath, `{"MESSAGE":"one","MESSAGE":"two"}`}, "\n")+"\n")
	command := runtimeCommandFixture(t, "cat "+shellQuote(path)+"\n")
	remote := Remote{}
	result, err := remote.Dispatch(t.Context(), Object{"transport": Object{"runtime": Object{"journalctl_path": command}}, "journal_watermark": Object{"cursor": "before"}}, "oom_collect")
	if err != nil {
		t.Fatal(err)
	}
	rows := result["events"].([]any)
	if len(rows) != 1 {
		t.Fatalf("malformed journal records admitted: %v", result)
	}
	row := rows[0].(Object)
	if row["raw_record"] != valid || row["raw_record_sha256"] != Hash([]byte(valid)) {
		t.Fatal(row)
	}
}

func TestCgroupInventoryRejectsUnexpectedProcessesAndCapturesRawIdentity(t *testing.T) {
	root := t.TempDir()
	group := filepath.Join(root, "group")
	cmd := exec.CommandContext(t.Context(), "sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pid := cmd.Process.Pid
	stressWrite(t, filepath.Join(group, "cgroup.procs"), fmt.Sprintf("%d\n", pid))
	r, e := PressureCgroupInventory(group, []int{pid}, map[int]string{pid: "cpu_worker"}, "/proc")
	if e != nil {
		t.Fatal(e)
	}
	process := r["processes"].([]any)[0].(Object)
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	rawPID, start := procStatIdentity(string(raw))
	if rawPID != int64(pid) || process["process_start_time"] != start || process["process_cgroup_raw"] == "" || r["process_inventory_sha256"] != Hash(Canonical(r["processes"])) {
		t.Fatal(r)
	}
	witness, err := (&Remote{}).Dispatch(t.Context(), Object{"transport": Object{"runtime": Object{}}, "remote_payload": Object{"pid": pid}}, "proc_witness")
	if err != nil {
		t.Fatal(err)
	}
	witnessPID, witnessStart := procStatIdentity(str(witness, "stat_raw"))
	if witnessPID != int64(pid) || witnessStart != start || witness["cgroup_raw"] != process["process_cgroup_raw"] {
		t.Fatal(witness)
	}
	stressWrite(t, filepath.Join(group, "cgroup.procs"), fmt.Sprintf("%d\n%d\n", pid, os.Getpid()))
	if _, e := PressureCgroupInventory(group, []int{pid}, map[int]string{pid: "cpu_worker"}, "/proc"); e == nil || !strings.Contains(e.Error(), "differs from owned") {
		t.Fatal(e)
	}
	stressWrite(t, filepath.Join(group, "cgroup.procs"), fmt.Sprintf("%d\n", pid))
	stressLink(t, root, filepath.Join(group, "unexpected"))
	if _, e := AssertExclusiveCgroup(group, []int{pid}); e == nil || !strings.Contains(e.Error(), "symlinks") {
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
	value, _, e := LoadJSON("testdata/canonical-unicode.json", 4096)
	if e != nil {
		t.Fatal(e)
	}
	wire, hash, e := WritePressureWorkerState(path, value)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	want, e := os.ReadFile("testdata/canonical-unicode.ascii.json")
	if e != nil {
		t.Fatal(e)
	}
	digest, e := os.ReadFile("testdata/canonical-unicode.sha256")
	if e != nil {
		t.Fatal(e)
	}
	if string(b) != wire || hash != Hash(b) || !bytes.Equal(bytes.TrimSuffix(b, []byte{'\n'}), bytes.TrimSuffix(want, []byte{'\n'})) || Hash(bytes.TrimSuffix(b, []byte{'\n'})) != strings.TrimSpace(string(digest)) {
		t.Fatal("retained Unicode worker state/hash differs")
	}
	if _, _, e := WritePressureWorkerState(path, Object{"payload": strings.Repeat("x", 16<<10)}); e == nil {
		t.Fatal("accepted unbounded worker evidence")
	}
	if retained, err := os.ReadFile(path); err != nil || !bytes.Equal(retained, b) {
		t.Fatalf("rejected state replaced retained evidence: %s %v", retained, err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	stressWrite(t, outside, "protected")
	if err := os.Symlink(outside, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := WritePressureWorkerState(path, Object{"status": "COMPLETED"}); err == nil {
		t.Fatal("followed a temporary evidence symlink")
	}
	if raw, err := os.ReadFile(outside); err != nil || string(raw) != "protected" {
		t.Fatalf("symlink target changed: %s %v", raw, err)
	}
}

func TestStressManifestRejectsUnboundedIOAndMemoryBeforeExecution(t *testing.T) {
	p := Object{"duration_seconds": 1, "sample_interval_seconds": 1, "cpu_workers": 1, "memory_bytes": 1, "memory_headroom_bytes": 1, "io_workers": 1, "io_file_bytes": 4096, "io_total_bytes": 4096, "io_bytes_per_second": 4096, "io_block_bytes": 4096, "io_directory": "/scratch", "workload_cgroup": Object{"parent_path": "/sys/fs/cgroup/workload.slice", "path": "/sys/fs/cgroup/workload.slice/pressure.scope", "cpu_max": "10000 100000", "memory_max_bytes": 4096, "io_weight": 100, "io_device": "8:0"}}
	m := Object{"schema": Schema, "pressure": p}
	directory := t.TempDir()
	path := filepath.Join(directory, "manifest.json")
	p["io_directory"] = directory
	for _, key := range []string{"io_total_bytes", "io_workers", "memory_headroom_bytes"} {
		old := p[key]
		for _, value := range []int64{int64(1) << 62, 0} {
			p[key] = value
			if err := os.WriteFile(path, Canonical(m), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := runtimeCLI(t, "pressure", "stress-worker", "--manifest", path, "--assigned-pressure-cgroup", "/sys/fs/cgroup/workload.slice/pressure.scope", "--expected-native-runner-cgroup", "/sys/fs/cgroup/native", "--protected-database-cgroup", "/sys/fs/cgroup/native/terrabase", "--run-id", "01ARZ3NDEKTSV4RRFFQ69G5FAV")
			reason := "stress worker count or memory request exceeds its harness bound"
			if key == "io_total_bytes" {
				reason = "stress I/O request exceeds its finite worker bounds"
			}
			if value == 0 {
				reason = "stress pressure." + key
			}
			if err == nil || !bytes.Contains(output, []byte("HarnessError:")) || !bytes.Contains(output, []byte(reason)) {
				t.Fatalf("invalid %s=%d: err=%v output=%s", key, value, err, output)
			}
		}
		p[key] = old
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("rejected manifest created worker files: %v %v", entries, err)
	}
}

func TestStressPinnedExecutableFixture(t *testing.T) {
	if os.Getenv("TS_STRESS_EXECUTABLE_FIXTURE") != "1" {
		return
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

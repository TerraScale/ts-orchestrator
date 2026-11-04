package runtimepriority

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStressManifestRejectsUnboundedIOAndMemoryBeforeExecution(t *testing.T) {
	p := Object{"duration_seconds": 1, "sample_interval_seconds": 1, "cpu_workers": 1, "memory_bytes": 1, "memory_headroom_bytes": 1, "io_workers": 1, "io_file_bytes": 4096, "io_total_bytes": 4096, "io_bytes_per_second": 4096, "io_block_bytes": 4096, "io_directory": "/scratch", "workload_cgroup": Object{"parent_path": "/sys/fs/cgroup/workload.slice", "path": "/sys/fs/cgroup/workload.slice/pressure.scope", "cpu_max": "10000 100000", "memory_max_bytes": 4096, "io_weight": 100, "io_device": "8:0"}}
	m := Object{"schema": Schema, "pressure": p}
	directory := t.TempDir()
	path := filepath.Join(directory, "manifest.json")
	p["io_directory"] = directory
	for _, key := range []string{"io_total_bytes"} {
		old := p[key]
		for _, value := range []int64{int64(1) << 62} {
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

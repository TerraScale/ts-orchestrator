package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadBakedRuntimePriorityProfileRejectsUnsafeAndInvalidFiles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "terrascale-orchestrator")
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runtime-priority.json")
	valid := []byte(`{"version":1,"profile_id":"preview-gru-v1","system_reserve_bytes":1073741824}`)
	write := func(data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	read := func() (uint64, error) {
		t.Helper()
		return readBakedRuntimePriorityProfileAt(path, uint32(os.Getuid()), uint32(os.Getgid()))
	}
	write(valid, 0644)
	if reserve, err := read(); err != nil || reserve != 1<<30 {
		t.Fatalf("valid image profile: reserve=%d err=%v", reserve, err)
	}
	for _, check := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"unknown field", []byte(`{"version":1,"profile_id":"preview-gru-v1","system_reserve_bytes":1073741824,"extra":1}`), 0644},
		{"unaligned reserve", []byte(`{"version":1,"profile_id":"preview-gru-v1","system_reserve_bytes":1073741825}`), 0644},
		{"unsafe mode", valid, 0664},
	} {
		t.Run(check.name, func(t *testing.T) {
			write(check.data, check.mode)
			if _, err := read(); err == nil {
				t.Fatal("unsafe image profile accepted")
			}
		})
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, valid, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := read(); err == nil {
		t.Fatal("symlinked image profile accepted")
	}
}

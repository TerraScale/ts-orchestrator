package observability

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDistinctFilesystemsCountsASharedFilesystemOnce(t *testing.T) {
	t.Parallel()
	got := DistinctFilesystems([]FilesystemView{
		{Role: "state", SizeBytes: 100, AvailBytes: 40, Device: 7},
		{Role: "install", SizeBytes: 100, AvailBytes: 40, Device: 7},
		{Role: "nats", SizeBytes: 100, AvailBytes: 40, Device: 9},
		// No device: identical statistics are the same filesystem.
		{Role: "a", SizeBytes: 50, AvailBytes: 10, Files: 3},
		{Role: "b", SizeBytes: 50, AvailBytes: 10, Files: 3},
		// Unobserved roles are kept as they are.
		{Role: "x"}, {Role: "y"},
	})
	roles := []string{}
	for _, filesystem := range got {
		roles = append(roles, filesystem.Role)
	}
	want := []string{"state, install", "nats", "a, b", "x", "y"}
	if len(roles) != len(want) {
		t.Fatalf("roles = %q", roles)
	}
	for index := range want {
		if roles[index] != want[index] {
			t.Fatalf("roles = %q, want %q", roles, want)
		}
	}
}

func TestStatFilesystemReportsTheDevice(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("filesystem statistics require Linux")
	}
	t.Parallel()
	directory := t.TempDir()
	for _, name := range []string{"state", "install"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	state, err := statFilesystem(filepath.Join(directory, "state"))
	if err != nil {
		t.Fatal(err)
	}
	install, err := statFilesystem(filepath.Join(directory, "install"))
	if err != nil {
		t.Fatal(err)
	}
	if state.Device == 0 || state.Device != install.Device {
		t.Fatalf("sibling directories report devices %d and %d", state.Device, install.Device)
	}
}

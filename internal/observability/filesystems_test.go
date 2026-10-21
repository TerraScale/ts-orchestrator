package observability

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

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
	state.Role, install.Role = "state", "install"
	distinct := DistinctFilesystems([]FilesystemView{state, install})
	if len(distinct) != 1 || distinct[0].Role != "state, install" {
		t.Fatalf("shared filesystem counted twice: %+v", distinct)
	}
	if state.Device == 0 || state.Device != install.Device {
		t.Fatalf("sibling directories report devices %d and %d", state.Device, install.Device)
	}
}

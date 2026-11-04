package ociregion_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/attempt"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

func attemptFixture(t *testing.T) (*attempt.Attempt, string) {
	t.Helper()
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	trust := map[string]any{}
	for _, k := range []string{"root_public", "root_private", "release_leaf_public", "release_leaf_private"} {
		trust[k] = filepath.Join(dir, k)
	}
	config := map[string]any{"workdir": work, "deployment_id": "0000000000F9PR1WNVDTEXS31Z", "prefix": "bootstrap/a", "validity_days": 1, "trust": trust, "tools": map[string]any{"guestfs_tools_dir": "/guestfs", "libguestfs_dir": "/libguestfs", "libguestfs_appliance": "/appliance"}, "orchestrator": map[string]any{"repository": "/repository", "source_revision": strings.Repeat("a", 40), "ci_run_number": 1, "ci_run_id": 42}, "image": map[string]any{"base_qcow2": "/base.qcow2", "kernel_release": "kernel", "native_verifier": "/native", "native_verifier_sha256": strings.Repeat("b", 64), "timesyncd_config": "/timesyncd", "priority": map[string]any{"profile_id": "profile", "system_reserve_bytes": 1, "host_memory_min_bytes": 1, "host_memory_low_bytes": 1, "controller_memory_min_bytes": 1, "controller_memory_low_bytes": 1, "system_slice_memory_min_bytes": 1, "system_slice_memory_low_bytes": 1}}}
	b, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "attempt.json")
	script.Write(t, path, b, 0600)
	script.Write(t, filepath.Join(work, "source", "cmd", "terrascale-orchestrator", "main.go"), []byte("pinned entry point\n"), 0600)
	a, e := attempt.New(t.Context(), path, io.Discard, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	a.Executable = "/qualified/orchestrator"
	return a, work
}
func commandValue(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 == len(args) {
		return ""
	}
	return args[i+1]
}
func TestAttemptLaunchUsesUnifiedTools(t *testing.T) {
	a, work := attemptFixture(t)
	script.Write(t, filepath.Join(work, "image", "import.json"), []byte(`{"image_id":"ocid1.image.fixture"}`), 0600)
	var command []string
	sentinel := errors.New("preflight captured")
	a.Runner = func(ctx context.Context, c attempt.Command) (string, error) {
		if slices.Contains(c.Args, "inventory") || slices.Contains(c.Args, "admit") {
			return "", nil
		}
		command = c.Args
		return "", sentinel
	}
	a.PhaseLaunch()
	if !errors.Is(a.Err(), sentinel) {
		t.Fatal(a.Err())
	}
	if !slices.Equal(command[:4], []string{a.Executable, "oci-region", "preview", "seed-preflight"}) {
		t.Fatal(command)
	}
	for _, flag := range []string{"--legacy-bootstrap-tool", "--legacy-release-tool"} {
		if slices.Contains(command, flag) {
			t.Fatal(flag, command)
		}
	}
	for _, pair := range [][2]string{{"--bootstrap-tool", a.BootstrapTool()}, {"--release-tool", a.ReleaseTool()}} {
		if commandValue(command, pair[0]) != pair[1] {
			t.Fatal(command)
		}
	}
}
func TestAttemptReservationCannotLaunchAgain(t *testing.T) {
	a, _ := attemptFixture(t)
	script.Write(t, a.Path("launch", "seed-reservation.json"), []byte("reserved"), 0600)
	a.Runner = func(context.Context, attempt.Command) (string, error) {
		t.Fatal("invoked external tool after unresolved reservation")
		return "", nil
	}
	a.PhaseLaunch()
	if a.Err() == nil || !strings.Contains(a.Err().Error(), "reconcile") {
		t.Fatal(a.Err())
	}
}

package deploy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"github.com/TerraScale/ts-orchestrator/internal/image"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport/imageimporttest"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

func deployRoot(t *testing.T) string { t.Helper(); return script.Root(t) }
func write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	script.Write(t, path, data, mode)
}
func read(t *testing.T, path string) []byte { t.Helper(); return script.Read(t, path) }
func digest(data []byte) string             { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func object(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func equal(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
func contains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("%q does not contain %q", got, want)
	}
}
func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s exists or could not be inspected: %v", path, err)
	}
}
func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	s, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return s.Mode().Perm()
}
func symlink(t *testing.T, path string) {
	t.Helper()
	s, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symlink", path)
	}
}

func successful(t *testing.T, result script.Result) {
	t.Helper()
	if result.Code != 0 {
		t.Fatalf("exit=%d\n%s\n%s", result.Code, result.Stdout, result.Stderr)
	}
}

// TestDeployTool runs native commands as subprocesses with each test's isolated environment.
func TestDeployTool(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 {
		return
	}
	args := os.Args[i+1:]
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	code := 2
	if len(args) > 0 {
		switch args[0] {
		case "image":
			var services image.Services
			// Promotion tests aim the real in-binary SDK importer at the
			// stand-in OCI region their parent process serves.
			if endpoint := os.Getenv(ociStandInEnv); endpoint != "" {
				services.ImageImporter = imageimporttest.Importer(endpoint)
			}
			code = image.RunWith(t.Context(), root, args[1:], os.Stdout, os.Stderr, services)
		case "netbird":
			code = client.Run(t.Context(), root, args[1:], os.Stdout, os.Stderr)
		}
	}
	os.Exit(code)
}

// ociStandInEnv carries the stand-in OCI endpoint from a test to the
// TestDeployTool subprocess. Only this test binary reads it.
const ociStandInEnv = "TS_TEST_OCI_STANDIN"

func deployTool(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ts-orch")
	write(t, path, []byte("#!/bin/sh\nGOMAXPROCS=2 GORACE=\"${GORACE:+$GORACE }atexit_sleep_ms=0\" exec "+shellQuote(exe)+" -test.run=^TestDeployTool$ -- \"$@\"\n"), 0755)
	return path
}

// runDeploy runs a deploy command. Its subprocesses (the offline builder,
// the promotion tool and this binary re-executed as ts-orch) read only
// repository files under deploy/: the pinned image inputs, systemd and udev
// units and the shell entry points. Tracking that tree alone keeps the
// suite's cached results valid across edits elsewhere; Go records every
// file the test process opens itself.
func runDeploy(t *testing.T, dir string, env map[string]string, name string, args ...string) script.Result {
	t.Helper()
	script.Track(t, "deploy")
	return script.Exec(t, dir, env, name, args...)
}

func runTool(t *testing.T, args ...string) script.Result {
	t.Helper()
	return runDeploy(t, deployRoot(t), nil, deployTool(t), args...)
}

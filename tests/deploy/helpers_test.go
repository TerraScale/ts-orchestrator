package deploy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
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
func runPython(t *testing.T, path string, args ...string) script.Result {
	t.Helper()
	return script.Run(t, deployRoot(t), nil, "python3", append([]string{filepath.Join(deployRoot(t), path)}, args...)...)
}
func successful(t *testing.T, result script.Result) {
	t.Helper()
	if result.Code != 0 {
		t.Fatalf("exit=%d\n%s\n%s", result.Code, result.Stdout, result.Stderr)
	}
}

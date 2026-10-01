// Package script supports Go contract tests of repository command-line tools.
// Python is used only to invoke implementations that have not yet moved to Go.
package script

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type Result struct {
	Stdout string
	Stderr string
	Code   int
}

func Root(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository test support")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func Write(t testing.TB, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func Read(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func Run(t *testing.T, dir string, env map[string]string, name string, args ...string) Result {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), name, args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for key, value := range env {
		prefix := key + "="
		for i := len(cmd.Env) - 1; i >= 0; i-- {
			if strings.HasPrefix(cmd.Env[i], prefix) {
				cmd.Env = append(cmd.Env[:i], cmd.Env[i+1:]...)
			}
		}
		cmd.Env = append(cmd.Env, prefix+value)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			code = exit.ExitCode()
		} else {
			t.Fatalf("start %s: %v", name, err)
		}
	}
	return Result{stdout.String(), stderr.String(), code}
}

// Python invokes a Python implementation with JSON input a and module m.
// body must set result to an observation; all assertions belong in Go.
// An implementation exception is returned as {error, error_type}. Import,
// serialization and process errors fail the test rather than appearing as
// expected implementation rejections.
func Python(t *testing.T, module string, args any, body string) []byte {
	t.Helper()
	input, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	program := `import contextlib, importlib.util, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).resolve().parent))
spec = importlib.util.spec_from_file_location("contract_subject", sys.argv[1])
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
a = json.loads(sys.argv[2])
with contextlib.redirect_stdout(sys.stderr):
    try:
`
	for line := range strings.SplitSeq(body, "\n") {
		program += "        " + line + "\n"
	}
	program += `    except Exception as exc:
        result = {"error": str(exc), "error_type": type(exc).__name__}
print(json.dumps(result))
`
	r := Run(t, Root(t), map[string]string{"PYTHONDONTWRITEBYTECODE": "1"}, "python3", "-c", program, module, string(input))
	if r.Code != 0 {
		t.Fatalf("Python observation adapter for %s exited %d:\n%s", module, r.Code, r.Stderr)
	}
	var value any
	if err := json.Unmarshal([]byte(r.Stdout), &value); err != nil {
		t.Fatal(fmt.Errorf("invalid observation from %s: %w; stdout=%q stderr=%q", module, err, r.Stdout, r.Stderr))
	}
	return []byte(r.Stdout)
}

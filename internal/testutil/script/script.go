// Package script supports Go contract tests of repository command-line tools.
// Python is used only to invoke implementations that have not yet moved to Go.
package script

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type Result struct {
	Stdout string
	Stderr string
	Code   int
}

var sourceOnce sync.Once
var sourceError error

// External interpreters do not report their file reads to Go's test cache.
// Record repository inputs here so editing an invoked script or its inputs
// invalidates cached Go contract results just like editing Go source does.
func trackSources(t *testing.T) {
	t.Helper()
	sourceOnce.Do(func() {
		sourceError = filepath.WalkDir(Root(t), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				switch entry.Name() {
				case ".git", "dist", "docs", ".qualification", "__pycache__":
					return filepath.SkipDir
				}
				return nil
			}
			_, err = os.Stat(path)
			return err
		})
	})
	if sourceError != nil {
		t.Fatal(sourceError)
	}
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
	trackSources(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
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
	if ctx.Err() != nil {
		t.Fatalf("%s exceeded its command deadline: %v", name, ctx.Err())
	}
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
	inputPath := filepath.Join(t.TempDir(), "observation-input.json")
	Write(t, inputPath, input, 0o600)
	program := `import contextlib, importlib.util, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).resolve().parent))
spec = importlib.util.spec_from_file_location("contract_subject", sys.argv[1])
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
a = json.loads(pathlib.Path(sys.argv[2]).read_text())
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
	r := Run(t, Root(t), map[string]string{"PYTHONDONTWRITEBYTECODE": "1"}, "python3", "-c", program, module, inputPath)
	if r.Code != 0 {
		t.Fatalf("Python observation adapter for %s exited %d:\n%s", module, r.Code, r.Stderr)
	}
	var value any
	if err := json.Unmarshal([]byte(r.Stdout), &value); err != nil {
		t.Fatal(fmt.Errorf("invalid observation from %s: %w; stdout=%q stderr=%q", module, err, r.Stdout, r.Stderr))
	}
	return []byte(r.Stdout)
}

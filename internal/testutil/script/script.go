// Package script supports Go contract tests of repository command-line tools.
package script

import (
	"bytes"
	"context"
	"errors"
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

// External commands do not report their file reads to Go's test cache.
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
	return Exec(t, dir, env, name, args...)
}

// Exec is Run without recording the repository tree. Use it only when the
// command's every repository input is already part of the test's cache key,
// for example embedded with go:embed: the tree's modification times then
// cannot invalidate a cached result, so the test re-runs only when its own
// package or those inputs change.
func Exec(t *testing.T, dir string, env map[string]string, name string, args ...string) Result {
	t.Helper()
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

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

// tracked memoizes Track per repository-relative path: the first walk puts
// the inputs in this test binary's log, and later calls share its result.
var tracked sync.Map // string -> *trackedPath

type trackedPath struct {
	once sync.Once
	err  error
}

// Track records every file under each repository-relative path (a file or a
// directory tree) as an input of the running test binary. External commands
// do not report their file reads to Go's test cache, so a test that runs
// one names the repository files the command may read: editing any of them
// then invalidates the cached result just like editing Go source does. Files
// the test process opens or stats itself are recorded by Go already.
//
// Go keys a recorded file on its size and modification time. Naming only a
// command's real inputs, instead of the whole tree, keeps the result cached
// across unrelated edits. CI stamps a clean checkout with content-derived
// modification times (scripts/ci/stablemtime), so unchanged inputs also stay
// cached across fresh checkouts.
func Track(t testing.TB, paths ...string) {
	t.Helper()
	root := Root(t)
	for _, path := range paths {
		clean := filepath.Clean(path)
		if !filepath.IsLocal(clean) {
			t.Fatalf("tracked input %q is not a repository-relative path", path)
		}
		value, _ := tracked.LoadOrStore(clean, &trackedPath{})
		entry := value.(*trackedPath)
		entry.once.Do(func() { entry.err = record(filepath.Join(root, clean)) })
		if entry.err != nil {
			t.Fatal(entry.err)
		}
	}
}

// record stats every file below path and lists every directory, which puts
// them in the test log. Generated and evidence directories are skipped: they
// are no command's input and change underneath concurrent CI jobs.
func record(path string) error {
	return filepath.WalkDir(path, func(path string, entry os.DirEntry, err error) error {
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

// Run runs a command after recording the whole repository tree as its
// input, so any edit anywhere re-runs the test. Prefer Track with the
// command's real inputs, then Exec.
func Run(t *testing.T, dir string, env map[string]string, name string, args ...string) Result {
	t.Helper()
	Track(t, ".")
	return Exec(t, dir, env, name, args...)
}

// Exec is Run without recording the repository tree. Use it only when the
// command's every repository input is already part of the test's cache key:
// embedded with go:embed, opened by the test process itself (including
// copies it makes into a temporary directory), or named with Track. The test
// then re-runs only when its own package or those inputs change.
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

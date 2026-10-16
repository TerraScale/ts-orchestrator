package runtimepriority

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestScopeAdmissionOwnershipAndCleanup(t *testing.T) {
	for _, test := range []struct {
		name, loadState               string
		cancel, admit, cleanupFailure bool
	}{
		{name: "failed evidence", loadState: "not-found"},
		{name: "failed evidence keeps cleanup error", loadState: "not-found", cleanupFailure: true},
		{name: "canceled admission", loadState: "not-found", cancel: true},
		{name: "preexisting unit", loadState: "loaded"},
		{name: "owned RUNNING admission", loadState: "not-found", admit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			root := t.TempDir()
			sleep, err := exec.LookPath("sleep")
			if err != nil {
				t.Fatal(err)
			}
			pidPath, stopPath := filepath.Join(root, "pid"), filepath.Join(root, "stop")
			command := "case \"$1\" in\nshow) printf '%s\\n' " + shellQuote("LoadState="+test.loadState) + ";;\nstop) printf '%s\\n' \"$2\" > " + shellQuote(stopPath)
			if test.cleanupFailure {
				command += "; exit 7"
			}
			command += ";;\nesac\n"
			systemctl := runtimeCommandFixture(t, command)
			launcher := runtimeCommandFixture(t, "echo $$ > "+shellQuote(pidPath)+"\nexec "+shellQuote(sleep)+" 30\n")
			request := Object{"run_id": "test-scope", "deadline_seconds": 2, "transport": Object{"runtime": Object{"systemctl_path": systemctl}}}
			remote := Remote{}
			pid := 0
			t.Cleanup(func() {
				if pid > 1 {
					_ = unix.Kill(-pid, unix.SIGKILL)
				}
			})
			result, err := remote.admitScope(ctx, request, []string{launcher}, func(context.Context, Object) (Object, error) {
				raw, err := os.ReadFile(pidPath)
				if err != nil {
					return nil, err
				}
				pid, err = strconv.Atoi(strings.TrimSpace(string(raw)))
				if err != nil {
					return nil, err
				}
				stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if err != nil {
					return nil, err
				}
				if test.cancel {
					cancel()
					return Object{"pid": pid}, nil
				}
				if test.admit {
					return Object{"pid": pid, "stat_raw": string(stat)}, nil
				}
				fail("RUNNING inventory is invalid")
				return nil, nil
			})
			if test.loadState != "not-found" {
				if err == nil || !strings.Contains(err.Error(), "already exists") {
					t.Fatalf("preexisting scope admitted: %v", err)
				}
				for _, path := range []string{pidPath, stopPath} {
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("preexisting scope launched or stopped: %s: %v", path, err)
					}
				}
				return
			}
			// The successful lifecycle owns its launcher until the test ends.
			if test.admit {
				if err != nil || result["pid"] != pid {
					t.Fatalf("admission: result=%v err=%v", result, err)
				}
				if _, err := os.Stat(stopPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("admitted scope stopped early: %v", err)
				}
				if err := unix.Kill(-pid, unix.SIGTERM); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil || result != nil {
					t.Fatalf("invalid admission succeeded: %v %v", result, err)
				}
				raw, readErr := os.ReadFile(stopPath)
				if readErr != nil || strings.TrimSpace(string(raw)) != "terrascale-d15-test-scope.scope" {
					t.Fatalf("scope cleanup missing: %s %v", raw, readErr)
				}
				if test.cancel && !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation: %v", err)
				}
				if !test.cancel && (ErrorType(err) != "HarnessError" || !strings.Contains(err.Error(), "RUNNING inventory is invalid")) {
					t.Fatalf("lost admission error: %v", err)
				}
				if test.cleanupFailure {
					if _, ok := errors.AsType[*exec.ExitError](err); !ok {
						t.Fatalf("lost real cleanup command failure: %v", err)
					}
				}
			}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); errors.Is(err, os.ErrNotExist) {
					pid = 0
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatalf("launcher %d was not reaped", pid)
		})
	}
}

func TestScopeLauncherRunsDetachedAndReapsOnStop(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	remote := Remote{}
	started := time.Now()
	stop, done, err := remote.launchScope([]string{executable, "-test.run=^TestDetachedScopeChild$", "--", "--runtime-scope-child"})
	if err != nil {
		t.Fatal(err)
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	defer stop(cleanupCtx)
	if time.Since(started) > time.Second {
		t.Fatal("launcher waited for pressure process to exit")
	}
	select {
	case err := <-done:
		t.Fatalf("launcher exited before stop: %v", err)
	default:
	}
	if err := stop(cleanupCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-cleanupCtx.Done():
		t.Fatal("stopped launcher was not reaped")
	}
}

func TestDetachedScopeChild(t *testing.T) {
	if !slices.Contains(os.Args, "--runtime-scope-child") {
		return
	}
	<-time.After(time.Minute)
}

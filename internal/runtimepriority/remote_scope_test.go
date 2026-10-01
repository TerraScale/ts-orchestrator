package runtimepriority

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestScopeAdmissionOwnershipAndCleanup(t *testing.T) {
	cleanupFailure := errors.New("unit cleanup failed")
	for _, test := range []struct {
		name, loadState string
		cancel, admit   bool
		cleanupError    error
	}{
		{name: "failed evidence", loadState: "not-found"},
		{name: "failed evidence keeps cleanup error", loadState: "not-found", cleanupError: cleanupFailure},
		{name: "canceled admission", loadState: "not-found", cancel: true},
		{name: "preexisting unit", loadState: "loaded"},
		{name: "owned RUNNING admission", loadState: "not-found", admit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request := Object{"run_id": "test-scope", "deadline_seconds": 2, "transport": Object{"runtime": Object{"systemctl_path": "/test/systemctl"}}}
			unit := "terrascale-d15-test-scope.scope"
			launched, stoppedUnit, stoppedLauncher, observed := 0, 0, 0, 0
			remote := Remote{
				Command: func(commandCtx context.Context, argv []string, _ []byte, _ time.Duration, _ int) ([]byte, error) {
					t.Helper()
					if argv[0] != "/test/systemctl" || argv[2] != unit {
						t.Fatalf("unexpected command %v", argv)
					}
					switch argv[1] {
					case "show":
						return []byte("LoadState=" + test.loadState + "\n"), nil
					case "stop":
						stoppedUnit++
						if commandCtx.Err() != nil {
							t.Fatal("cleanup inherited canceled admission context")
						}
						if _, bounded := commandCtx.Deadline(); !bounded {
							t.Fatal("cleanup has no deadline")
						}
						return nil, test.cleanupError
					default:
						t.Fatalf("unexpected command %v", argv)
						return nil, nil
					}
				},
				ScopeLauncher: func(argv []string) (func(context.Context) error, <-chan error, error) {
					launched++
					if !slices.Equal(argv, []string{"/test/systemd-run", "--scope"}) {
						t.Fatalf("unexpected launcher %v", argv)
					}
					return func(cleanupCtx context.Context) error {
						stoppedLauncher++
						if cleanupCtx.Err() != nil {
							t.Fatal("launcher cleanup inherited canceled admission context")
						}
						return nil
					}, make(chan error), nil
				},
			}
			proof := Object{"handle": unit}
			result, err := remote.admitScope(ctx, request, []string{"/test/systemd-run", "--scope"}, func(context.Context, Object) (Object, error) {
				observed++
				if test.cancel {
					cancel()
				}
				if test.admit || test.cancel {
					return proof, nil
				}
				fail("RUNNING inventory is invalid")
				return nil, nil
			})
			if test.loadState != "not-found" {
				if err == nil || !strings.Contains(err.Error(), "already exists") || launched != 0 || stoppedUnit != 0 || stoppedLauncher != 0 || observed != 0 {
					t.Fatalf("preexisting scope was adopted or stopped: err=%v launch=%d unit=%d launcher=%d observed=%d", err, launched, stoppedUnit, stoppedLauncher, observed)
				}
				return
			}
			if launched != 1 || observed == 0 {
				t.Fatalf("missing launch/admission attempt: launch=%d observed=%d", launched, observed)
			}
			if test.admit {
				if err != nil || !same(result, proof) || stoppedUnit != 0 || stoppedLauncher != 0 {
					t.Fatalf("owned admitted scope stopped early: result=%v err=%v unit=%d launcher=%d", result, err, stoppedUnit, stoppedLauncher)
				}
				return
			}
			if err == nil || result != nil || stoppedUnit != 1 || stoppedLauncher != 1 {
				t.Fatalf("failed admission left scope/launcher: result=%v err=%v unit=%d launcher=%d", result, err, stoppedUnit, stoppedLauncher)
			}
			if test.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost canceled admission: %v", err)
			}
			if test.cleanupError != nil && !errors.Is(err, test.cleanupError) {
				t.Fatalf("lost cleanup failure: %v", err)
			}
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
	default:
		t.Fatal("stopped launcher was not reaped")
	}
}

func TestDetachedScopeChild(t *testing.T) {
	if !slices.Contains(os.Args, "--runtime-scope-child") {
		t.Skip("subprocess helper")
	}
	<-time.After(time.Minute)
}

func TestRecoverWrappedDomainErrorKeepsCleanupError(t *testing.T) {
	cleanupError := errors.New("cleanup failed")
	err := func() (err error) {
		defer recoverError(&err)
		defer func() { err = cleanupError }()
		panic(errors.Join(&DomainError{"HarnessError", "invalid evidence"}))
	}()
	if ErrorType(err) != "HarnessError" || !errors.Is(err, cleanupError) {
		t.Fatalf("lost wrapped domain or cleanup error: %v", err)
	}
}

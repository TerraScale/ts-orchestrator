package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

func TestTransientControllerBootstrapErrorAuthorityClassifications(t *testing.T) {
	conflict := fmt.Errorf("observe authority lease: %w", authority.ErrConflict)
	unknownConflict := fmt.Errorf("probe authority outcome: %w", fmt.Errorf("%w: %w",
		authority.ErrOutcomeUnknown, authority.ErrConflict))
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "wrapped conflict retries", err: conflict, want: true},
		{name: "fenced remains permanent", err: fmt.Errorf("open authority: %w", authority.ErrFenced)},
		{name: "corrupt lease remains permanent", err: fmt.Errorf("open authority: %w", authority.ErrLeaseCorrupt)},
		{name: "unknown outcome remains permanent", err: unknownConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := transientControllerBootstrapError(test.err); got != test.want {
				t.Fatalf("transientControllerBootstrapError(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestRetryControllerOpenRetriesAuthorityConflict(t *testing.T) {
	var calls int
	resource, cancel, err := retryControllerOpen(t.Context(), "start regional authority", func() bool {
		return true
	}, false, func(context.Context) (string, error) {
		calls++
		if calls == 1 {
			return "", fmt.Errorf("observe authority lease: %w", authority.ErrConflict)
		}
		return "regional authority", nil
	}, nil)
	if cancel != nil {
		cancel()
	}
	if err != nil {
		t.Fatalf("retryControllerOpen() error = %v", err)
	}
	if calls != 2 || resource != "regional authority" {
		t.Fatalf("retryControllerOpen() calls=%d resource=%q, want calls=2 resource=%q", calls, resource, "regional authority")
	}
}

func TestRetryControllerOpenDoesNotRetryPermanentAuthorityErrors(t *testing.T) {
	for _, sentinel := range []struct {
		name string
		err  error
	}{
		{name: "fenced", err: authority.ErrFenced},
		{name: "corrupt lease", err: authority.ErrLeaseCorrupt},
		{name: "unknown outcome", err: fmt.Errorf("%w: %w", authority.ErrOutcomeUnknown, authority.ErrConflict)},
	} {
		t.Run(sentinel.name, func(t *testing.T) {
			var calls int
			_, _, err := retryControllerOpen(t.Context(), "start regional authority", func() bool {
				return true
			}, false, func(context.Context) (string, error) {
				calls++
				return "", fmt.Errorf("open authority: %w", sentinel.err)
			}, nil)
			if !errors.Is(err, sentinel.err) {
				t.Fatalf("retryControllerOpen() error = %v, want it to wrap %v", err, sentinel.err)
			}
			if calls != 1 {
				t.Fatalf("retryControllerOpen() attempts=%d, want 1", calls)
			}
		})
	}
}

type fixedControllerClock struct {
	bound brokerauth.ClockBound
	err   error
	calls int
}

func (clock *fixedControllerClock) Measure() (brokerauth.ClockBound, error) {
	clock.calls++
	return clock.bound, clock.err
}

func TestBootstrapControllerCommandDispatchesSameBinary(t *testing.T) {
	prior := controllerBootstrapCommand
	t.Cleanup(func() { controllerBootstrapCommand = prior })
	called := false
	controllerBootstrapCommand = func(_ context.Context, cfg Config) error {
		called = true
		if cfg.NATS.Cell != "gru" {
			t.Fatalf("bootstrap command received wrong config: %+v", cfg.NATS)
		}
		return nil
	}
	path := filepath.Join(t.TempDir(), "controller.json")
	wire, err := json.Marshal(Config{Version: ConfigVersion, NATS: natscell.Config{Cell: "gru"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(t.Context(), []string{"bootstrap-controller", "--config", path}, io.Discard); err != nil || !called {
		t.Fatalf("same-binary bootstrap command = called %t, %v", called, err)
	}
	called = false
	if err := Run(t.Context(), []string{"bootstrap-controller", "--config", path, "extra"}, io.Discard); err == nil || called {
		t.Fatalf("bootstrap command accepted positional arguments: %v", err)
	}
}

func TestRootBootstrapExistingMarkerDelegatesToControllerRestartAdmission(t *testing.T) {
	called := 0
	present, err := acceptedControllerInstallPresent(func() (bootstrapstart.AcceptedIdentity, error) {
		called++
		return bootstrapstart.AcceptedIdentity{}, nil
	})
	if err != nil || !present || called != 1 {
		t.Fatalf("existing accepted marker: present=%t calls=%d err=%v", present, called, err)
	}
	present, err = acceptedControllerInstallPresent(func() (bootstrapstart.AcceptedIdentity, error) {
		return bootstrapstart.AcceptedIdentity{}, os.ErrNotExist
	})
	if err != nil || present {
		t.Fatalf("first install marker absence: present=%t err=%v", present, err)
	}
	present, err = acceptedControllerInstallPresent(func() (bootstrapstart.AcceptedIdentity, error) {
		return bootstrapstart.AcceptedIdentity{}, errors.New("invalid accepted marker")
	})
	if err == nil || present {
		t.Fatalf("invalid accepted marker was treated as an initial install: present=%t err=%v", present, err)
	}
}

func TestDirectControllerRunChecksAcceptedAdmissionBeforeNATS(t *testing.T) {
	priorProduction, priorMarker, priorBaked := controllerBootstrapProduction, controllerMarkerPresent, controllerBakedInputsPresent
	priorClock := controllerBrokerClockProbe
	t.Cleanup(func() {
		controllerBootstrapProduction, controllerMarkerPresent, controllerBakedInputsPresent = priorProduction, priorMarker, priorBaked
		controllerBrokerClockProbe = priorClock
	})
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	controllerBrokerClockProbe = func() brokerauth.ClockProbe { return clock }
	controllerMarkerPresent = func() (bool, error) { return false, nil }
	controllerBakedInputsPresent = func() (bool, error) { return true, nil }
	sentinel := errors.New("production admission stopped startup")
	called := false
	controllerBootstrapProduction = func(context.Context, Config) error { called = true; return sentinel }
	if err := admitControllerBootstrap(t.Context(), Config{}, func() error { return nil }); !errors.Is(err, sentinel) || !called {
		t.Fatalf("production skipped pre-NATS gate: %v", err)
	}
	called = false
	if err := runController(t.Context(), Config{Version: ConfigVersion}, io.Discard); !errors.Is(err, sentinel) || !called {
		t.Fatalf("baked input skipped pre-NATS gate: %v", err)
	}
	controllerBakedInputsPresent = func() (bool, error) { return false, nil }
	called = false
	if err := runController(t.Context(), Config{Version: ConfigVersion}, io.Discard); err == nil || !strings.Contains(err.Error(), "baked bootstrap") || called {
		t.Fatalf("production without baked inputs = %v, gate called=%t", err, called)
	}
}

func TestProductionControllerRejectsUnhealthyClockBeforeAdmission(t *testing.T) {
	priorMarker := controllerMarkerPresent
	priorBaked := controllerBakedInputsPresent
	priorProduction := controllerBootstrapProduction
	priorClock := controllerBrokerClockProbe
	t.Cleanup(func() {
		controllerMarkerPresent = priorMarker
		controllerBakedInputsPresent = priorBaked
		controllerBootstrapProduction = priorProduction
		controllerBrokerClockProbe = priorClock
	})
	controllerMarkerPresent = func() (bool, error) { return false, nil }
	controllerBakedInputsPresent = func() (bool, error) { return true, nil }
	admissionCalls := 0
	controllerBootstrapProduction = func(context.Context, Config) error {
		admissionCalls++
		return errors.New("admission was reached")
	}
	for _, test := range []struct {
		name  string
		clock *fixedControllerClock
	}{
		{"unhealthy", &fixedControllerClock{err: errors.New("NTP unsynchronized")}},
		{"0000000000RNVXNPAX5Y5BB8RY", &fixedControllerClock{bound: brokerauth.ClockBound{
			SampledAt: time.Now().Add(-2 * time.Second), MaxError: time.Millisecond}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			controllerBrokerClockProbe = func() brokerauth.ClockProbe { return test.clock }
			if err := runController(t.Context(), Config{Version: ConfigVersion}, io.Discard); err == nil ||
				!strings.Contains(err.Error(), "NTP clock health") {
				t.Fatalf("run with baked inputs and %s clock = %v", test.name, err)
			}
			if admissionCalls != 0 || test.clock.calls != 1 {
				t.Fatalf("%s clock reached admission %d times after %d clock samples",
					test.name, admissionCalls, test.clock.calls)
			}
			for _, initial := range []bool{true, false} {
				want := "NTP clock health"
				if !initial {
					want = "read accepted controller identity"
				}
				if err := admitProductionController(t.Context(), Config{Version: ConfigVersion}, bootstrapstart.MarkerStore{}, initial); err == nil ||
					!strings.Contains(err.Error(), want) {
					t.Fatalf("hidden child body initial=%t with %s clock = %v", initial, test.name, err)
				}
			}
			if os.Geteuid() == 0 {
				if err := bootstrapController(t.Context(), Config{Version: ConfigVersion}); err == nil ||
					!strings.Contains(err.Error(), "NTP clock health") {
					t.Fatalf("standalone root bootstrap with %s clock = %v", test.name, err)
				}
			}
		})
	}
}

func TestControllerBakedPresenceErrorStopsStartup(t *testing.T) {
	priorPresent := controllerBakedInputsPresent
	t.Cleanup(func() { controllerBakedInputsPresent = priorPresent })
	controllerBakedInputsPresent = func() (bool, error) { return false, errors.New("permission denied") }
	if err := runController(t.Context(), Config{Version: ConfigVersion}, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("baked path inspection error allowed startup: %v", err)
	}
}

func TestDamagedAcceptedIdentityCannotEnterInitialFormation(t *testing.T) {
	priorMarker := controllerMarkerPresent
	t.Cleanup(func() { controllerMarkerPresent = priorMarker })
	controllerMarkerPresent = func() (bool, error) { return false, errors.New("permission denied") }
	if _, err := startControllerAdmission(t.Context(), Config{}, nil); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("accepted identity inspection error entered initial formation: %v", err)
	}
}

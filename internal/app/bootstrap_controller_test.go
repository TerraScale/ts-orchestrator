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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
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
	wire, err := json.Marshal(Config{NATS: natscell.Config{Cell: "gru"}})
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
	present, err := acceptedControllerInstallPresent(func() (bootstrapstart.AcceptedInstall, error) {
		called++
		return bootstrapstart.AcceptedInstall{}, nil
	})
	if err != nil || !present || called != 1 {
		t.Fatalf("existing accepted marker: present=%t calls=%d err=%v", present, called, err)
	}
	present, err = acceptedControllerInstallPresent(func() (bootstrapstart.AcceptedInstall, error) {
		return bootstrapstart.AcceptedInstall{}, os.ErrNotExist
	})
	if err != nil || present {
		t.Fatalf("first install marker absence: present=%t err=%v", present, err)
	}
	present, err = acceptedControllerInstallPresent(func() (bootstrapstart.AcceptedInstall, error) {
		return bootstrapstart.AcceptedInstall{}, errors.New("invalid accepted marker")
	})
	if err == nil || present {
		t.Fatalf("invalid accepted marker was treated as an initial install: present=%t err=%v", present, err)
	}
}

func TestDirectControllerRunChecksBakedAdmissionBeforeNATS(t *testing.T) {
	priorPresent := controllerBakedInputsPresent
	priorProduction := controllerBootstrapProduction
	priorClock := controllerBrokerClockProbe
	t.Cleanup(func() {
		controllerBakedInputsPresent = priorPresent
		controllerBootstrapProduction = priorProduction
		controllerBrokerClockProbe = priorClock
	})
	clock := &fixedControllerClock{bound: brokerauth.ClockBound{SampledAt: time.Now(), MaxError: time.Millisecond}}
	controllerBrokerClockProbe = func() brokerauth.ClockProbe { return clock }
	sentinel := errors.New("production admission stopped startup")
	called := false
	controllerBakedInputsPresent = func() (bool, error) { return true, nil }
	controllerBootstrapProduction = func(context.Context, Config) error {
		called = true
		return sentinel
	}
	for _, lab := range []bool{false, true} {
		called = false
		cfg := Config{NATS: natscell.Config{Lab: lab}}
		if err := runController(t.Context(), cfg, io.Discard); !errors.Is(err, sentinel) || !called {
			t.Fatalf("baked input with lab=%t skipped pre-NATS gate: %v", lab, err)
		}
	}
	controllerBakedInputsPresent = func() (bool, error) { return false, nil }
	called = false
	if err := runController(t.Context(), Config{}, io.Discard); err == nil || !strings.Contains(err.Error(), "baked bootstrap") || called {
		t.Fatalf("production without baked inputs = %v, gate called=%t", err, called)
	}
	if err := runController(t.Context(), Config{NATS: natscell.Config{Lab: true}}, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "embedded regional NATS") {
		t.Fatalf("explicit lab without baked inputs did not reach normal controller validation: %v", err)
	}
}

func TestProductionControllerRejectsUnhealthyClockBeforeAdmission(t *testing.T) {
	priorPresent := controllerBakedInputsPresent
	priorProduction := controllerBootstrapProduction
	priorClock := controllerBrokerClockProbe
	t.Cleanup(func() {
		controllerBakedInputsPresent = priorPresent
		controllerBootstrapProduction = priorProduction
		controllerBrokerClockProbe = priorClock
	})
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
			for _, lab := range []bool{false, true} {
				if err := runController(t.Context(), Config{NATS: natscell.Config{Lab: lab}}, io.Discard); err == nil ||
					!strings.Contains(err.Error(), "NTP clock health") {
					t.Fatalf("run with baked inputs, lab=%t and %s clock = %v", lab, test.name, err)
				}
			}
			if admissionCalls != 0 || test.clock.calls != 2 {
				t.Fatalf("%s clock reached admission %d times after %d clock samples",
					test.name, admissionCalls, test.clock.calls)
			}
			for _, initial := range []bool{true, false} {
				if err := admitProductionController(t.Context(), Config{}, bootstrapstart.MarkerStore{}, initial); err == nil ||
					!strings.Contains(err.Error(), "NTP clock health") {
					t.Fatalf("hidden child body initial=%t with %s clock = %v", initial, test.name, err)
				}
			}
			if os.Geteuid() == 0 {
				if err := bootstrapController(t.Context(), Config{}); err == nil ||
					!strings.Contains(err.Error(), "NTP clock health") {
					t.Fatalf("standalone root bootstrap with %s clock = %v", test.name, err)
				}
			}
		})
	}
}

func TestControllerBakedPresenceErrorCannotFallBackToLab(t *testing.T) {
	priorPresent := controllerBakedInputsPresent
	t.Cleanup(func() { controllerBakedInputsPresent = priorPresent })
	controllerBakedInputsPresent = func() (bool, error) { return false, errors.New("permission denied") }
	if err := runController(t.Context(), Config{NATS: natscell.Config{Lab: true}}, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("baked path inspection error fell through to lab: %v", err)
	}
}

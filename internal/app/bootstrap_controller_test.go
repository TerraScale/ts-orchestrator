package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

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
		{"stale", &fixedControllerClock{bound: brokerauth.ClockBound{
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

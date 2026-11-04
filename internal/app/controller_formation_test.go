package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

type admissionStubs struct {
	local, full atomic.Int32
}

func stubControllerAdmission(t *testing.T, marker bool, localErr error, full func(int32) error) *admissionStubs {
	t.Helper()
	stubs := &admissionStubs{}
	previousMarker := controllerMarkerPresent
	previousBaked := controllerBakedInputsPresent
	previousLocal, previousFull := controllerLocalAdmissionProduction, controllerBootstrapProduction
	previousMin, previousMax := controllerAdmissionMinBackoff, controllerAdmissionMaxBackoff
	controllerMarkerPresent = func() (bool, error) { return marker, nil }
	controllerBakedInputsPresent = func() (bool, error) { return true, nil }
	controllerLocalAdmissionProduction = func(context.Context, Config) error {
		stubs.local.Add(1)
		return localErr
	}
	controllerBootstrapProduction = func(ctx context.Context, _ Config) error {
		return full(stubs.full.Add(1))
	}
	controllerAdmissionMinBackoff, controllerAdmissionMaxBackoff = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() {
		controllerMarkerPresent = previousMarker
		controllerBakedInputsPresent = previousBaked
		controllerLocalAdmissionProduction, controllerBootstrapProduction = previousLocal, previousFull
		controllerAdmissionMinBackoff, controllerAdmissionMaxBackoff = previousMin, previousMax
	})
	return stubs
}

func productionAdmissionConfig() Config {
	return Config{Version: ConfigVersion, NATS: natscell.Config{Cell: "gru", Instance: "controller-a", Replicas: 3}}
}

// During an OCI outage the restarted controller passes local admission, so
// routes can form, while full admission keeps retrying and holds authority.
func TestOfflineRestartAdmissionHoldsAuthorityUntilFullAdmission(t *testing.T) {
	release := make(chan struct{})
	stubs := stubControllerAdmission(t, true, nil, func(attempt int32) error {
		if attempt < 3 {
			return errors.New("OCI Object Storage unavailable")
		}
		<-release
		return nil
	})
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(), func() error { return nil })
	if err != nil || !admission.offline {
		t.Fatalf("offline admission = %+v, %v", admission, err)
	}
	defer admission.stop()
	if stubs.local.Load() != 1 {
		t.Fatalf("local admission calls = %d", stubs.local.Load())
	}
	held, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := admission.wait(held); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("authority gate opened before full admission: %v", err)
	}
	close(release)
	ready, readyCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer readyCancel()
	if err := admission.wait(ready); err != nil {
		t.Fatalf("authority gate did not open after full admission: %v", err)
	}
	if stubs.full.Load() != 3 {
		t.Fatalf("full admission attempts = %d", stubs.full.Load())
	}
}

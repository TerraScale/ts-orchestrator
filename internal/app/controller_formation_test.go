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

func TestInitialControllerAdmissionStaysSynchronous(t *testing.T) {
	want := errors.New("OCI ledger unavailable")
	stubs := stubControllerAdmission(t, false, nil, func(int32) error { return want })
	if _, err := startControllerAdmission(t.Context(), productionAdmissionConfig(),
		func() error { return nil }); !errors.Is(err, want) {
		t.Fatalf("initial admission failure did not stop startup: %v", err)
	}
	if stubs.local.Load() != 0 || stubs.full.Load() != 1 {
		t.Fatalf("initial admission used local admission: local=%d full=%d", stubs.local.Load(), stubs.full.Load())
	}
	stubs = stubControllerAdmission(t, false, nil, func(int32) error { return nil })
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(), func() error { return nil })
	if err != nil || admission.offline {
		t.Fatalf("initial admission = %+v, %v", admission, err)
	}
	if stubs.local.Load() != 0 || stubs.full.Load() != 1 {
		t.Fatalf("initial admission calls: local=%d full=%d", stubs.local.Load(), stubs.full.Load())
	}
	if err := admission.wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	admission.stop()
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

func TestOfflineRestartAdmissionHoldsAuthorityUntilClockIsHealthy(t *testing.T) {
	stubs := stubControllerAdmission(t, true, nil, func(int32) error { return nil })
	var healthy atomic.Bool
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(), func() error {
		if !healthy.Load() {
			return errors.New("NTP clock is unhealthy")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer admission.stop()
	held, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := admission.wait(held); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("authority gate opened without a healthy clock: %v", err)
	}
	if stubs.local.Load() != 1 || stubs.full.Load() != 0 {
		t.Fatalf("admission calls before clock health: local=%d full=%d", stubs.local.Load(), stubs.full.Load())
	}
	healthy.Store(true)
	ready, readyCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer readyCancel()
	if err := admission.wait(ready); err != nil || stubs.full.Load() != 1 {
		t.Fatalf("healthy clock did not finish full admission: %v calls=%d", err, stubs.full.Load())
	}
}

func TestOfflineRestartAdmissionRequiresLocalProofAndMarker(t *testing.T) {
	want := errors.New("IMDS instance differs from accepted marker")
	stubs := stubControllerAdmission(t, true, want, func(int32) error { return nil })
	if _, err := startControllerAdmission(t.Context(), productionAdmissionConfig(),
		func() error { return nil }); !errors.Is(err, want) {
		t.Fatalf("failed local admission did not stop startup: %v", err)
	}
	if stubs.full.Load() != 0 {
		t.Fatal("full admission ran after local admission failed")
	}
	// Initial admission (no accepted marker yet) never takes the offline path.
	stubs = stubControllerAdmission(t, false, nil, func(int32) error { return nil })
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(), func() error { return nil })
	if err != nil || admission.offline || stubs.local.Load() != 0 || stubs.full.Load() != 1 {
		t.Fatalf("first boot used offline admission: %+v %v local=%d", admission, err, stubs.local.Load())
	}
	if offline, err := offlineRestartAdmission(productionAdmissionConfig()); offline || err != nil {
		t.Fatalf("initial install used offline admission: %v %v", offline, err)
	}
}

func TestOfflineRestartAdmissionStopCancelsPendingAttempt(t *testing.T) {
	entered := make(chan struct{}, 1)
	stubControllerAdmission(t, true, nil, func(int32) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		return errors.New("OCI unavailable")
	})
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(), func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	stopped := make(chan struct{})
	go func() {
		admission.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not join the background admission")
	}
	if err := admission.wait(canceledContext()); err == nil {
		t.Fatal("canceled admission opened the authority gate")
	}
}

func TestOfflineRestartAdmissionStopCancelsInFlightFullGate(t *testing.T) {
	stubControllerAdmission(t, true, nil, func(int32) error { return nil })
	entered := make(chan struct{})
	controllerBootstrapProduction = func(ctx context.Context, _ Config) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(), func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		admission.stop()
		t.Fatal("full admission did not start")
	}
	stopped := make(chan struct{})
	go func() {
		admission.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not cancel and join the in-flight full admission")
	}
	if err := admission.wait(canceledContext()); err == nil {
		t.Fatal("canceled full admission opened the authority gate")
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

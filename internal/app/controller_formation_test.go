package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

type admissionStubs struct {
	local, full, finish atomic.Int32
}

func stubControllerAdmission(t *testing.T, marker bool, localErr error, full func(int32) error) *admissionStubs {
	t.Helper()
	stubs := &admissionStubs{}
	previousPresence, previousMarker := controllerBakedInputsPresent, controllerMarkerPresent
	previousLocal, previousFull := controllerLocalAdmissionProduction, controllerBootstrapProduction
	previousMin, previousMax := controllerAdmissionMinBackoff, controllerAdmissionMaxBackoff
	previousFinish := controllerFinishMaterialAdoption
	controllerFinishMaterialAdoption = func(Config) error { stubs.finish.Add(1); return nil }
	controllerBakedInputsPresent = func() (bool, error) { return true, nil }
	controllerMarkerPresent = func() (bool, error) { return marker, nil }
	controllerLocalAdmissionProduction = func(context.Context, Config) error {
		stubs.local.Add(1)
		return localErr
	}
	controllerBootstrapProduction = func(ctx context.Context, _ Config) error {
		return full(stubs.full.Add(1))
	}
	controllerAdmissionMinBackoff, controllerAdmissionMaxBackoff = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() {
		controllerBakedInputsPresent, controllerMarkerPresent = previousPresence, previousMarker
		controllerLocalAdmissionProduction, controllerBootstrapProduction = previousLocal, previousFull
		controllerAdmissionMinBackoff, controllerAdmissionMaxBackoff = previousMin, previousMax
		controllerFinishMaterialAdoption = previousFinish
	})
	return stubs
}

func productionAdmissionConfig(offline bool) Config {
	return Config{NATS: natscell.Config{Cell: "gru", Instance: "controller-a", Replicas: 3},
		Controller: ControllerConfig{OfflineRestartAdmission: offline}}
}

func TestDefaultRestartAdmissionStaysSynchronous(t *testing.T) {
	want := errors.New("OCI ledger unavailable")
	stubs := stubControllerAdmission(t, true, nil, func(int32) error { return want })
	if _, err := startControllerAdmission(t.Context(), productionAdmissionConfig(false),
		func() error { return nil }); !errors.Is(err, want) {
		t.Fatalf("default admission failure did not stop startup: %v", err)
	}
	if stubs.local.Load() != 0 || stubs.full.Load() != 1 {
		t.Fatalf("default admission used local admission: local=%d full=%d", stubs.local.Load(), stubs.full.Load())
	}
	stubControllerAdmission(t, true, nil, func(int32) error { return nil })
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(false), func() error { return nil })
	if err != nil || admission.offline {
		t.Fatalf("default admission = %+v, %v", admission, err)
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
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(true), func() error { return nil })
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
	// The interrupted-install recovery runs once at startup, never beside
	// the running controller's own retries.
	if stubs.finish.Load() != 1 {
		t.Fatalf("material adoption recovery ran %d times, want once at startup", stubs.finish.Load())
	}
	if stubs.full.Load() != 3 {
		t.Fatalf("full admission attempts = %d", stubs.full.Load())
	}
}

func TestOfflineRestartAdmissionRequiresLocalProofAndMarker(t *testing.T) {
	want := errors.New("IMDS instance differs from accepted marker")
	stubs := stubControllerAdmission(t, true, want, func(int32) error { return nil })
	if _, err := startControllerAdmission(t.Context(), productionAdmissionConfig(true),
		func() error { return nil }); !errors.Is(err, want) {
		t.Fatalf("failed local admission did not stop startup: %v", err)
	}
	if stubs.full.Load() != 0 {
		t.Fatal("full admission ran after local admission failed")
	}
	// Initial admission (no accepted marker yet) never takes the offline path.
	stubs = stubControllerAdmission(t, false, nil, func(int32) error { return nil })
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(true), func() error { return nil })
	if err != nil || admission.offline || stubs.local.Load() != 0 || stubs.full.Load() != 1 {
		t.Fatalf("first boot used offline admission: %+v %v local=%d", admission, err, stubs.local.Load())
	}
	lab := productionAdmissionConfig(true)
	lab.NATS.Lab = true
	if offline, err := offlineRestartAdmission(lab); offline || err != nil {
		t.Fatalf("lab used offline admission: %v %v", offline, err)
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
	admission, err := startControllerAdmission(t.Context(), productionAdmissionConfig(true), func() error { return nil })
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

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

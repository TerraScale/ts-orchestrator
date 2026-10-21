package app

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Local process scenarios keep the real JWT broker gate and replace only cloud admission.
func stubAuthenticatedController(t *testing.T, cfg *Config) {
	t.Helper()
	previousRuntime, previousMarker := controllerRuntimeProduction, controllerMarkerPresent
	previousBaked, previousAdmission := controllerBakedInputsPresent, controllerBootstrapProduction
	previousFounder, previousClock := controllerFounderProduction, controllerBrokerClockProbe
	previousSeed := rolloutSeedSlot
	controllerRuntimeProduction = func(ctx context.Context, cfg Config, _ func() error) (*natscell.Runtime, error) {
		return natscell.Start(ctx, cfg.NATS)
	}
	controllerMarkerPresent = func() (bool, error) { return false, nil }
	controllerBakedInputsPresent = func() (bool, error) { return true, nil }
	controllerBootstrapProduction = func(context.Context, Config) error { return nil }
	controllerFounderProduction = func(context.Context) error { return nil }
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	controllerBrokerClockProbe = func() brokerauth.ClockProbe { return clock }
	rolloutSeedSlot = func(Config) (string, error) { return cfg.NATS.Instance, nil }
	t.Cleanup(func() {
		controllerRuntimeProduction, controllerMarkerPresent = previousRuntime, previousMarker
		controllerBakedInputsPresent, controllerBootstrapProduction = previousBaked, previousAdmission
		controllerFounderProduction, controllerBrokerClockProbe = previousFounder, previousClock
		rolloutSeedSlot = previousSeed
	})
	newAcceptedSpecTrust(t, cfg)
}

func TestControllerBootstrapRetriesOnlyTransientErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want bool
	}{
		{context.DeadlineExceeded, true},
		{nats.ErrNoResponders, true},
		{fmt.Errorf("%w: %w", delivery.ErrStoreNotReady, jetstream.ErrStreamNotFound), true},
		{fmt.Errorf("%w: %w", host.ErrStateNotReady, jetstream.ErrStreamNotFound), true},
		{jetstream.ErrStreamNotFound, false},
		{&jetstream.APIError{Code: 400, ErrorCode: 10005, Description: "no suitable peers for placement"}, true},
		{jetstream.ErrJetStreamNotEnabled, false},
		{nats.ErrAuthorization, false},
		{&jetstream.APIError{Code: 400, ErrorCode: jetstream.JSErrCodeBadRequest}, false},
	} {
		if got := transientControllerBootstrapError(test.err); got != test.want {
			t.Errorf("transientControllerBootstrapError(%v) = %t, want %t", test.err, got, test.want)
		}
	}
}

func reserveControllerPort(t *testing.T) int {
	t.Helper()
	return reserveControllerPorts(t, 1)[0]
}

func reserveControllerPorts(t *testing.T, count int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			if err := listener.Close(); err != nil {
				t.Errorf("close reserved controller port: %v", err)
			}
		}
	}()
	ports := make([]int, count)
	for index := range ports {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports[index] = listener.Addr().(*net.TCPAddr).Port
	}
	return ports
}

func TestReserveControllerPortsDistinct(t *testing.T) {
	ports := reserveControllerPorts(t, 6)
	seen := make(map[int]bool, len(ports))
	for _, port := range ports {
		if seen[port] {
			t.Fatalf("reserved controller port %d more than once", port)
		}
		seen[port] = true
	}
}

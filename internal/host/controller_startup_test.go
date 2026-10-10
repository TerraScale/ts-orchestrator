package host

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type hostStateStatusError struct {
	jetstream.KeyValue
	err error
}

func (state hostStateStatusError) Status(ctx context.Context) (jetstream.KeyValueStatus, error) {
	if state.err != nil {
		return nil, state.err
	}
	return state.KeyValue.Status(ctx)
}

type hostStateProvisioner struct {
	jetstream.JetStream
	statusError error
}

func (js hostStateProvisioner) CreateOrUpdateKeyValue(ctx context.Context, cfg jetstream.KeyValueConfig) (jetstream.KeyValue, error) {
	state, err := js.JetStream.CreateOrUpdateKeyValue(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return hostStateStatusError{KeyValue: state, err: js.statusError}, nil
}

func TestControllerMarksOnlyProvisionedHostStateVisibilityForRetry(t *testing.T) {
	var cfg ControllerConfig
	controller, _, _, _, _ := testControllerWithVerifier(t, nil, func(config *ControllerConfig) { cfg = *config })
	for _, test := range []struct {
		name  string
		err   error
		state jetstream.KeyValue
		retry bool
	}{
		{name: "provisioned state not visible", err: jetstream.ErrStreamNotFound, retry: true},
		{name: "authorization refused", err: nats.ErrAuthorization},
		{name: "canceled", err: context.Canceled},
		{name: "supplied state missing", err: jetstream.ErrStreamNotFound,
			state: hostStateStatusError{KeyValue: controller.state, err: jetstream.ErrStreamNotFound}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := cfg
			config.State = test.state
			config.JS = hostStateProvisioner{JetStream: cfg.JS, statusError: test.err}
			got, err := NewController(t.Context(), config)
			if got != nil || !errors.Is(err, test.err) || errors.Is(err, ErrStateNotReady) != test.retry {
				t.Fatalf("controller=%v error=%v; want original error and retry=%t", got, err, test.retry)
			}
		})
	}
	if _, err := NewController(t.Context(), cfg); err != nil {
		t.Fatalf("controller did not recover after metadata became visible: %v", err)
	}
}

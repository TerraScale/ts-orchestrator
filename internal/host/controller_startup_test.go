package host

import (
	"context"

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

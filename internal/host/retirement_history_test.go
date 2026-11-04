package host

import (
	"context"

	"github.com/nats-io/nats.go/jetstream"
)

type unavailableRetirementKeys struct {
	jetstream.KeyValue
	err error
}

func (state unavailableRetirementKeys) ListKeysFiltered(context.Context, ...string) (jetstream.KeyLister, error) {
	return nil, state.err
}

type retirementInventoryStream struct {
	jetstream.Stream
	info func(context.Context, ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error)
}

func (s retirementInventoryStream) Info(ctx context.Context, opts ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
	return s.info(ctx, opts...)
}
